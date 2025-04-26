#include <pwd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>

#include <litehook.h>

#include "common.h"
#include "envbuf.h"
#include "roothider.h"

const char* HOOK_DYLIB_PATH = NULL;

bool dyld_patch_global_enabled = true;

//export for PatchLoader
__attribute__((visibility("default"))) int PLRequiredJIT() {
	return 0;
}

static uid_t _CFGetSVUID(bool *successful) {
	uid_t uid = -1;
	struct kinfo_proc kinfo;
	u_int miblen = 4;
	size_t  len;
	int mib[miblen];
	int ret;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = getpid();
	len = sizeof(struct kinfo_proc);
	ret = sysctl(mib, miblen, &kinfo, &len, NULL, 0);
	if (ret != 0) {
		uid = -1;
		*successful = false;
	} else {
		uid = kinfo.kp_eproc.e_pcred.p_svuid;
		*successful = true;
	}
	return uid;
}

bool _CFCanChangeEUIDs(void) {
	static bool canChangeEUIDs;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		uid_t euid = geteuid();
		uid_t uid = getuid();
		bool gotSVUID = false;
		uid_t svuid = _CFGetSVUID(&gotSVUID);
		canChangeEUIDs = (uid == 0 || uid != euid || svuid != euid || !gotSVUID);
	});
	return canChangeEUIDs;
}

void loadPathHook()
{
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		void* roothidehooks = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		ASSERT(roothidehooks != NULL);
		void (*pathhook)() = dlsym(roothidehooks, "pathhook");
		ASSERT(pathhook != NULL);
		pathhook();
	});
}

void redirect_env_paths(const char* rootdir)
{
	//for now libSystem should be initlized, container should be set.

	char* homedir = NULL;

/* 
there is a bug in NSHomeDirectory,
if a containerized root process changes its uid/gid, 
NSHomeDirectory may return a home directory that it cannot access. (exclude NSTemporaryDirectory)
We just keep this bug:
*/
	if(!issetugid()) // issetugid() should always be false at this time. (but how about persona-mgmt? idk)
	{
		homedir = getenv("CFFIXED_USER_HOME");
		if(homedir)
		{
#define CONTAINER_PATH_PREFIX   "/private/var/mobile/Containers/Data/" // +/Application,PluginKitPlugin,InternalDaemon
			if(strncmp(homedir, CONTAINER_PATH_PREFIX, sizeof(CONTAINER_PATH_PREFIX)-1) == 0)
			{
				return; //containerized
			}
			else
			{
				homedir = NULL; //from parent, drop it
			}
		}
	}

	if(!homedir) {
		struct passwd* pwd = getpwuid(geteuid());
		if(pwd && pwd->pw_dir) {
			homedir = pwd->pw_dir;
		}
	}

	if(!homedir) {
		homedir = "/var/empty";
	}

	if(homedir[0] == '/') {
		char newhome[PATH_MAX*2]={0};
		strlcpy(newhome, rootdir, sizeof(newhome));
		strlcat(newhome, homedir, sizeof(newhome));
		setenv("CFFIXED_USER_HOME", newhome, 1);
	}
}

void redirect_paths(const char* rootdir)
{
	do {
		
		char executablePath[PATH_MAX]={0};
		uint32_t bufsize=sizeof(executablePath);
		if(_NSGetExecutablePath(executablePath, &bufsize) != 0)
			break;
		
		char realexepath[PATH_MAX]={0};
		if(!realpath(executablePath, realexepath))
			break;
			
		char realjbroot[PATH_MAX+1]={0};
		if(!realpath(rootdir, realjbroot))
			break;
		
		if(realjbroot[0] && realjbroot[strlen(realjbroot)-1] != '/')
			strlcat(realjbroot, "/", sizeof(realjbroot));
		
		if(strncmp(realexepath, realjbroot, strlen(realjbroot)) != 0)
			break;

		//for jailbroken binaries
		redirect_env_paths(rootdir);
		
		if(_CFCanChangeEUIDs()) {
			loadPathHook();
		}
	
		pid_t ppid = __getppid();
		ASSERT(ppid > 0);
		if(ppid != 1)
			break;
		
		char pwd[PATH_MAX];
		if(getcwd(pwd, sizeof(pwd)) == NULL)
			break;
		if(strcmp(pwd, "/") != 0)
			break;
	
		ASSERT(chdir(rootdir)==0);
		
	} while(0);
}


kSpawnConfig spawn_config_for_executable(const char* path, char *const argv[restrict]);
void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop));

void trust_insert_libraries(char** envc)
{
	const char* DYLD_INSERT_LIBRARIES = envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES");
	if(!DYLD_INSERT_LIBRARIES) return;

	string_enumerate_components(DYLD_INSERT_LIBRARIES, ":", ^(const char *path, bool *stop) {
		jbclient_trust_library_recurse(path, NULL);
	});
}

int __no_need_to_trust_now__(const char* path)
{
	return 0;
}

#define NBINPREFS	   4
#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

int roothide_systemhook___posix_spawn_prehook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict], void *orig, int (*trust_binary)(const char *path), int (*set_process_debugged)(uint64_t pid, bool fullyDebugged), double jetsamMultiplier)
{
	if(!path) { //Don't crash here due to bad posix_spawn call
		return __posix_spawn_orig(pidp, path, desc, argv, envp);
	}

	if(!desc || !desc->attrp) {
		posix_spawnattr_t attr=NULL;
		posix_spawnattr_init(&attr);
		int ret = posix_spawn(pidp, path, (desc && desc->file_actions) ? &desc->file_actions : NULL, &attr, argv, envp);
		posix_spawnattr_destroy(&attr);
		return ret;
	}

	if(!dyld_patch_global_enabled)
	{
		trust_binary = __no_need_to_trust_now__;
	}

	return posix_spawn_hook_shared(pidp, path, desc, argv, envp, orig, trust_binary, set_process_debugged, jetsamMultiplier);
}

int roothide_systemhook___posix_spawn_posthook(pid_t *restrict pidp,
	const char *restrict path,
	struct _posix_spawn_args_desc *desc,
	char *const argv[restrict],
	char *const envp[restrict])
{
	posix_spawnattr_t *attrp = &desc->attrp;
	kSpawnConfig cfg = dyld_patch_global_enabled
		? 0
		: spawn_config_for_executable(path, argv);

	if (!dyld_patch_global_enabled && (cfg & kSpawnConfigTrust)) {
		cpu_type_t types[NBINPREFS];
		cpu_subtype_t subs[NBINPREFS];
		size_t cnt = 0;
		if (posix_spawnattr_getarchpref_np(attrp, NBINPREFS, types, subs, &cnt) == 0 && cnt) {
			xpc_object_t archs = xpc_array_create_empty();
			for (size_t i = 0; i < cnt; i++) {
				xpc_object_t d = xpc_dictionary_create_empty();
				xpc_dictionary_set_uint64(d, "type", types[i]);
				xpc_dictionary_set_uint64(d, "subtype", subs[i]);
				xpc_array_set_value(archs, XPC_ARRAY_APPEND, d);
				xpc_release(d);
			}
			jbclient_trust_executable_recurse(path, archs);
			xpc_release(archs);
		}
	}

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool resume  = suspend && !(flags & POSIX_SPAWN_START_SUSPENDED);
	bool patch   = suspend && (flags & POSIX_SPAWN_SETEXEC);

	if (suspend)
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);

	if (patch && jbdSpawnExecStart(path, resume) != 0) {
		posix_spawnattr_setflags(attrp, flags);
		return 201;
	}

	char **envc = envbuf_mutcopy((const char **)envp);
	if (envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES"))
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");

	if (!dyld_patch_global_enabled && (cfg & kSpawnConfigTrust))
		trust_insert_libraries(envc);

	int pid = 0;
	int ret = __posix_spawn_orig(&pid, path, desc, argv, envc);
	if (pidp) *pidp = pid;

	envbuf_free(envc);
	posix_spawnattr_setflags(attrp, flags);

	if (patch) {
		jbdSpawnExecCancel(path);
	} else if (ret == 0 && pid > 0 && suspend) {
		if (jbdSpawnPatchChild(pid, resume) != 0) {
			kill(pid, SIGKILL);
			return 202;
		}
	}

	return ret;
}

int roothide_systemhook___execve_prehook(const char *path, char *const argv[], char *const envp[], void *orig, int (*trust_binary)(const char *))
{
	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	int ret = posix_spawn(NULL, path, NULL, &attr, argv, envp);
	posix_spawnattr_destroy(&attr);

	if (ret == EPERM && access(path, X_OK) == 0) {
		trust_binary = __no_need_to_trust_now__;
		return execve_hook_shared(path, argv, envp, orig, trust_binary);
	}

	errno = ret;
	return -1;
}

int roothide_systemhook___execve_posthook(const char *path, char *const argv[], char *const envp[])
{
	bool traced = false;
	if (jbdExecTraceStart(path, &traced) != 0) {
		errno = 203;
		return -1;
	}
	while (!traced) {
		usleep(10 * 1000);
	}

	char **envc = envbuf_mutcopy((const char **)envp);
	if (envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES"))
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");

	int ret = __execve_orig(path, argv, envc);
	int old = errno;
	envbuf_free(envc);

	jbdExecTraceCancel(path);
	errno = old;
	return ret;
}

// Collapse all four dyld-dlopen hooks into compact macros:

#define DEFINE_DYLD_HOOK3(name, orig, idx, salt)							  \
	void* (*orig)(void*, const char*, int);									\
	static void* name##_impl(void* dyld, const char* path, int mode)		   \
	{																		  \
		if (path && !(mode & RTLD_NOLOAD))									 \
			jbclient_trust_library_recurse(path, __builtin_return_address(0)); \
		return orig(dyld, path, mode);										 \
	}																		  \
	__attribute__((alias(#name "_impl")))									  \
	void* name(void* dyld, const char* path, int mode);						\
	static void __attribute__((constructor)) _reg_##name(void)				 \
	{																		  \
		void*** g = litehook_find_dsc_symbol(								  \
			"/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");			 \
		if (g)																 \
			hook_dyld_routine(*g, idx, name, (void**)&orig, salt);			 \
	}

#define DEFINE_DYLD_HOOK4(name, orig, idx, salt)									\
	void* (*orig)(void*, const char*, int, void*);								   \
	static void* name##_impl(void* dyld, const char* path, int mode, void* caller)  \
	{																			   \
		if (path && !(mode & RTLD_NOLOAD))										  \
			jbclient_trust_library_recurse(path, caller);						   \
		return orig(dyld, path, mode, caller);									  \
	}																			   \
	__attribute__((alias(#name "_impl")))										   \
	void* name(void* dyld, const char* path, int mode, void* caller);			   \
	static void __attribute__((constructor)) _reg_##name(void)					  \
	{																			   \
		void*** g = litehook_find_dsc_symbol(									   \
			"/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");				  \
		if (g)																	  \
			hook_dyld_routine(*g, idx, name, (void**)&orig, salt);				  \
	}

#define DEFINE_DYLD_PREHOOK(name, orig, idx, salt)					   \
	bool (*orig)(void*, const char*);									 \
	static bool name##_impl(void* dyld, const char* path)				 \
	{																	 \
		if (path)														\
			jbclient_trust_library_recurse(path, __builtin_return_address(0)); \
		return orig(dyld, path);										 \
	}																	 \
	__attribute__((alias(#name "_impl")))								 \
	bool name(void* dyld, const char* path);							  \
	static void __attribute__((constructor)) _reg_##name(void)			\
	{																	 \
		void*** g = litehook_find_dsc_symbol(							 \
			"/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");		\
		if (g)															\
			hook_dyld_routine(*g, idx, name, (void**)&orig, salt);		\
	}

// Instantiate all four hooks:
DEFINE_DYLD_HOOK3(dyld_dlopen_hook,			dyld_dlopen_orig,			14, 0xBF31)
DEFINE_DYLD_PREHOOK(dyld_dlopen_preflight_hook, dyld_dlopen_preflight_orig, 18, 0xB1B6)
DEFINE_DYLD_HOOK4(dyld_dlopen_from_hook,	   dyld_dlopen_from_orig,	   97, 0xD48C)
DEFINE_DYLD_HOOK3(dyld_dlopen_audited_hook,	dyld_dlopen_audited_orig,	98, 0xD2A5)

// Keep hook_dyld_routine unchanged:
int hook_dyld_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	if (!dyld) return -1;

	uint64_t divers = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **fptrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, divers);
	if (!fptrs) return -1;

	if (vm_protect(mach_task_self_, (mach_vm_address_t)&fptrs[idx], sizeof(void*),
				   false, VM_PROT_READ | VM_PROT_WRITE) == 0)
	{
		uint64_t loc = (uint64_t)&fptrs[idx];
		uint64_t div = (loc & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);

		*orig = ptrauth_auth_and_resign(
			fptrs[idx],
			ptrauth_key_process_independent_code,
			div,
			ptrauth_key_function_pointer,
			0
		);

		fptrs[idx] = ptrauth_auth_and_resign(
			hook,
			ptrauth_key_function_pointer,
			0,
			ptrauth_key_process_independent_code,
			div
		);

		vm_protect(mach_task_self_, (mach_vm_address_t)&fptrs[idx], sizeof(void*),
				   false, VM_PROT_READ);

		return 0;
	}

	return -1;
}

void roothide_init(void)
{
	const char *insert = getenv("DYLD_INSERT_LIBRARIES");
	const char *cache  = getenv("DYLD_IN_CACHE");
	if (insert && cache && strcmp(cache, "0") == 0)
		unsetenv("DYLD_IN_CACHE");

	HOOK_DYLIB_PATH = strdup(dyld_image_path_containing_address(&__dso_handle));
}

void roothide_init_with_checkin(const char *rootdir)
{
	redirect_paths(rootdir);
	dlopen(JBROOT_PATH("/usr/lib/roothideinit.dylib"), RTLD_NOW);
}

void roothide_init_with_executable(const char *exe)
{
	if (__builtin_available(iOS 16.0, *) && !isRemovableBundlePath(exe)) {
		litehook_hook_function(__sysctl, __sysctl_hook);
		litehook_hook_function(__sysctlbyname, __sysctlbyname_hook);
	}

#ifndef __arm64e__
	if (jbclient_palehide_present()) {
		const char *e = exe;
		if (!strcmp(e, "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd") ||
			!strcmp(e, "/System/Library/Frameworks/CryptoTokenKit.framework/ctkd") ||
			!strcmp(e, "/usr/libexec/securityd") ||
			!strcmp(e, "/usr/libexec/keybagd")) {
			void *lib = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
			ASSERT(lib);
			((void (*)(void))dlsym(lib, "palera1n"))();
		}
	}
#endif

	if (string_has_suffix(exe, "/Dopamine.app/Dopamine"))
		loadPathHook();

	dlopen(JBROOT_PATH("/usr/lib/roothidepatch.dylib"), RTLD_NOW);
}