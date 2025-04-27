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
bool dyld_patch_fallback_enabled = false;

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

	char* homedir = NULL;

	if(!issetugid()) 
	{
		homedir = getenv("CFFIXED_USER_HOME");
		if(homedir)
		{
#define CONTAINER_PATH_PREFIX   "/private/var/mobile/Containers/Data/" 
			if(strncmp(homedir, CONTAINER_PATH_PREFIX, sizeof(CONTAINER_PATH_PREFIX)-1) == 0)
			{
				return; 
			}
			else
			{
				homedir = NULL; 
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
	const char* libs=envbuf_getenv((const char**)envc,"DYLD_INSERT_LIBRARIES");
	if(!libs)return;
	static CFMutableSetRef t;
	static dispatch_once_t o;
	dispatch_once(&o,^{t=CFSetCreateMutable(NULL,0,&kCFTypeSetCallBacks);});
	string_enumerate_components(libs,":",^(const char*p,bool*stop){
		CFStringRef s=CFStringCreateWithCString(NULL,p,kCFStringEncodingUTF8);
		if(!CFSetContainsValue(t,s)){CFSetAddValue(t,s);jbclient_trust_library_recurse(p,NULL);}
		CFRelease(s);
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
	if(!path) { 
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

#define NBINPREFS 4
#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700

int roothide_systemhook___posix_spawn_posthook(pid_t *pidp,
	const char *path,
	struct _posix_spawn_args_desc *desc,
	char *const argv[],
	char *const envp[])
{
	posix_spawnattr_t *attrp = &desc->attrp;
	
	/* Trust logic */
	if (!dyld_patch_global_enabled) {
		kSpawnConfig cfg = spawn_config_for_executable(path, argv);
		if (cfg & kSpawnConfigTrust) {
			jbclient_trust_executable_recurse(path, NULL);
		}
	}
	
	/* Suspension flags */
	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);
	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);
	
	bool suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool resume = suspend && !(flags & POSIX_SPAWN_START_SUSPENDED);
	bool exec   = suspend && (flags & POSIX_SPAWN_SETEXEC);
	
	if (suspend)
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	
	if (exec) {
		if (jbdSpawnExecStart(path, resume) != 0) {
			posix_spawnattr_setflags(attrp, flags);
			return 201;
		}
	}
	
	/* Prepare environment */
	char **envc = envbuf_mutcopy((const char **)envp);
	if (envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) {
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	}
	
	if (!dyld_patch_global_enabled) {
		kSpawnConfig cfg2 = spawn_config_for_executable(path, argv);
		if (cfg2 & kSpawnConfigTrust) {
			trust_insert_libraries(envc);
		}
	}
	
	/* Spawn original */
	int child = 0;
	int ret = __posix_spawn_orig(&child, path, desc, argv, envc);
	if (pidp) *pidp = child;
		envbuf_free(envc);
	posix_spawnattr_setflags(attrp, flags);
	
	/* Post-patch */
	if (exec) {
		jbdSpawnExecCancel(path);
	} else if (ret == 0 && child > 0 && suspend) {
		if (jbdSpawnPatchChild(child, resume) != 0) {
			kill(child, SIGKILL);
			return 202;
		}
	}
	
	return ret;
}

int roothide_systemhook___execve_prehook(const char *path, char *const argv[], char *const envp[], void *orig, int (*trust_binary)(const char *path))
{

	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	int ret = posix_spawn(NULL, path, NULL, &attr, argv, envp);
	posix_spawnattr_destroy(&attr);

	assert(ret != 0);

	if(ret==EPERM && access(path, X_OK)==0)
	{
		trust_binary = __no_need_to_trust_now__;
		return execve_hook_shared(path, argv, envp, orig, trust_binary);
	}

	errno = ret; 
	return -1;
}

int roothide_systemhook___execve_posthook(const char* path,char* const argv[],char* const envp[])
{
	bool traced=false;
	if(jbdExecTraceStart(path,&traced)!=0){errno=203;return-1;}
	const int sleep_ms=50,max_wait_ms=500;
	int waited=0;
	while(!traced&&waited<max_wait_ms){usleep(sleep_ms*1000);waited+=sleep_ms;}
	if(!traced){jbdExecTraceCancel(path);errno=203;return-1;}
	bool need_copy=envbuf_getenv((const char**)envp,"DYLD_INSERT_LIBRARIES")!=NULL;
	char** envc=need_copy?envbuf_mutcopy((const char**)envp):(char**)envp;
	int ret=__execve_orig(path,argv,envc),olderr=errno;
	if(need_copy)envbuf_free(envc);
	jbdExecTraceCancel(path);
	errno=olderr;
	return ret;
}

void* (*dyld_dlopen_orig)(void *dyld, const char* path, int mode);
void* dyld_dlopen_hook(void *dyld, const char* path, int mode)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_orig(dyld, path, mode);
}

void* (*dyld_dlopen_from_orig)(void *dyld, const char* path, int mode, void* addressInCaller);
void* dyld_dlopen_from_hook(void *dyld, const char* path, int mode, void* addressInCaller)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, addressInCaller);
	}
	__attribute__((musttail)) return dyld_dlopen_from_orig(dyld, path, mode, addressInCaller);
}

void* (*dyld_dlopen_audited_orig)(void *dyld, const char* path, int mode);
void* dyld_dlopen_audited_hook(void *dyld, const char* path, int mode)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_audited_orig(dyld, path, mode);
}

bool (*dyld_dlopen_preflight_orig)(void *dyld, const char *path);
bool dyld_dlopen_preflight_hook(void *dyld, const char* path)
{
	if (path) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_preflight_orig(dyld, path);
}

int hook_dyld_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	if (!dyld) return -1;

	uint64_t dyldPacDiversifier = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **dyldFuncPtrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, dyldPacDiversifier);
	if (!dyldFuncPtrs) return -1;

	if (vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
		uint64_t location = (uint64_t)&dyldFuncPtrs[idx];
		uint64_t pacDiversifier = (location & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);

		*orig = ptrauth_auth_and_resign(dyldFuncPtrs[idx], ptrauth_key_process_independent_code, pacDiversifier, ptrauth_key_function_pointer, 0);
		dyldFuncPtrs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, pacDiversifier);
		vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ);
		return 0;
	}

	return -1;
}

void init_dyldhooks()
{

	void ***gDyldPtr = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
	if (gDyldPtr) {
		hook_dyld_routine(*gDyldPtr, 14, (void *)&dyld_dlopen_hook, (void **)&dyld_dlopen_orig, 0xBF31);
		hook_dyld_routine(*gDyldPtr, 18, (void *)&dyld_dlopen_preflight_hook, (void **)&dyld_dlopen_preflight_orig, 0xB1B6);
		hook_dyld_routine(*gDyldPtr, 97, (void *)&dyld_dlopen_from_hook, (void **)&dyld_dlopen_from_orig, 0xD48C);
		hook_dyld_routine(*gDyldPtr, 98, (void *)&dyld_dlopen_audited_hook, (void **)&dyld_dlopen_audited_orig, 0xD2A5);
	}
}

extern struct mach_header __dso_handle;
extern const char* dyld_image_path_containing_address(const void* addr);

extern int parse_dyldhook_jbinfo(char **jbRootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut);

void roothide_init()
{
	if(getenv("DYLD_INSERT_LIBRARIES")) {
		const char* DYLD_IN_CACHE = getenv("DYLD_IN_CACHE");
		if(DYLD_IN_CACHE && strcmp(DYLD_IN_CACHE, "0") == 0) {
			unsetenv("DYLD_IN_CACHE");
		}
	}

	HOOK_DYLIB_PATH = strdup(dyld_image_path_containing_address(&__dso_handle));
}

void roothide_init_with_checkin(const char* rootdir)
{
	if(dyld_patch_fallback_enabled)
	{
		init_dyldhooks();
	}

	redirect_paths(rootdir);

	dlopen(JBROOT_PATH("/usr/lib/roothideinit.dylib"), RTLD_NOW);
}

void roothide_init_with_executable(const char* executable)
{
	if (__builtin_available(iOS 16.0, *))
	{
		if(!isRemovableBundlePath(executable)) {
			litehook_hook_function(__sysctl, __sysctl_hook);
			litehook_hook_function(__sysctlbyname, __sysctlbyname_hook);
		}
	}

#ifndef __arm64e__
	if(strcmp(executable, "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd")==0
	|| strcmp(executable, "/System/Library/Frameworks/CryptoTokenKit.framework/ctkd")==0
	|| strcmp(executable, "/usr/libexec/securityd")==0
	|| strcmp(executable, "/usr/libexec/keybagd")==0) {
		if(jbclient_palehide_present())
		{
			void* roothidehooks = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
			ASSERT(roothidehooks != NULL);
			void (*palera1n)() = dlsym(roothidehooks, "palera1n");
			palera1n();
		}
	}
#endif

	if(string_has_suffix(executable, "/Dopamine.app/Dopamine")) {
		loadPathHook(); 
	}

	dlopen(JBROOT_PATH("/usr/lib/roothidepatch.dylib"), RTLD_NOW); 
}