#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <spawn.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <mach-o/dyld.h>
#include <xpc/xpc.h>

#include <litehook.h>

#include "common.h"
#include "envbuf.h"
#include "roothider.h"

extern struct mach_header __dso_handle;
extern const char* dyld_image_path_containing_address(const void* addr);

const char* HOOK_DYLIB_PATH = NULL;
bool dyld_patch_global_enabled = true;
bool dyld_patch_fallback_enabled = false;

__attribute__((visibility("default")))
int PLRequiredJIT(void)
{
	return 0;
}

static uid_t _CFGetSVUID(bool *successful)
{
	struct kinfo_proc kinfo;
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
	size_t len = sizeof(kinfo);
	if (sysctl(mib, 4, &kinfo, &len, NULL, 0) != 0) {
		*successful = false;
		return (uid_t)-1;
	}
	*successful = true;
	return kinfo.kp_eproc.e_pcred.p_svuid;
}

bool _CFCanChangeEUIDs(void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	static bool can;
	pthread_once(&once, ({ 
		uid_t euid = geteuid();
		uid_t uid  = getuid();
		bool ok    = false;
		uid_t sv   = _CFGetSVUID(&ok);
		can = (uid == 0 || uid != euid || sv != euid || !ok);
	}));
	return can;
}

static pthread_once_t _load_roothidehooks_once = PTHREAD_ONCE_INIT;
static void _load_roothidehooks(void)
{
	void* lib = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
	ASSERT(lib);
	void (*pathhook)(void) = dlsym(lib, "pathhook");
	ASSERT(pathhook);
	pathhook();
}

void loadPathHook(void)
{
	pthread_once(&_load_roothidehooks_once, _load_roothidehooks);
}

void redirect_env_paths(const char* rootdir)
{
	char* homedir = NULL;
	if (!issetugid()) {
		homedir = getenv("CFFIXED_USER_HOME");
		if (homedir && strncmp(homedir, "/private/var/mobile/Containers/Data/", strlen("/private/var/mobile/Containers/Data/")) == 0)
			return;
		homedir = NULL;
	}
	if (!homedir) {
		struct passwd* pwd = getpwuid(geteuid());
		if (pwd && pwd->pw_dir)
			homedir = pwd->pw_dir;
	}
	if (!homedir) homedir = "/var/empty";
	if (homedir[0] == '/') {
		size_t max = PATH_MAX * 2;
		char* newhome = malloc(max);
		if (!newhome) return;
		strlcpy(newhome, rootdir, max);
		strlcat(newhome, homedir, max);
		setenv("CFFIXED_USER_HOME", newhome, 1);
		free(newhome);
	}
}

void redirect_paths(const char* rootdir)
{
	char exe[PATH_MAX]; uint32_t sz = sizeof(exe);
	if (_NSGetExecutablePath(exe, &sz) != 0) return;
	char realExe[PATH_MAX]; if (!realpath(exe, realExe)) return;
	char realRoot[PATH_MAX]; if (!realpath(rootdir, realRoot)) return;
	size_t len = strlen(realRoot);
	if (len && realRoot[len-1] != '/') strlcat(realRoot, "/", sizeof(realRoot));
	if (strncmp(realExe, realRoot, len) != 0) return;

	redirect_env_paths(rootdir);
	if (_CFCanChangeEUIDs()) loadPathHook();
	if (__getppid() != 1) return;
	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/") != 0) return;
	ASSERT(chdir(rootdir) == 0);
}

void trust_insert_libraries(char** envc)
{
	char* libs = envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES");
	if (!libs) return;
	char* copy = strdup(libs);
	if (!copy) return;
	char* tok = strtok(copy, ":");
	while (tok) {
		jbclient_trust_library_recurse(tok, NULL);
		tok = strtok(NULL, ":");
	}
	free(copy);
}

int __no_need_to_trust_now__(const char*) { return 0; }

#define NBINPREFS 4
#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700

int roothide_systemhook___posix_spawn_prehook(
	pid_t *restrict pidp,
	const char *restrict path,
	struct _posix_spawn_args_desc *restrict desc,
	char *const argv[restrict], char *const envp[restrict],
	void *orig, int (*trust_binary)(const char*),
	int (*set_process_debugged)(uint64_t, bool), double jetsamMultiplier)
{
	if (!path) return __posix_spawn_orig(pidp, path, desc, argv, envp);
	if (!desc || !desc->attrp) {
		posix_spawnattr_t a; posix_spawnattr_init(&a);
		int r = posix_spawn(pidp, path,
			(desc && desc->file_actions) ? &desc->file_actions : NULL,
			&a, argv, envp);
		posix_spawnattr_destroy(&a);
		return r;
	}
	if (!dyld_patch_global_enabled) trust_binary = __no_need_to_trust_now__;
	return posix_spawn_hook_shared(pidp, path, desc, argv, envp,
		orig, trust_binary, set_process_debugged, jetsamMultiplier);
}

int roothide_systemhook___posix_spawn_posthook(
	pid_t *restrict pidp, const char *restrict path,
	struct _posix_spawn_args_desc *desc,
	char *const argv[restrict], char *const envp[restrict])
{
	posix_spawnattr_t *attrp = &desc->attrp;
	kSpawnConfig cfg = dyld_patch_global_enabled ? 0 : spawn_config_for_executable(path, argv);
	if (!dyld_patch_global_enabled && (cfg & kSpawnConfigTrust)) {
		cpu_type_t types[NBINPREFS]; cpu_subtype_t subs[NBINPREFS]; size_t cnt = 0;
		if (posix_spawnattr_getarchpref_np(attrp, NBINPREFS, types, subs, &cnt) == 0 && cnt) {
			xpc_object_t arr = xpc_array_create_empty();
			for (size_t i = 0; i < cnt; i++) {
				xpc_object_t d = xpc_dictionary_create_empty();
				xpc_dictionary_set_uint64(d, "type", types[i]);
				xpc_dictionary_set_uint64(d, "subtype", subs[i]);
				xpc_array_set_value(arr, XPC_ARRAY_APPEND, d);
				xpc_release(d);
			}
			jbclient_trust_executable_recurse(path, arr);
			xpc_release(arr);
		}
	}
	short flags = 0; posix_spawnattr_getflags(attrp, &flags);
	int proctype = 0; posix_spawnattr_getprocesstype_np(attrp, &proctype);
	bool suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool resume  = suspend && !(flags & POSIX_SPAWN_START_SUSPENDED);
	bool patch   = suspend && (flags & POSIX_SPAWN_SETEXEC);
	if (suspend) posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	if (patch && jbdSpawnExecStart(path, resume) != 0) { posix_spawnattr_setflags(attrp, flags); return 201; }
	char **envc = envbuf_mutcopy((const char **)envp);
	if (envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	if (!dyld_patch_global_enabled && (cfg & kSpawnConfigTrust)) trust_insert_libraries(envc);
	int pid = 0; int ret = __posix_spawn_orig(&pid, path, desc, argv, envc);
	if (pidp) *pidp = pid; envbuf_free(envc); posix_spawnattr_setflags(attrp, flags);
	if (patch) { jbdSpawnExecCancel(path); }
	else if (ret == 0 && pid > 0 && suspend) { if (jbdSpawnPatchChild(pid, resume) != 0) { kill(pid, SIGKILL); return 202; }}
	return ret;
}

int roothide_systemhook___execve_prehook(const char *path, char *const argv[], char *const envp[], void *orig, int (*trust_binary)(const char*))
{
	posix_spawnattr_t a; posix_spawnattr_init(&a);
	posix_spawnattr_setflags(&a, POSIX_SPAWN_SETEXEC);
	int r = posix_spawn(NULL, path, NULL, &a, argv, envp);
	posix_spawnattr_destroy(&a);
	if (r == EPERM && access(path, X_OK) == 0) return execve_hook_shared(path, argv, envp, orig, __no_need_to_trust_now__);
	errorno = r; return -1;
}

int roothide_systemhook___execve_posthook(const char *path, char *const argv[], char *const envp[])
{
	bool traced = false;
	if (jbdExecTraceStart(path, &traced) != 0) { errno = 203; return -1; }
	while (!traced) usleep(10000);
	char **envc = envbuf_mutcopy((const char **)envp);
	if (envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	int ret = __execve_orig(path, argv, envc); int old = errno;
	envc_free: envbuf_free(envc);
	jbdExecTraceCancel(path);
\errno = old; return ret;
}

#define DEFINE_DYLD_HOOK3(name, orig, idx, salt)                              \
	void* (*orig)(void*, const char*, int);                                    \
	static void* name##_impl(void* dyld, const char* path, int mode)           \
	{                                                                          \
		if (path && !(mode & RTLD_NOLOAD))                                     \
			jbclient_trust_library_recurse(path, __builtin_return_address(0)); \
		return orig(dyld, path, mode);                                         \
	}                                                                          \
	__attribute__((alias(#name "_impl")))                                      \
	void* name(void* dyld, const char* path, int mode);                        \
	static void __attribute__((constructor)) _reg_##name(void)                 \
	{                                                                          \
		void*** g = litehook_find_dsc_symbol(                                  \
			"/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");             \
		if (g)                                                                 \
			hook_dyld_routine(*g, idx, name, (void**)&orig, salt);             \
	}

#define DEFINE_DYLD_HOOK4(name, orig, idx, salt)                                    \
	void* (*orig)(void*, const char*, int, void*);                                   \
	static void* name##_impl(void* dyld, const char* path, int mode, void* caller)  \
	{                                                                               \
		if (path && !(mode & RTLD_NOLOAD))                                          \
			jbclient_trust_library_recurse(path, caller);                           \
		return orig(dyld, path, mode, caller);                                      \
	}                                                                               \
	__attribute__((alias(#name "_impl")))                                           \
	void* name(void* dyld, const char* path, int mode, void* caller);               \
	static void __attribute__((constructor)) _reg_##name(void)                      \
	{                                                                               \
		void*** g = litehook_find_dsc_symbol(                                       \
			"/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");                  \
		if (g)                                                                      \
			hook_dyld_routine(*g, idx, name, (void**)&orig, salt);                  \
	}

#define DEFINE_DYLD_PREHOOK(name, orig, idx, salt)                       \
	bool (*orig)(void*, const char*);                                     \
	static bool name##_impl(void* dyld, const char* path)                 \
	{                                                                     \
		if (path)                                                        \
			jbclient_trust_library_recurse(path, __builtin_return_address(0)); \
		return orig(dyld, path);                                         \
	}                                                                     \
	__attribute__((alias(#name "_impl")))                                 \
	bool name(void* dyld, const char* path);                              \
	static void __attribute__((constructor)) _reg_##name(void)            \
	{                                                                     \
		void*** g = litehook_find_dsc_symbol(                             \
			"/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");        \
		if (g)                                                            \
			hook_dyld_routine(*g, idx, name, (void**)&orig, salt);        \
	}

DEFINE_DYLD_HOOK3(dyld_dlopen_hook,            dyld_dlopen_orig,            14,   0xBF31)
DEFINE_DYLD_PREHOOK(dyld_dlopen_preflight_hook, dyld_dlopen_preflight_orig, 18,   0xB1B6)
DEFINE_DYLD_HOOK4(dyld_dlopen_from_hook,       dyld_dlopen_from_orig,       97,   0xD48C)
DEFINE_DYLD_HOOK3(dyld_dlopen_audited_hook,    dyld_dlopen_audited_orig,    98,   0xD2A5)

int hook_dyld_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	if (!dyld) return -1;
	uint64_t divers = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **fptrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, divers);
	if (!fptrs) return -1;
	if (vm_protect(mach_task_self_, (mach_vm_address_t)&fptrs[idx], sizeof(void*), false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
		uint64_t loc = (uint64_t)&fptrs[idx];
		uint64_t div = (loc & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);
		*orig = ptrauth_auth_and_resign(fptrs[idx], ptrauth_key_process_independent_code, div, ptrauth_key_function_pointer, 0);
		fptrs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, div);
		vm_protect(mach_task_self_, (mach_vm_address_t)&fptrs[idx], sizeof(void*), false, VM_PROT_READ);
		return 0;
	}
	return -1;
}

void roothide_init(void)
{
	const char *insert = getenv("DYLD_INSERT_LIBRARIES");
	const char *cache  = getenv("DYLD_IN_CACHE");
	if (insert && cache && strcmp(cache, "0") == 0) unsetenv("DYLD_IN_CACHE");
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
			void (*palera1n)(void) = dlsym(lib, "palera1n");
			ASSERT(palera1n);
			palera1n();
		}
	}
#endif

	if (string_has_suffix(exe, "/Dopamine.app/Dopamine"))
		loadPathHook();

	dlopen(JBROOT_PATH("/usr/lib/roothidepatch.dylib"), RTLD_NOW);
}
