#include "common.h"
#include "roothider.h"

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/getsect.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <paths.h>
#include <util.h>
#include <ptrauth.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/codesign.h>
#include <libjailbreak/jbroot.h>
#include "../dyldhook/src/dyld_jbinfo.h"
#include "litehook.h"
#include "sandbox.h"
#include "private.h"

extern int parse_dyldhook_jbinfo(char **jbRootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut);
extern const struct mach_header_64 *get_dyld_mach_header(void);

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
	struct _posix_spawn_args_desc *desc,
	char *const argv[restrict], char *const envp[restrict]);
int __posix_spawn_hook_with_filter(pid_t *restrict pid,
	const char *restrict path,
	char *const argv[restrict], char *const envp[restrict],
	struct _posix_spawn_args_desc *desc, int *ret);
int __execve_hook(const char *path, char *const argv[], char *const envp[]);

bool gFullyDebugged = false;
static void *gLibSandboxHandle = NULL;
char *JB_BootUUID = NULL;
char *JB_RootPath = NULL;
static char *JB_SandboxExtensions = NULL;
char *get_jbroot(void) { return JB_RootPath; }

static char gExecutablePath[PATH_MAX];

static int load_executable_path(void)
{
	char temp[PATH_MAX];
	uint32_t size = PATH_MAX;
	if (_NSGetExecutablePath(temp, &size) == 0 && realpath(temp, gExecutablePath))
		return 0;
	return -1;
}

static void consume_tokenized_sandbox_extensions(char *exts)
{
	char *tok = strtok(exts, "|");
	while (tok) {
		sandbox_extension_consume(tok);
		tok = strtok(NULL, "|");
	}
}

static void *(*orig_sandbox_apply)(void *) = NULL;
void *sandbox_apply_hook(void *ctx)
{
	void *res = orig_sandbox_apply(ctx);
	consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
	return res;
}

static inline int dyld_hook_routine(void **dyld, int idx, void *hook,
	void **orig, uint16_t salt)
{
	if (!dyld) return -1;
	uint64_t base = (uint64_t)*dyld;
	uint64_t diversifier = (base & ~(0xFFFFull<<48)) | ((uint64_t)salt<<48);
	void **funcs = ptrauth_auth_data(*dyld,
		ptrauth_key_process_independent_data, diversifier);
	if (!funcs) return -1;
	vm_protect(mach_task_self_, (mach_vm_address_t)&funcs[idx],
		sizeof(void*), false,
		VM_PROT_READ|VM_PROT_WRITE);
	*orig = ptrauth_auth_and_resign(funcs[idx],
		ptrauth_key_process_independent_code,
		diversifier,
		ptrauth_key_function_pointer, 0);
	funcs[idx] = ptrauth_auth_and_resign(hook,
		ptrauth_key_function_pointer, 0,
		ptrauth_key_process_independent_code,
		diversifier);
	vm_protect(mach_task_self_, (mach_vm_address_t)&funcs[idx],
		sizeof(void*), false, VM_PROT_READ);
	return 0;
}

static void update_csflag(uint32_t *flagp, pid_t pid)
{
	*flagp |= CS_VALID;
	*flagp &= ~CS_DEBUGGED;
	if (pid == getpid() && gFullyDebugged)
		*flagp |= CS_DEBUGGED;
}

int csops_status_hook(pid_t pid, unsigned ops, void *addr, size_t size)
{
	int rv = syscall(SYS_csops, pid, ops, addr, size);
	if (rv) return rv;
	if (ops == CS_OPS_STATUS && size == sizeof(uint32_t))
		update_csflag((uint32_t*)addr, pid);
	return 0;
}

#ifndef __arm64e__
int necp_match_policy_hook(uint8_t *parameters,
	size_t parameters_size,
	void *returned_result)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_match_policy,
		parameters, parameters_size, returned_result);
}
#endif

int ptrace_hook(int req, pid_t pid, caddr_t addr, int data)
{
	int r = syscall(SYS_ptrace, req, pid, addr, data);
	if (!r && (req == PT_ATTACHEXC || req == PT_ATTACH)) {
		jbclient_platform_set_process_debugged(pid, true);
		jbclient_platform_set_process_debugged(getpid(), true);
	}
	return r;
}

bool should_enable_tweaks(void)
{
	const char *env;
	if (!access(JBROOT_PATH("/basebin/.safe_mode"), F_OK)) return false;
	if ((env = getenv("DISABLE_TWEAKS")) && !strcmp(env, "1")) return false;
	if (getenv("_SafeMode") || getenv("_MSSafeMode")) return false;

	const char *suffixes[] = {"/usr/libexec/xpcproxy",
		"Dopamine.app/Dopamine"};
	for (unsigned i = 0; i < sizeof(suffixes)/sizeof(suffixes[0]); i++)
		if (string_has_suffix(gExecutablePath, suffixes[i]))
			return false;

	if (__builtin_available(iOS 16.0, *)) {
		const char *paths[] = {"/usr/libexec/logd",
			"/usr/sbin/notifyd",
			"/usr/libexec/usermanagerd"};
		for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++)
			if (!strcmp(gExecutablePath, paths[i]))
				return false;
	}

	return true;
}

__attribute__((constructor))
static void initializer(void)
{
	roothide_init();

	if (parse_dyldhook_jbinfo(&JB_RootPath,
		&JB_BootUUID,
		&JB_SandboxExtensions,
		&gFullyDebugged) != 0) {
		if (jbclient_process_checkin(&JB_RootPath,
			&JB_BootUUID,
			&JB_SandboxExtensions,
			&gFullyDebugged) == 0) {
			consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
		} else return;
	}

	const char *dyldEnv = getenv("DYLD_INSERT_LIBRARIES");
	if (dyldEnv && !strcmp(dyldEnv, HOOK_DYLIB_PATH))
		unsetenv("DYLD_INSERT_LIBRARIES");

	litehook_hook_function((void*)__posix_spawn,
		(void*)__posix_spawn_hook);
	litehook_hook_function((void*)__execve,
		(void*)__execve_hook);

	orig_sandbox_apply = dlsym(
		gLibSandboxHandle = dlopen(
			"/usr/lib/libsandbox.1.dylib",
			RTLD_FIRST|RTLD_LOCAL|RTLD_LAZY),
		"sandbox_apply");

	void *dyld_fcntl = litehook_find_symbol(
		get_dyld_mach_header(),
		"___fcntl");
	extern int __fcntl(int, int, ...);
	litehook_hook_function((void*)__fcntl, dyld_fcntl);

	if (load_executable_path() == 0) {
		if (!strcmp(gExecutablePath,
			"/usr/sbin/cfprefsd") ||
		    !strcmp(gExecutablePath,
			"/System/Library/CoreServices/SpringBoard.app/SpringBoard") ||
		    !strcmp(gExecutablePath,
			"/usr/libexec/lsd")) {
			dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		} else if (!strcmp(gExecutablePath,
			"/usr/libexec/watchdogd")) {
			dlopen(JBROOT_PATH("/basebin/watchdoghook.dylib"), RTLD_NOW);
		}

		if (string_has_suffix(gExecutablePath,
			"/debugserver"))
			litehook_hook_function(
				(void*)ptrace, (void*)ptrace_hook);

#ifndef __arm64e__
		litehook_hook_function(
			(void*)csops, (void*)csops_status_hook);
		litehook_hook_function(
			(void*)csops_audittoken,
			(void*)csops_status_hook);

		if (__builtin_available(iOS 16.0, *)) {
			litehook_hook_function(
				(void*)necp_match_policy,
				(void*)necp_match_policy_hook);
		}
#endif

		roothide_init_with_executable(gExecutablePath);

		if (should_enable_tweaks()) {
			const char *loader =
				JBROOT_PATH("/usr/lib/TweakLoader.dylib");
			void *h = dlopen(loader,
				RTLD_NOW);
			if (h) dlclose(h);
		}

#ifndef __arm64e__
		jbclient_cs_revalidate();
#endif
	}
}