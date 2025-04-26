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

static inline int dyld_hook_routine(void **dyld, int idx, void *hook, void **orig, uint16_t salt)
{
	if (!dyld) return -1;
	uint64_t base = (uint64_t)*dyld;
	uint64_t diversifier = (base & ~(0xFFFFull<<48)) | ((uint64_t)salt<<48);
	void **funcs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, diversifier);
	if (!funcs) return -1;
	vm_protect(mach_task_self_, (mach_vm_address_t)&funcs[idx], sizeof(void*), false, VM_PROT_READ|VM_PROT_WRITE);
	*orig = ptrauth_auth_and_resign(funcs[idx], ptrauth_key_process_independent_code, diversifier, ptrauth_key_function_pointer, 0);
	funcs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, diversifier);
	vm_protect(mach_task_self_, (mach_vm_address_t)&funcs[idx], sizeof(void*), false, VM_PROT_READ);
	return 0;
}

static void *(*orig_dlsym)(void*, void*, const char*) = NULL;
void *dyld_dlsym_hook(void *dyld, void *handle, const char *sym)
{
	if (handle == gLibSandboxHandle && !strcmp(sym, "sandbox_apply"))
		return sandbox_apply_hook;
	return orig_dlsym(dyld, handle, sym);
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
	if (syscall(SYS_csops, pid, ops, addr, size)) return -1;
	if (ops == CS_OPS_STATUS && size == sizeof(uint32_t))
		update_csflag((uint32_t*)addr, pid);
	return 0;
}

#ifndef __arm64e__
#define HOOK_NECP(fn, ...) \
int fn##_hook(__VA_ARGS__) { jbclient_cs_revalidate(); return syscall(SYS_##fn, __VA_ARGS__); }
HOOK_NECP(necp_match_policy, uint8_t *p, size_t s, void *r)
int necp_open_hook(int flags) { jbclient_cs_revalidate(); return syscall(SYS_necp_open, flags); }
#undef HOOK_NECP
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

	const char *suffixes[] = {"/usr/libexec/xpcproxy", "Dopamine.app/Dopamine"};
	for (unsigned i = 0; i < sizeof(suffixes)/sizeof(suffixes[0]); i++)
		if (string_has_suffix(gExecutablePath, suffixes[i])) return false;

	if (__builtin_available(iOS 16.0, *)) {
		const char *paths[] = {"/usr/libexec/logd", "/usr/sbin/notifyd", "/usr/libexec/usermanagerd"};
		for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++)
			if (!strcmp(gExecutablePath, paths[i])) return false;
	}

	return true;
}

__attribute__((constructor))
static void initializer(void)
{
	roothide_init();
	if (parse_dyldhook_jbinfo(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged) != 0) {
		if (jbclient_process_checkin(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged) == 0)
			consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
		else return;
	}

	if (getenv("DYLD_INSERT_LIBRARIES") && !strcmp(getenv("DYLD_INSERT_LIBRARIES"), HOOK_DYLIB_PATH))
		unsetenv("DYLD_INSERT_LIBRARIES");

	if (__builtin_available(iOS 16.0, *)) {
		litehook_hook_function(__posix_spawn, __posix_spawn_hook);
		litehook_hook_function(__execve,      __execve_hook);
	} else {
		void **psf = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_posix_spawn_with_filter");
		void **evf = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_execve_with_filter");
		*psf = __posix_spawn_hook_with_filter;
		*evf = __execve_hook;
	}

	orig_sandbox_apply = dlsym(gLibSandboxHandle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_FIRST|RTLD_LOCAL|RTLD_LAZY), "sandbox_apply");
	litehook_hook_function(__builtin_available(iOS 16.0, *) ? NULL : NULL, NULL); // placeholder

	if (load_executable_path() == 0) {
		if (!strcmp(gExecutablePath, "/usr/sbin/cfprefsd") ||
		    !strcmp(gExecutablePath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ||
		    !strcmp(gExecutablePath, "/usr/libexec/lsd")) {
			dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		} else if (!strcmp(gExecutablePath, "/usr/libexec/watchdogd")) {
			dlopen(JBROOT_PATH("/basebin/watchdoghook.dylib"), RTLD_NOW);
		}

		if (string_has_suffix(gExecutablePath, "/debugserver"))
			litehook_hook_function(ptrace, ptrace_hook);

#ifndef __arm64e__
		litehook_hook_function(csops, csops_status_hook);
		litehook_hook_function(csops_audittoken, csops_status_hook);
		if (__builtin_available(iOS 16.0, *)) {
			litehook_hook_function(necp_match_policy, necp_match_policy_hook);
			litehook_hook_function(necp_open, necp_open_hook);
		}
#endif

		roothide_init_with_executable(gExecutablePath);

		if (should_enable_tweaks()) {
			const char *loader = JBROOT_PATH("/usr/lib/TweakLoader.dylib");
			if (!access(loader, F_OK)) { dlopen(loader, RTLD_NOW); dlclose(loader); }
		}
#ifndef __arm64e__
		jbclient_cs_revalidate();
#endif
	}
}