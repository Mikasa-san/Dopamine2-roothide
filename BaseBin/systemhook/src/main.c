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
static void *gLibSandboxHandle;
char *JB_BootUUID = NULL;
char *JB_RootPath = NULL;
char *get_jbroot(void) { return JB_RootPath; }

static char gExecutablePath[PATH_MAX];
static int load_executable_path(void) {
	char path[PATH_MAX];
	uint32_t size = PATH_MAX;
	if (_NSGetExecutablePath(path, &size) == 0)
		return realpath(path, gExecutablePath) ? 0 : -1;
	return -1;
}

static char *JB_SandboxExtensions = NULL;
void consume_tokenized_sandbox_extensions(char *ext) {
	char *s = ext, *p = ext;
	if (!*s) return;
	while (*(++s)) {
		if (*s == '|') {
			*s = '\0';
			sandbox_extension_consume(p);
			p = s + 1;
			*s = '|';
		}
	}
	sandbox_extension_consume(p);
}

void *(*sandbox_apply_orig)(void *) = NULL;
void *sandbox_apply_hook(void *a1) {
	void *r = sandbox_apply_orig(a1);
	consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
	return r;
}

int dyld_hook_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt) {
	if (!dyld) return -1;
	uint64_t diversifier = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **funcs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, diversifier);
	if (!funcs) return -1;
	if (vm_protect(mach_task_self_, (mach_vm_address_t)&funcs[idx], sizeof(void *), false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
		uint64_t loc = (uint64_t)&funcs[idx];
		uint64_t pd = (loc & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);
		*orig = ptrauth_auth_and_resign(funcs[idx], ptrauth_key_process_independent_code, pd, ptrauth_key_function_pointer, 0);
		funcs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, pd);
		vm_protect(mach_task_self_, (mach_vm_address_t)&funcs[idx], sizeof(void *), false, VM_PROT_READ);
		return 0;
	}
	return -1;
}

void *(*dyld_dlsym_orig)(void *, void *, const char *);
void *dyld_dlsym_hook(void *dyld, void *handle, const char *name) {
	if (handle == gLibSandboxHandle && !strcmp(name, "sandbox_apply"))
		return sandbox_apply_hook;
	__attribute__((musttail)) return dyld_dlsym_orig(dyld, handle, name);
}

int ptrace_hook(int req, pid_t pid, caddr_t addr, int data) {
	int r = syscall(SYS_ptrace, req, pid, addr, data);
	if (!r && (req == PT_ATTACHEXC || req == PT_ATTACH)) {
		jbclient_platform_set_process_debugged(pid, true);
		jbclient_platform_set_process_debugged(getpid(), true);
	}
	return r;
}

#ifndef __arm64e__
#define NECP_HOOK(fn, ...) \
int fn##_hook(__VA_ARGS__) { jbclient_cs_revalidate(); return syscall(SYS_##fn, __VA_ARGS__); }

NECP_HOOK(necp_match_policy, uint8_t *parameters, size_t parameters_size, void *returned_result)
NECP_HOOK(necp_open, int flags)
NECP_HOOK(necp_client_action, int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size)
NECP_HOOK(necp_session_open, int flags)
NECP_HOOK(necp_session_action, int necp_fd, uint32_t action, uint8_t *in_buffer, size_t in_length, uint8_t *out_buffer, size_t out_length)

static int csops_common(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
	int rv = syscall(SYS_csops, pid, ops, useraddr, usersize);
	if (!rv && ops == CS_OPS_STATUS && useraddr && usersize == sizeof(uint32_t)) {
		uint32_t *f = useraddr;
		*f = (*f | CS_VALID) & ~CS_DEBUGGED;
		if (pid == getpid() && gFullyDebugged) *f |= CS_DEBUGGED;
	}
	return rv;
}
int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) { return csops_common(pid, ops, useraddr, usersize); }
int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token) { (void)token; return csops_common(pid, ops, useraddr, usersize); }
#endif

bool should_enable_tweaks(void) {
	if (!access(JBROOT_PATH("/basebin/.safe_mode"), F_OK)) return false;
	char *e = getenv("DISABLE_TWEAKS"); if (e && !strcmp(e, "1")) return false;
	e = getenv("_SafeMode"); if (e && !strcmp(e, "1")) return false;
	e = getenv("_MSSafeMode"); if (e && !strcmp(e, "1")) return false;
	const char *sufs[] = { "/usr/libexec/xpcproxy", "Dopamine.app/Dopamine" };
	for (int i = 0; i < 2; i++) if (string_has_suffix(gExecutablePath, sufs[i])) return false;
	if (__builtin_available(iOS 16.0, *)) {
		const char *iOS16[] = { "/usr/libexec/logd", "/usr/sbin/notifyd", "/usr/libexec/usermanagerd" };
		for (int i = 0; i < 3; i++) if (!strcmp(gExecutablePath, iOS16[i])) return false;
	}
	return true;
}

int __posix_spawn_hook(pid_t *pid, const char *path, struct _posix_spawn_args_desc *desc, char *const argv[], char *const envp[]) {
	return roothide_systemhook___posix_spawn_prehook(pid, path, desc, argv, envp, (void *)roothide_systemhook___posix_spawn_posthook, jbclient_trust_file_by_path, jbclient_platform_set_process_debugged, jbclient_jbsettings_get_double("jetsamMultiplier"));
}
int __posix_spawn_hook_with_filter(pid_t *pid, const char *path, char *const argv[], char *const envp[], struct _posix_spawn_args_desc *desc, int *ret) {
	*ret = roothide_systemhook___posix_spawn_prehook(pid, path, desc, argv, envp, (void *)roothide_systemhook___posix_spawn_posthook, jbclient_trust_file_by_path, jbclient_platform_set_process_debugged, jbclient_jbsettings_get_double("jetsamMultiplier"));
	return 1;
}
int __execve_hook(const char *path, char *const argv[], char *const envp[]) {
	return roothide_systemhook___execve_prehook(path, argv, envp, (void *)roothide_systemhook___execve_posthook, jbclient_trust_file_by_path);
}

static const struct mach_header_64 *get_dyld_mach_header(void) {
	static const struct mach_header_64 *hdr = NULL;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		task_dyld_info_data_t info; uint32_t cnt = TASK_DYLD_INFO_COUNT;
		if (task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&info, &cnt) == KERN_SUCCESS)
			hdr = (const struct mach_header_64 *)((struct dyld_all_image_infos *)info.all_image_info_addr)->dyldImageLoadAddress;
	});
	return hdr;
}

int parse_dyldhook_jbinfo(char **jbRoot, char **bootUUID, char **sandboxExt, bool *fullyDebugged) {
	const struct mach_header_64 *hdr = get_dyld_mach_header(); if (!hdr) return -1;
	uuid_t uuid; if (!_dyld_get_image_uuid((const struct mach_header *)hdr, uuid)) return -2;
	if (!string_has_prefix((char *)uuid, "DOPA")) return -3;
	size_t size = 0;
	struct dyld_jbinfo *info = (struct dyld_jbinfo *)getsectiondata(hdr, "__DATA", "__jbinfo", &size);
	if (!info) return -4;
	if (info->state != DYLD_STATE_CHECKED_IN) return -5;
	if (jbRoot) *jbRoot = info->jbRootPath;
	if (bootUUID) *bootUUID = info->bootUUID;
	if (sandboxExt) *sandboxExt = info->sandboxExtensions;
	if (fullyDebugged) *fullyDebugged = info->fullyDebugged;
	return 0;
}

__attribute__((constructor)) static void initializer(void) {
	roothide_init();
	if (parse_dyldhook_jbinfo(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged) != 0) {
		if (jbclient_process_checkin(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged) == 0)
			consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
		else return;
	}
	char *d = getenv("DYLD_INSERT_LIBRARIES"); if (d && !strcmp(d, HOOK_DYLIB_PATH)) unsetenv("DYLD_INSERT_LIBRARIES");
	if (__builtin_available(iOS 16.0, *)) {
		litehook_hook_function(__posix_spawn, __posix_spawn_hook);
		litehook_hook_function(__execve, __execve_hook);
	} else {
		void **ps = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_posix_spawn_with_filter");
		void **ev = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_execve_with_filter");
		*ps = (void *)__posix_spawn_hook_with_filter;
		*ev = (void *)__execve_hook;
	}
	void *dyld_fcntl = litehook_find_symbol(get_dyld_mach_header(), "___fcntl");
	extern int __fcntl(int, int, ...);
	litehook_hook_function(__fcntl, dyld_fcntl);
	gLibSandboxHandle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_FIRST | RTLD_LOCAL | RTLD_LAZY);
	sandbox_apply_orig = dlsym(gLibSandboxHandle, "sandbox_apply");
	void ***gDyldPtr = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "__ZN5dyld45gDyldE");
	if (gDyldPtr) dyld_hook_routine(*gDyldPtr, 17, (void *)&dyld_dlsym_hook, (void **)&dyld_dlsym_orig, 0x839D);
	roothide_init_with_checkin(JB_RootPath);
#ifdef __arm64e__
	if (!sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL))
		dlopen(JBROOT_PATH("/basebin/forkfix.dylib"), RTLD_NOW);
#endif
	if (load_executable_path() == 0) {
		if (!strcmp(gExecutablePath, "/usr/sbin/cfprefsd") || !strcmp(gExecutablePath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") || !strcmp(gExecutablePath, "/usr/libexec/lsd"))
			dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		else if (!strcmp(gExecutablePath, "/usr/libexec/watchdogd"))
			dlopen(JBROOT_PATH("/basebin/watchdoghook.dylib"), RTLD_NOW);
		if (string_has_suffix(gExecutablePath, "/debugserver")) litehook_hook_function(ptrace, ptrace_hook);
#ifndef __arm64e__
		litehook_hook_function(csops, csops_hook);
		litehook_hook_function(csops_audittoken, csops_audittoken_hook);
		if (__builtin_available(iOS 16.0, *)) {
			litehook_hook_function(necp_match_policy, necp_match_policy_hook);
			litehook_hook_function(necp_open, necp_open_hook);
			litehook_hook_function(necp_client_action, necp_client_action_hook);
			litehook_hook_function(necp_session_open, necp_session_open_hook);
			litehook_hook_function(necp_session_action, necp_session_action_hook);
		}
#endif
		roothide_init_with_executable(gExecutablePath);
		if (should_enable_tweaks()) {
			const char *tl = JBROOT_PATH("/usr/lib/TweakLoader.dylib");
			if (!access(tl, F_OK)) { void *h = dlopen(tl, RTLD_NOW); if (h) dlclose(h); }
		}
#ifndef __arm64e__
		jbclient_cs_revalidate();
#endif
	}
}