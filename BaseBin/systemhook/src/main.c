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
static int load_executable_path(void)
{
	char executablePath[PATH_MAX];
	uint32_t bufsize = PATH_MAX;
	if (_NSGetExecutablePath(executablePath, &bufsize) == 0) {
		if (realpath(executablePath, gExecutablePath) != NULL) return 0;
	}
	return -1;
}

static char *JB_SandboxExtensions = NULL;

void consume_tokenized_sandbox_extensions(char *sandboxExtensions)
{
	if (sandboxExtensions[0] == '\0') return;

	char *it = sandboxExtensions;
	char *last = sandboxExtensions;
	while (*(++it) != '\0') {
		if (*it == '|') {
			*it = '\0';
			sandbox_extension_consume(last);
			last = &it[1];
			*it = '|';
		}
	}
	sandbox_extension_consume(last);
}

void *(*sandbox_apply_orig)(void *) = NULL;
void *sandbox_apply_hook(void *a1)
{
	void *r = sandbox_apply_orig(a1);
	consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
	return r;
}

int dyld_hook_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
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

void *(*dyld_dlsym_orig)(void *dyld, void *handle, const char *name);
void *dyld_dlsym_hook(void *dyld, void *handle, const char *name)
{
	if (handle == gLibSandboxHandle && !strcmp(name, "sandbox_apply")) {

		return sandbox_apply_hook;
	}
	__attribute__((musttail)) return dyld_dlsym_orig(dyld, handle, name);
}

int ptrace_hook(int request, pid_t pid, caddr_t addr, int data)
{
	int r = syscall(SYS_ptrace, request, pid, addr, data);

	if (r == 0 && (request == PT_ATTACHEXC || request == PT_ATTACH)) {
		jbclient_platform_set_process_debugged(pid, true);
		jbclient_platform_set_process_debugged(getpid(), true);
	}

	return r;
}

#ifndef __arm64e__

int necp_match_policy_hook(uint8_t *parameters, size_t parameters_size, void *returned_result)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_match_policy, parameters, parameters_size, returned_result);
}

int necp_open_hook(int flags)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_open, flags);
}

int necp_client_action_hook(int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_client_action, necp_fd, action, client_id, client_id_len, buffer, buffer_size);
}

int necp_session_open_hook(int flags)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_session_open, flags);
}

int necp_session_action_hook(int necp_fd, uint32_t action, uint8_t *in_buffer, size_t in_buffer_length, uint8_t *out_buffer, size_t out_buffer_length)
{
	jbclient_cs_revalidate();
	return syscall(SYS_necp_session_action, necp_fd, action, in_buffer, in_buffer_length, out_buffer, out_buffer_length);
}

int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
	int rv = syscall(SYS_csops, pid, ops, useraddr, usersize);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t* csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
			if (pid == getpid() && gFullyDebugged) {
				*csflag |= CS_DEBUGGED;
			}
		}
	}
	return rv;
}

int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token)
{
	int rv = syscall(SYS_csops_audittoken, pid, ops, useraddr, usersize, token);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t* csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
			if (pid == getpid() && gFullyDebugged) {
				*csflag |= CS_DEBUGGED;
			}
		}
	}
	return rv;
}

#endif

bool should_enable_tweaks(void)
{
	if (access(JBROOT_PATH("/basebin/.safe_mode"), F_OK) == 0)
		return false;

	{
		char *v;

		v = getenv("DISABLE_TWEAKS");
		if (v && v[0] == '1' && v[1] == '\0')
			return false;

		v = getenv("_SafeMode");
		if (v && v[0] == '1' && v[1] == '\0')
			return false;

		v = getenv("_MSSafeMode");
		if (v && v[0] == '1' && v[1] == '\0')
			return false;
	}

	if (string_has_suffix(gExecutablePath, "/usr/libexec/xpcproxy"))
		return false;
	if (string_has_suffix(gExecutablePath, "Dopamine.app/Dopamine"))
		return false;

	if (__builtin_available(iOS 16.0, *)) {
		if (!strcmp(gExecutablePath, "/usr/libexec/logd"))
			return false;
		if (!strcmp(gExecutablePath, "/usr/sbin/notifyd"))
			return false;
		if (!strcmp(gExecutablePath, "/usr/libexec/usermanagerd"))
			return false;
	}

	return true;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char * const envp[restrict])
{
	return roothide_systemhook___posix_spawn_prehook(pid, path, desc, argv, envp, (void *)roothide_systemhook___posix_spawn_posthook, jbclient_trust_file_by_path, jbclient_platform_set_process_debugged, jbclient_jbsettings_get_double("jetsamMultiplier"));
}

int __posix_spawn_hook_with_filter(pid_t *restrict pid, const char *restrict path, char *const argv[restrict], char * const envp[restrict], struct _posix_spawn_args_desc *desc, int *ret)
{
	*ret = roothide_systemhook___posix_spawn_prehook(pid, path, desc, argv, envp, (void *)roothide_systemhook___posix_spawn_posthook, jbclient_trust_file_by_path, jbclient_platform_set_process_debugged, jbclient_jbsettings_get_double("jetsamMultiplier"));
	return 1;
}

int __execve_hook(const char *path, char *const argv[], char *const envp[])
{
	return roothide_systemhook___execve_prehook(path, argv, envp, (void *)roothide_systemhook___execve_posthook, jbclient_trust_file_by_path);
}

const struct mach_header_64 *get_dyld_mach_header(void)
{
	static const struct mach_header_64 *dyldMachHeader = NULL;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		task_dyld_info_data_t dyldInfo;
		uint32_t count = TASK_DYLD_INFO_COUNT;
		kern_return_t kr = task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
		if (kr == KERN_SUCCESS) {
			struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
			dyldMachHeader = (const struct mach_header_64 *)infos->dyldImageLoadAddress;
		}
	});
	return dyldMachHeader;
}

int parse_dyldhook_jbinfo(char **jbRootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut)
{

	const struct mach_header_64 *dyldHeader = get_dyld_mach_header();
	if (!dyldHeader) return -1;

	uuid_t dyldUUID;
	if (!_dyld_get_image_uuid((const struct mach_header *)dyldHeader, dyldUUID)) return -2;
	if (!string_has_prefix((char *)dyldUUID, "DOPA")) return -3;

	size_t jbInfoSize = 0;
	struct dyld_jbinfo *jbInfo = (struct dyld_jbinfo *)getsectiondata(dyldHeader, "__DATA", "__jbinfo", &jbInfoSize);
	if (!jbInfo) return -4;

	if (jbInfo->state != DYLD_STATE_CHECKED_IN) return -5;

	if (jbRootPathOut)        *jbRootPathOut        = jbInfo->jbRootPath;
	if (bootUUIDOut)          *bootUUIDOut          = jbInfo->bootUUID;
	if (sandboxExtensionsOut) *sandboxExtensionsOut = jbInfo->sandboxExtensions;
	if (fullyDebuggedOut)     *fullyDebuggedOut     = jbInfo->fullyDebugged;

	return 0;
}

__attribute__((constructor)) static void initializer(void)
{	

	roothide_init();

	if (parse_dyldhook_jbinfo(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged) != 0) {

		if (jbclient_process_checkin(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions, &gFullyDebugged) == 0) {
			consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
		}
		else {

			return;
		}
	}

	const char *dyldInsertLibraries = getenv("DYLD_INSERT_LIBRARIES");
	if (dyldInsertLibraries) {
		if (!strcmp(dyldInsertLibraries, HOOK_DYLIB_PATH)) {
			unsetenv("DYLD_INSERT_LIBRARIES");
		}
	}

	if (__builtin_available(iOS 16.0, *)) {
		litehook_hook_function(__posix_spawn, __posix_spawn_hook);
		litehook_hook_function(__execve,      __execve_hook);
	}
	else {

		void **posix_spawn_with_filter = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_posix_spawn_with_filter");
		void **execve_with_filter      = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib", "_execve_with_filter");

		*posix_spawn_with_filter = __posix_spawn_hook_with_filter;
		*execve_with_filter      = __execve_hook;
	}

	void *dyld___fcntl = litehook_find_symbol(get_dyld_mach_header(), "___fcntl");
	extern int __fcntl(int fd, int op, ...  );
	litehook_hook_function(__fcntl, dyld___fcntl);

	gLibSandboxHandle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_FIRST | RTLD_LOCAL | RTLD_LAZY);
	sandbox_apply_orig = dlsym(gLibSandboxHandle, "sandbox_apply");

	void ***gDyldPtr = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
	if (gDyldPtr) {

		dyld_hook_routine(*gDyldPtr, 17, (void *)&dyld_dlsym_hook, (void **)&dyld_dlsym_orig, 0x839D);
	}

roothide_init_with_checkin(JB_RootPath); 

#ifdef __arm64e__

	if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0) {
		dlopen(JBROOT_PATH("/basebin/forkfix.dylib"), RTLD_NOW);
	}
#endif

	if (load_executable_path() == 0) {

		if (!strcmp(gExecutablePath, "/usr/sbin/cfprefsd") ||
			!strcmp(gExecutablePath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") ||
			!strcmp(gExecutablePath, "/usr/libexec/lsd")) {
			dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		}
		else if (!strcmp(gExecutablePath, "/usr/libexec/watchdogd")) {
			dlopen(JBROOT_PATH("/basebin/watchdoghook.dylib"), RTLD_NOW);
		}

		if (string_has_suffix(gExecutablePath, "/debugserver")) {
			litehook_hook_function(ptrace, ptrace_hook);
		}

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
			const char *tweakLoaderPath = JBROOT_PATH("/usr/lib/TweakLoader.dylib");
			if (access(tweakLoaderPath, F_OK) == 0) {
				void *tweakLoaderHandle = dlopen(tweakLoaderPath, RTLD_NOW);
				if (tweakLoaderHandle != NULL) {
					dlclose(tweakLoaderHandle);
				}
			}
		}

#ifndef __arm64e__

		jbclient_cs_revalidate();
#endif
	}
}