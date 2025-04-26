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
	char buf[PATH_MAX];
	uint32_t sz = PATH_MAX;
	if (_NSGetExecutablePath(buf, &sz) == 0)
		if (realpath(buf, gExecutablePath)) return 0;
	return -1;
}

static void consume_tokenized_sandbox_extensions(char *ext)
{
	if (!*ext) return;
	char *start = ext;
	for (char *p = ext; *p; ++p) {
		if (*p == '|') {
			*p = '\0';
			sandbox_extension_consume(start);
			*p = '|';
			start = p + 1;
		}
	}
	sandbox_extension_consume(start);
}

void *(*sandbox_apply_orig)(void *) = NULL;
void *sandbox_apply_hook(void *a1)
{
	void *r = sandbox_apply_orig(a1);
	consume_tokenized_sandbox_extensions(JB_BootUUID /*sic*/);
	return r;
}

int dyld_hook_routine(void **dyld, int idx, void *hook, void **orig, uint16_t salt)
{
	if (!dyld) return -1;
	uint64_t divers = ((uint64_t)dyld & ~(0xFFFFull<<48)) | ((uint64_t)salt<<48);
	void **ptrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, divers);
	if (!ptrs) return -1;
	if (!vm_protect(mach_task_self_, (mach_vm_address_t)&ptrs[idx], sizeof(void*), false,
	                VM_PROT_READ|VM_PROT_WRITE)) {
		uint64_t loc = (uint64_t)&ptrs[idx];
		uint64_t div2 = (loc & ~(0xFFFFull<<48)) | ((uint64_t)salt<<48);
		*orig = ptrauth_auth_and_resign(ptrs[idx],
			ptrauth_key_process_independent_code, divers,
			ptrauth_key_function_pointer, 0);
		ptrs[idx] = ptrauth_auth_and_resign(hook,
			ptrauth_key_function_pointer, 0,
			ptrauth_key_process_independent_code, div2);
		vm_protect(mach_task_self_, (mach_vm_address_t)&ptrs[idx], sizeof(void*), false,
		           VM_PROT_READ);
		return 0;
	}
	return -1;
}

void *(*dyld_dlsym_orig)(void*,void*,const char*);
void *dyld_dlsym_hook(void *dyld, void *h, const char *n)
{
	if (h == gLibSandboxHandle && !strcmp(n, "sandbox_apply"))
		return sandbox_apply_hook;
	return dyld_dlsym_orig(dyld, h, n);
}

int ptrace_hook(int req, pid_t pid, caddr_t addr, int d)
{
	int r = syscall(SYS_ptrace, req, pid, addr, d);
	if (!r && (req==PT_ATTACHEXC||req==PT_ATTACH)) {
		jbclient_platform_set_process_debugged(pid, true);
		jbclient_platform_set_process_debugged(getpid(), true);
	}
	return r;
}

#ifndef __arm64e__
#define NECP_HOOK(fn, name, ...) \
int fn(__VA_ARGS__) { jbclient_cs_revalidate(); return syscall(SYS_##name, __VA_ARGS__); }

NECP_HOOK(necp_match_policy_hook, necp_match_policy, uint8_t *p, size_t s, void *r)
NECP_HOOK(necp_open_hook, necp_open, int f)
NECP_HOOK(necp_client_action_hook, necp_client_action, int fd, uint32_t a, uuid_t cid, size_t l, uint8_t *b, size_t z)
NECP_HOOK(necp_session_open_hook, necp_session_open, int f)
NECP_HOOK(necp_session_action_hook, necp_session_action, int fd, uint32_t a, uint8_t *in, size_t il, uint8_t *out, size_t ol)

static int csops_common(pid_t pid, unsigned int ops, void *ua, size_t us)
{
	int rv = syscall(SYS_csops, pid, ops, ua, us);
	if (!rv && ops==CS_OPS_STATUS && ua && us==sizeof(uint32_t)) {
		uint32_t *f = ua;
		*f |= CS_VALID; *f &= ~CS_DEBUGGED;
		if (pid==getpid() && gFullyDebugged) *f |= CS_DEBUGGED;
	}
	return rv;
}
int csops_hook(pid_t pid, unsigned int o, void *ua, size_t us) {
	return csops_common(pid, o, ua, us);
}
int csops_audittoken_hook(pid_t pid, unsigned int o, void *ua, size_t us, audit_token_t *t) {
	(void)t; return csops_common(pid, o, ua, us);
}
#endif

static bool is_env_disabled(const char *n)
{
	const char *v = getenv(n);
	return v && !strcmp(v, "1");
}

bool should_enable_tweaks(void)
{
	if (!access(JBROOT_PATH("/basebin/.safe_mode"), F_OK)) return false;
	for (const char *e: (const char*[]){"DISABLE_TWEAKS","_SafeMode","_MSSafeMode",NULL})
		if (e && is_env_disabled(e)) return false;

	static const char *skip[] = {"/usr/libexec/xpcproxy","Dopamine.app/Dopamine"};
	for (int i=0; i<2; ++i)
		if (string_has_suffix(gExecutablePath, skip[i])) return false;

	if (__builtin_available(iOS 16.0, *)) {
		static const char *ios16[] = {"/usr/libexec/logd","/usr/sbin/notifyd","/usr/libexec/usermanagerd"};
		for (int i=0; i<3; ++i)
			if (!strcmp(gExecutablePath, ios16[i])) return false;
	}
	return true;
}

int __posix_spawn_hook(pid_t *p, const char *path, struct _posix_spawn_args_desc *d,
                       char *const argv[], char *const envp[])
{
	return roothide_systemhook___posix_spawn_prehook(p,path,d,argv,envp,
		(void*)roothide_systemhook___posix_spawn_posthook,
		jbclient_trust_file_by_path,
		jbclient_platform_set_process_debugged,
		jbclient_jbsettings_get_double("jetsamMultiplier"));
}

int __posix_spawn_hook_with_filter(pid_t *p, const char *path,
                                   char *const argv[], char *const envp[],
                                   struct _posix_spawn_args_desc *d, int *ret)
{
	*ret = roothide_systemhook___posix_spawn_prehook(p,path,d,argv,envp,
		(void*)roothide_systemhook___posix_spawn_posthook,
		jbclient_trust_file_by_path,
		jbclient_platform_set_process_debugged,
		jbclient_jbsettings_get_double("jetsamMultiplier"));
	return 1;
}

int __execve_hook(const char *path, char *const argv[], char *const envp[])
{
	return roothide_systemhook___execve_prehook(path,argv,envp,
		(void*)roothide_systemhook___execve_posthook,
		jbclient_trust_file_by_path);
}

const struct mach_header_64 *get_dyld_mach_header(void)
{
	static const struct mach_header_64 *hdr = NULL;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		task_dyld_info_data_t info;
		uint32_t cnt = TASK_DYLD_INFO_COUNT;
		if (task_info(mach_task_self_, TASK_DYLD_INFO,(task_info_t)&info,&cnt)==KERN_SUCCESS) {
			auto *ai = (struct dyld_all_image_infos*)info.all_image_info_addr;
			hdr = (const struct mach_header_64*)ai->dyldImageLoadAddress;
		}
	});
	return hdr;
}

int parse_dyldhook_jbinfo(char **rOut,char **bOut,char **sOut,bool *fOut)
{
	auto hdr = get_dyld_mach_header();
	if (!hdr) return -1;
	uuid_t u;
	if (_dyld_get_image_uuid((const struct mach_header*)hdr,u)) return -2;
	if (!string_has_prefix((char*)u,"DOPA")) return -3;
	size_t sz=0;
	auto *info = (struct dyld_jbinfo*)getsectiondata(hdr,"__DATA","__jbinfo",&sz);
	if (!info||info->state!=DYLD_STATE_CHECKED_IN) return -4;
	if (rOut) *rOut        = info->jbRootPath;
	if (bOut) *bOut        = info->bootUUID;
	if (sOut) *sOut        = info->sandboxExtensions;
	if (fOut) *fOut        = info->fullyDebugged;
	return 0;
}

__attribute__((constructor)) static void initializer(void)
{
	roothide_init();

	if (parse_dyldhook_jbinfo(&JB_RootPath,&JB_BootUUID,&JB_SandboxExtensions,&gFullyDebugged))
		if (jbclient_process_checkin(&JB_RootPath,&JB_BootUUID,&JB_SandboxExtensions,&gFullyDebugged)==0)
			consume_tokenized_sandbox_extensions(JB_SandboxExtensions);
		else
			return;

	if (getenv("DYLD_INSERT_LIBRARIES") &&
	    !strcmp(getenv("DYLD_INSERT_LIBRARIES"),HOOK_DYLIB_PATH))
		unsetenv("DYLD_INSERT_LIBRARIES");

	if (__builtin_available(iOS 16.0, *)) {
		litehook_hook_function(__posix_spawn, __posix_spawn_hook);
		litehook_hook_function(__execve,      __execve_hook);
	} else {
		auto **psf = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib","_posix_spawn_with_filter");
		auto **evf = litehook_find_dsc_symbol("/usr/lib/system/libsystem_kernel.dylib","_execve_with_filter");
		*psf = __posix_spawn_hook_with_filter;
		*evf = __execve_hook;
	}

	void *f = litehook_find_symbol(get_dyld_mach_header(),"___fcntl");
	extern int __fcntl(int,int,...);
	litehook_hook_function(__fcntl,f);

	gLibSandboxHandle = dlopen("/usr/lib/libsandbox.1.dylib",RTLD_FIRST|RTLD_LOCAL|RTLD_LAZY);
	sandbox_apply_orig = dlsym(gLibSandboxHandle,"sandbox_apply");

	if (auto ***d = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib","__ZN5dyld45gDyldE"))
		dyld_hook_routine(*d,17,(void*)&dyld_dlsym_hook,(void**)&dyld_dlsym_orig,0x839D);

	roothide_init_with_checkin(JB_RootPath);

#ifdef __arm64e__
	if (!sandbox_check(getpid(),"process-fork",SANDBOX_CHECK_NO_REPORT,NULL))
		dlopen(JBROOT_PATH("/basebin/forkfix.dylib"),RTLD_NOW);
#endif

	if (!load_executable_path()) {
		if (!strcmp(gExecutablePath,"/usr/sbin/cfprefsd")||
		    !strcmp(gExecutablePath,"/System/Library/CoreServices/SpringBoard.app/SpringBoard")||
		    !strcmp(gExecutablePath,"/usr/libexec/lsd"))
			dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"),RTLD_NOW);
		else if (!strcmp(gExecutablePath,"/usr/libexec/watchdogd"))
			dlopen(JBROOT_PATH("/basebin/watchdoghook.dylib"),RTLD_NOW);

		if (string_has_suffix(gExecutablePath,"/debugserver"))
			litehook_hook_function(ptrace, ptrace_hook);

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
			if (!access(tl,F_OK)) { void *h = dlopen(tl,RTLD_NOW); if (h) dlclose(h); }
		}
#ifndef __arm64e__
		jbclient_cs_revalidate();
#endif
	}
}