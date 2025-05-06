#include "common.h"
#include "roothider.h"
#include <xpc/xpc.h>
#include "launchd.h"
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sandbox.h>
#include <paths.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "envbuf.h"
#include "private.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/jbserver_domains.h>

bool string_has_prefix(const char *str, const char *prefix) {
	if (!str || !prefix) return false;
	size_t pre = strlen(prefix);
	return strlen(str) >= pre && memcmp(str, prefix, pre) == 0;
}

bool string_has_suffix(const char *str, const char *suffix) {
	if (!str || !suffix) return false;
	size_t sfx = strlen(suffix), len = strlen(str);
	return len >= sfx && memcmp(str + len - sfx, suffix, sfx) == 0;
}

void string_enumerate_components(const char *string, const char *sep, void (^enumBlock)(const char *comp, bool *stop)) {
	char *buf = strdup(string);
	char *tok = strtok(buf, sep);
	while (tok) {
		bool stop = false;
		enumBlock(tok, &stop);
		if (stop) break;
		tok = strtok(NULL, sep);
	}
	free(buf);
}

static const char *processBlacklist[] = {
	"/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
	"/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd",
	"/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
	"/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService"
};

kSpawnConfig spawn_config_for_executable(const char *path, char *const argv[restrict]) {
	if (!strcmp(path, "/usr/libexec/xpcproxy") && argv && argv[0] && argv[1] &&
		string_has_prefix(argv[1], "com.apple.WebKit.WebContent")) {
		// Skip injection for WebKit WebContent processes on iOS 16+
		if (__builtin_available(iOS 16.0, *)) {
			return 0;
		}
	}
	for (size_t i = 0; i < sizeof(processBlacklist)/sizeof(*processBlacklist); i++) {
		if (strcmp(processBlacklist[i], path) == 0)
			return 0;
	}
	return kSpawnConfigInject | kSpawnConfigTrust;
}

int __posix_spawn_orig(pid_t *pid, const char *path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]) {
	return syscall(SYS_posix_spawn, pid, path, desc, argv, envp);
}

int __execve_orig(const char *path, char *const argv[], char *const envp[]) {
	return syscall(SYS_execve, path, argv, envp);
}

static int spawn_exec_hook_common(const char *path,
					 char *const argv[restrict],
					 char *const envp[restrict],
					 struct _posix_spawn_args_desc *desc,
					 int (*trust_binary)(const char *),
					 double jetsamMultiplier,
					 int (^orig_call)(char *const envp_patched[])) {
	if (!path) return orig_call((char *const*)envp);

	posix_spawnattr_t attr = desc ? desc->attrp : NULL;
	kSpawnConfig cfg = spawn_config_for_executable(path, argv);

	if (cfg & kSpawnConfigTrust) trust_binary(path);

	// Check existing DYLD_INSERT_LIBRARIES
	const char *existing = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES");
	bool hookInserted = false;
	if (existing) {
		char *dup = strdup(existing);
		char *tok = strtok(dup, ":");
		while (tok) {
			if (strcmp(tok, HOOK_DYLIB_PATH) == 0) { hookInserted = true; break; }
			tok = strtok(NULL, ":");
		}
		free(dup);
	}

	// Determine injection
	bool inject = (cfg & kSpawnConfigInject) != 0;
	const char *safe = envbuf_getenv((const char **)envp, "_SafeMode");
	const char *mss = envbuf_getenv((const char **)envp, "_MSSafeMode");
	if ((safe && strcmp(safe, "1") == 0) || (mss && strcmp(mss, "1") == 0)) inject = false;

	// Adjust jetsam
	if (inject && attr && jetsamMultiplier > 1) {
		uint8_t *a = (uint8_t*)attr;
		int *active = (int*)(a + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
		int *inactive = (int*)(a + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
		if (*active != -1) *active *= jetsamMultiplier;
		if (*inactive != -1) *inactive *= jetsamMultiplier;
	}

	// Call original or modify env
	int result;
	if ((inject && hookInserted) || (!inject && !hookInserted)) {
		result = orig_call((char *const*)envp);
	} else {
		char **envc = envbuf_mutcopy((const char **)envp);
		if (inject && !hookInserted) {
			char newVal[strlen(HOOK_DYLIB_PATH) + (existing ? strlen(existing)+1 : 0) + 1];
			strcpy(newVal, HOOK_DYLIB_PATH);
			if (existing) { strcat(newVal, ":"); strcat(newVal, existing); }
			envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newVal);
		} else if (!inject && hookInserted) {
			envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
		}
		envbuf_unsetenv(&envc, "_SafeMode");
		envbuf_unsetenv(&envc, "_MSSafeMode");

		result = orig_call((char *const*)envc);
		envbuf_free(envc);
	}
	return result;
}

int posix_spawn_hook_shared(pid_t *pid,
			 const char *path,
			 struct _posix_spawn_args_desc *desc,
			 char *const argv[restrict],
			 char *const envp[restrict],
			 void *orig,
			 int (*trust_binary)(const char *),
			 int (*set_process_debugged)(uint64_t, bool),
			 double jetsamMultiplier) {
	int (*orig_spawn)(pid_t*, const char*, struct _posix_spawn_args_desc*, char*const[], char*const[]) = orig;
	int r = spawn_exec_hook_common(path, argv, envp, desc, trust_binary, jetsamMultiplier,
								^(char *const envp2[]){ return orig_spawn(pid, path, desc, argv, envp2); });
	if (r == 0 && pid && desc) {
		posix_spawnattr_t attr = desc->attrp;
		short flags;
		if (posix_spawnattr_getflags(&attr, &flags) == 0 && (flags & POSIX_SPAWN_START_SUSPENDED)) {
			set_process_debugged(*pid, false);
		}
	}
	return r;
}

int execve_hook_shared(const char *path,
		 char *const argv[],
		 char *const envp[],
		 void *orig,
		 int (*trust_binary)(const char *)) {
	int (*orig_execve)(const char*, char*const[], char*const[]) = orig;
	return spawn_exec_hook_common(path, argv, envp, NULL, trust_binary, 0,
						^(char *const envp2[]){ return orig_execve(path, argv, envp2); });
}