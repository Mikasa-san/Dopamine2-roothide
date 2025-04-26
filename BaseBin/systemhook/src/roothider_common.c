#include <stdio.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/proc_info.h>
#include <dispatch/dispatch.h>

#include "roothider.h"

pid_t __getppid(void)
{
	struct proc_bsdinfo infoBSD;
	if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &infoBSD, sizeof(infoBSD)) == sizeof(infoBSD)) {
		return infoBSD.pbi_ppid;
	}

	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
	struct kinfo_proc info = {0};
	size_t len = sizeof(info);
	if (sysctl(mib, 4, &info, &len, NULL, 0) == 0 &&
		(info.kp_proc.p_flag & P_TRACED))
	{
		return info.kp_proc.p_oppid;
	}

	return getppid();
}

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
static char *getAppUUIDPath(const char *path)
{
	static char resolved[PATH_MAX];
	if (!path ||
		!realpath(path, resolved) ||
		strncmp(resolved, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
	{
		return NULL;
	}

	char *p2 = strchr(resolved + sizeof(APP_PATH_PREFIX)-1, '/');
	if (!p2 || p2 - (resolved + sizeof(APP_PATH_PREFIX)-1) != 36) {
		return NULL;
	}

	*p2 = '\0';
	return resolved;
}

bool isRemovableBundlePath(const char *path)
{
	return getAppUUIDPath(path) != NULL;
}

bool hasTrollstoreMarker(const char *path)
{
	char *uuid = getAppUUIDPath(path);
	if (!uuid) {
		return false;
	}

	char marker[PATH_MAX];
	snprintf(marker, sizeof(marker), "%s/_TrollStore", uuid);
	if (access(marker, F_OK) != 0) {
		snprintf(marker, sizeof(marker), "%s/_TrollStoreLite", uuid);
	}

	return access(marker, F_OK) == 0;
}

bool allowInjectWithSafeMode(const char *path)
{
	if (getpid() != 1) {
		return true;
	}

	if (isRemovableBundlePath(path)) {
		return hasTrollstoreMarker(path);
	}

	struct statfs fs;
	if (statfs(path, &fs) == 0 &&
		strcmp(fs.f_mntonname, "/") == 0)
	{
		return false;
	}

	return true;
}

int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp,
				  const void *newp, size_t newlen)
{
	static int cached_namelen;
	static int cached_name[CTL_MAXNAME + 1];
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		int mib[] = { CTL_KERN, KERN_PROC };
		size_t buflen = sizeof(cached_name);
		const char *query = "security.mac.amfi.developer_mode_status";
		if (syscall(SYS_sysctl, mib, 2, cached_name, &buflen,
					(void*)query, strlen(query)) == 0)
		{
			cached_namelen = buflen / sizeof(cached_name[0]);
		}
	});

	if (name &&
		(u_int)cached_namelen == namelen &&
		memcmp(name, cached_name, namelen * sizeof(int)) == 0 &&
		oldp && oldlenp && *oldlenp >= sizeof(int))
	{
		*(int*)oldp = 1;
		*oldlenp = sizeof(int);
		return 0;
	}

	return syscall(SYS_sysctl, name, namelen, oldp, oldlenp, newp, newlen);
}

int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	const char target[] = "security.mac.amfi.developer_mode_status";
	if (namelen == sizeof(target)-1 &&
		strncmp(name, target, namelen) == 0 &&
		oldp && oldlenp && *oldlenp >= sizeof(int))
	{
		*(int*)oldp = 1;
		*oldlenp = sizeof(int);
		return 0;
	}

	return syscall(SYS_sysctlbyname, name, namelen, oldp, oldlenp, newp, newlen);
}
