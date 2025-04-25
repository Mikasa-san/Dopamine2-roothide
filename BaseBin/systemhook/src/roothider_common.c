#include <stdio.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/proc_info.h>
#include <string.h>
#include <limits.h>

#include "roothider.h"

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"

// Fast parent PID retrieval
static pid_t get_parent_pid(void) {
    struct kinfo_proc kp = {0};
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t len = sizeof(kp);
    if (sysctl(mib, 4, &kp, &len, NULL, 0) == 0 && (kp.kp_proc.p_flag & P_TRACED))
        return kp.kp_proc.p_oppid;

    struct proc_bsdinfo pi;
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &pi, sizeof(pi)) == sizeof(pi))
        return pi.pbi_ppid;

    return getppid();
}

// Extract app UUID path into buffer
static bool extract_uuid_path(const char *path, char *out, size_t outlen) {
    if (!path) return false;

    char realp[PATH_MAX];
    if (!realpath(path, realp)) return false;

    const size_t prefix_len = sizeof(APP_PATH_PREFIX) - 1;
    if (strncmp(realp, APP_PATH_PREFIX, prefix_len) != 0) return false;

    char *uuid_start = realp + prefix_len;
    if (strlen(uuid_start) < 36 || uuid_start[36] != '/') return false;

    size_t copy_len = prefix_len + 36;
    if (copy_len + 1 > outlen) return false;
    memcpy(out, realp, copy_len);
    out[copy_len] = '\0';
    return true;
}

bool isRemovableBundlePath(const char *path) {
    char uuid[PATH_MAX];
    return extract_uuid_path(path, uuid, sizeof(uuid));
}

bool hasTrollstoreMarker(const char *path) {
    char uuid[PATH_MAX], marker[PATH_MAX];
    if (!extract_uuid_path(path, uuid, sizeof(uuid))) return false;

    snprintf(marker, sizeof(marker), "%s/_TrollStore", uuid);
    if (access(marker, F_OK) == 0) return true;

    snprintf(marker, sizeof(marker), "%s/_TrollStoreLite", uuid);
    return (access(marker, F_OK) == 0);
}

bool allowInjectWithSafeMode(const char *path) {
    if (getpid() != 1) return true;

    char uuid[PATH_MAX];
    if (extract_uuid_path(path, uuid, sizeof(uuid))) {
        return hasTrollstoreMarker(path);
    }

    struct statfs fs;
    if (statfs(path, &fs) == 0 && strcmp(fs.f_mntonname, "/") == 0)
        return false;

    return true;
}

// Unified sysctl hook without extra headers
static int do_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp) {
    static int cached_name[CTL_MAXNAME+2];
    static int cached_len = 0;
    static bool inited = false;

    if (!inited) {
        inited = true;
        int mib[] = {0, 3};
        size_t blen = sizeof(cached_name);
        const char *query = "security.mac.amfi.developer_mode_status";
        if (syscall(SYS_sysctl, mib, 2, cached_name, &blen, (void*)query, strlen(query)) == 0) {
            cached_len = (int)(blen / sizeof(cached_name[0]));
        }
    }

    if (cached_len && namelen == (u_int)cached_len && 
        memcmp(name, cached_name, namelen * sizeof(int)) == 0) {
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            *(int*)oldp = 1;
            *oldlenp = sizeof(int);
            return 0;
        }
    }

    return syscall(SYS_sysctl, name, namelen, oldp, oldlenp, NULL, 0);
}

int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                   const void *newp, size_t newlen) {
    return do_sysctl(name, namelen, oldp, oldlenp);
}

int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp,
                        void *newp, size_t newlen) {
    const char *target = "security.mac.amfi.developer_mode_status";
    if (namelen == strlen(target) && strncmp(name, target, namelen) == 0) {
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            *(int*)oldp = 1;
            *oldlenp = sizeof(int);
            return 0;
        }
    }
    return syscall(SYS_sysctlbyname, name, namelen, oldp, oldlenp, NULL, 0);
}