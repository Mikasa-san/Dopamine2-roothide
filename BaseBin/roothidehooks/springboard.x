#import <Foundation/Foundation.h>
#include <roothide.h>
#import <fcntl.h>
#include "common.h"

bool string_has_prefix(const char *str, const char* prefix) {
	return str && prefix && strncmp(str, prefix, strlen(prefix)) == 0;
}

@interface XBSnapshotContainerIdentity : NSObject <NSCopying>
@property (nonatomic, readonly, copy) NSString *bundleIdentifier;
- (NSString *)snapshotContainerPath;
@end

%hook XBSnapshotContainerIdentity

- (NSString *)snapshotContainerPath {
	NSString *path = %orig;
	if ([path hasPrefix:@"/var/mobile/Library/SplashBoard/Snapshots/"] &&
		![self.bundleIdentifier hasPrefix:@"com.apple."]) {
		return jbroot(path);
	}
	return path;
}

%end

%hookf(int, fcntl, int fildes, int cmd, ...) {
	if (cmd == F_SETPROTECTIONCLASS) {
		char filePath[PATH_MAX];
		if (fcntl(fildes, F_GETPATH, filePath) != -1 &&
			string_has_prefix(filePath, jbroot("/var/mobile/Library/SplashBoard/Snapshots"))) {
			return 0;
		}
	}

	va_list a;
	va_start(a, cmd);
	int result = %orig(fildes, cmd, va_arg(a, void *), va_arg(a, void *), 
					   va_arg(a, void *), va_arg(a, void *), 
					   va_arg(a, void *), va_arg(a, void *), 
					   va_arg(a, void *), va_arg(a, void *), 
					   va_arg(a, void *));
	va_end(a);
	return result;
}

void sbInit(void) {
	%init();
}