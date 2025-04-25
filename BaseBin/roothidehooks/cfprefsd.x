#import <Foundation/Foundation.h>
#import <substrate.h>
#include <roothide.h>

static BOOL preferencePlistNeedsRedirection(NSString *plistPath) {
	if ([plistPath hasPrefix:@"/var/db/"] ||
		[plistPath hasPrefix:@"/private/var/preferences/"] ||
		[plistPath hasPrefix:@"/private/var/mobile/Containers/"]) {
		return NO;
	}

	NSString *plistName = plistPath.lastPathComponent;

	static NSSet *internalPlists;
	static NSSet *systemPrefixes;
	static NSSet *systemPlistNames;

	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		internalPlists = [NSSet setWithArray:@[
			@"com.apple.Terminal.plist"
		]];

		systemPrefixes = [NSSet setWithArray:@[
			@"com.apple.",
			@"group.com.apple.",
			@"systemgroup.com.apple."
		]];

		systemPlistNames = [NSSet setWithArray:@[
			@".GlobalPreferences.plist",
			@".GlobalPreferences_m.plist",
			@"bluetoothaudiod.plist",
			@"NetworkInterfaces.plist",
			@"OSThermalStatus.plist",
			@"preferences.plist",
			@"osanalyticshelper.plist",
			@"UserEventAgent.plist",
			@"wifid.plist",
			@"dprivacyd.plist",
			@"silhouette.plist",
			@"nfcd.plist",
			@"kNPProgressTrackerDomain.plist",
			@"siriknowledged.plist",
			@"UITextInputContextIdentifiers.plist",
			@"mobile_storage_proxy.plist",
			@"splashboardd.plist",
			@"mobile_installation_proxy.plist",
			@"languageassetd.plist",
			@"ptpcamerad.plist",
			@"com.google.gmp.measurement.monitor.plist",
			@"com.google.gmp.measurement.plist"
		]];
	});

	if ([internalPlists containsObject:plistName])
		return YES;

	for (NSString *prefix in systemPrefixes) {
		if ([plistName hasPrefix:prefix])
			return NO;
	}

	return ![systemPlistNames containsObject:plistName];
}

static BOOL (*orig_CFPrefsGetPathForTriplet)(CFStringRef, CFStringRef, BOOL, CFStringRef, UInt8*);
static BOOL new_CFPrefsGetPathForTriplet(CFStringRef bundleIdentifier, CFStringRef user, BOOL byHost, CFStringRef path, UInt8 *buffer) {
	BOOL orig = orig_CFPrefsGetPathForTriplet(bundleIdentifier, user, byHost, path, buffer);

	NSLog(@"CFPrefsGetPathForTriplet %@ %@ %d %@ : %d %s", bundleIdentifier, user, byHost, path, orig, orig ? (char *)buffer : "");

	if (orig && buffer) {
		NSString *origPath = [NSString stringWithUTF8String:(char *)buffer];
		if (preferencePlistNeedsRedirection(origPath)) {
			NSLog(@"Plist redirected to jbroot: %@", origPath);
			const char *newpath = jbroot(origPath.UTF8String);

			if (strlen(newpath) < 1024) {
				strcpy((char *)buffer, newpath);
				NSLog(@"CFPrefsGetPathForTriplet redirected to %s", buffer);
			}
		}
	}

	return orig;
}

void cfprefsdInit(void) {
	NSLog(@"cfprefsdInit...");

	MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
	void *CFPrefsGetPathForTriplet_ptr = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet");

	if (CFPrefsGetPathForTriplet_ptr) {
		MSHookFunction(CFPrefsGetPathForTriplet_ptr, (void *)&new_CFPrefsGetPathForTriplet, (void **)&orig_CFPrefsGetPathForTriplet);
		NSLog(@"Hooked __CFPrefsGetPathForTriplet %p => %p : %p", CFPrefsGetPathForTriplet_ptr, new_CFPrefsGetPathForTriplet, orig_CFPrefsGetPathForTriplet);
	}

	%init();
}