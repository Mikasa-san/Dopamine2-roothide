#import <Foundation/Foundation.h>
#import <spawn.h>
#include <roothide.h>
#include "common.h"

extern char **environ;

#pragma GCC diagnostic ignored "-Wobjc-method-access"
#pragma GCC diagnostic ignored "-Wunused-variable"

BOOL isJailbreakURLScheme(NSString *scheme) {
	__block BOOL blocked = NO;
	NSArray *apps = [[NSClassFromString(@"LSApplicationWorkspace") defaultWorkspace]
		applicationsAvailableForHandlingURLScheme:scheme];
	[apps enumerateObjectsUsingBlock:^(id app, NSUInteger idx, BOOL *stop) {
		NSURL *bundleURL = [app performSelector:@selector(bundleURL)];
		if (bundleURL && isJailbreakBundlePath(bundleURL.path.UTF8String)) {
			blocked = YES;
			*stop = YES;
		}
	}];
	return blocked;
}

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (NSArray *)applicationsAvailableForHandlingURLScheme:(NSString *)scheme;
@end

static const void *kBlockSchemeTagKey = &kBlockSchemeTagKey;

%hook _LSURLOverride
- (id)initWithOriginalURL:(NSURL *)url {
	NSNumber *tag = objc_getAssociatedObject(url, kBlockSchemeTagKey);
	if (tag.boolValue) return nil;
	return %orig;
}
%end

%hook _LSCanOpenURLManager
- (void *)getIsURL:(NSURL *)url alwaysCheckable:(BOOL *)pCheckable hasHandler:(BOOL *)pHasHandler {
	BOOL checkable = NO, hasHandler = NO;
	void *res = %orig(url, &checkable, &hasHandler);
	NSNumber *tag = objc_getAssociatedObject(url, kBlockSchemeTagKey);
	if (tag.boolValue) {
		checkable = hasHandler = NO;
	}
	if (pCheckable) *pCheckable = checkable;
	if (pHasHandler)  *pHasHandler  = hasHandler;
	return res;
}
%end

%hook LSApplicationWorkspace
- (BOOL)canOpenURL:(NSURL *)url publicSchemes:(BOOL)isPublic privateSchemes:(BOOL)isPrivate XPCConnection:(NSXPCConnection *)conn error:(NSError *)err {
	if (conn && jbclient_blacklist_check_pid(conn.processIdentifier) && isJailbreakURLScheme(url.scheme)) {
		objc_setAssociatedObject(url, kBlockSchemeTagKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
		return NO;
	}
	return %orig;
}
%end

%hook _LSQueryContext
- (NSMutableDictionary *)_resolveQueries:(NSMutableSet *)queries XPCConnection:(NSXPCConnection *)conn error:(NSError *)err {
	NSMutableDictionary *result = %orig;
	if (!conn || !jbclient_blacklist_check_pid(conn.processIdentifier)) return result;
	[result enumerateKeysAndObjectsUsingBlock:^(id key, NSMutableArray *plugins, BOOL *stopDict) {
		NSIndexSet *toRemove = [plugins indexesOfObjectsPassingTest:^BOOL(id plugin, NSUInteger idx, BOOL *stopInner) {
			id bundle = [plugin performSelector:@selector(containingBundle)];
			NSURL *url = [bundle performSelector:@selector(bundleURL)];
			return url && isJailbreakBundlePath(url.path.UTF8String);
		}];
		if (toRemove.count) {
			[plugins removeObjectsAtIndexes:toRemove];
			if ([key respondsToSelector:@selector(setValue:forKey:)]) {
				NSMutableArray *units = [[key valueForKey:@"_pluginUnits"] mutableCopy];
				[units removeObjectsAtIndexes:toRemove];
				[key setValue:units forKey:@"_pluginUnits"];
			}
		}
	}];
	return result;
}
%end

NSURL *(*orig_LSGetInboxURLForBundleIdentifier)(NSString *) = NULL;
NSURL *new_LSGetInboxURLForBundleIdentifier(NSString *bundleId) {
	NSURL *url = orig_LSGetInboxURLForBundleIdentifier(bundleId);
	if (![bundleId hasPrefix:@"com.apple."] &&
		[url.path hasPrefix:@"/var/mobile/Library/Application Support/Containers/"]) {
		url = [NSURL fileURLWithPath:jbroot(url.path)];
	}
	return url;
}

int (*orig_LSServer_RebuildApplicationDatabases)() = NULL;
int new_LSServer_RebuildApplicationDatabases() {
	int r = orig_LSServer_RebuildApplicationDatabases();
	if (access(jbroot("/.disable_auto_uicache"), F_OK)) {
		dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
			const char *const args[] = { jbroot("/usr/bin/uicache"), "-a", NULL };
			posix_spawn(NULL, args[0], NULL, NULL, (char *const *)args, environ);
		});
	}
	return r;
}

void lsdInit(void) {
	MSImageRef img = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
	void *sym = MSFindSymbol(img, "__LSGetInboxURLForBundleIdentifier");
	if (sym) MSHookFunction(sym, new_LSGetInboxURLForBundleIdentifier, (void **)&orig_LSGetInboxURLForBundleIdentifier);
	sym = MSFindSymbol(img, "__LSServer_RebuildApplicationDatabases");
	if (sym) MSHookFunction(sym, new_LSServer_RebuildApplicationDatabases, (void **)&orig_LSServer_RebuildApplicationDatabases);
	%init();
}
