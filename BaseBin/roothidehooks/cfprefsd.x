#import <Foundation/Foundation.h>
#import <substrate.h>
#include <roothide.h>
#import "common.h"

#define MAX_BUFFER_SIZE	1024

static NSSet<NSString*>	*kAppleInternalPlists;
static NSSet<NSString*>	*kAdditionalSystemPlists;
static NSArray<NSString*>	*kBlacklistPrefixes;
static NSRegularExpression	*kPrefsPathRegex;

static void initStaticData(void) {
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		kAppleInternalPlists=[NSSet setWithObject:@"com.apple.Terminal.plist"];
		kAdditionalSystemPlists=[NSSet setWithArray:@[
			@".GlobalPreferences.plist",@".GlobalPreferences_m.plist",
			@"bluetoothaudiod.plist",@"NetworkInterfaces.plist",
			@"OSThermalStatus.plist",@"preferences.plist",
			@"osanalyticshelper.plist",@"UserEventAgent.plist",
			@"wifid.plist",@"dprivacyd.plist",@"silhouette.plist",
			@"nfcd.plist",@"kNPProgressTrackerDomain.plist",
			@"siriknowledged.plist",@"UITextInputContextIdentifiers.plist",
			@"mobile_storage_proxy.plist",@"splashboardd.plist",
			@"mobile_installation_proxy.plist",@"languageassetd.plist",
			@"ptpcamerad.plist",
			@"com.google.gmp.measurement.monitor.plist",
			@"com.google.gmp.measurement.plist"
		]];
		kBlacklistPrefixes=@[@"com.apple.",@"group.com.apple.",@"systemgroup.com.apple."];
		NSError *error=nil;
		kPrefsPathRegex=[NSRegularExpression regularExpressionWithPattern:@"^(/private)?/var/\\w+/Library/Preferences/" options:0 error:&error];
	});
}

static BOOL preferencePlistNeedsRedirection(NSString *plistPath) {
	initStaticData();
	if(![kPrefsPathRegex firstMatchInString:plistPath options:0 range:NSMakeRange(0,plistPath.length)]) return NO;
	NSString *name=plistPath.lastPathComponent;
	if([kAppleInternalPlists containsObject:name]) return YES;
	for(NSString *prefix in kBlacklistPrefixes) if([name hasPrefix:prefix]) return NO;
	return ![kAdditionalSystemPlists containsObject:name];
}

static BOOL (*orig_CFPrefsGetPathForTriplet)(CFStringRef,CFStringRef,BOOL,CFStringRef,UInt8*);
BOOL new_CFPrefsGetPathForTriplet(CFStringRef identifier,CFStringRef user,BOOL byHost,CFStringRef container,UInt8 *buffer) {
	BOOL result=orig_CFPrefsGetPathForTriplet(identifier,user,byHost,container,buffer);
	if(result&&buffer) {
		NSString *origPath=[NSString stringWithUTF8String:(char*)buffer];
		if(preferencePlistNeedsRedirection(origPath)) {
			if(!(gCurrentClientPid>0&&jbclient_blacklist_check_pid(gCurrentClientPid))) {
				const char *redirected=jbroot(origPath.UTF8String);
				if(strlen(redirected)<MAX_BUFFER_SIZE) strcpy((char*)buffer,redirected);
				else return NO;
			}
		}
	}
	return result;
}

static void* (*orig_CFPrefsDaemon_handleMessage)(id,xpc_object_t,xpc_connection_t,void*);
void* new_CFPrefsDaemon_handleMessage(id self,xpc_object_t message,xpc_connection_t connection,void *replyHandler) {
	gCurrentClientPid=xpc_connection_get_pid(connection);
	return orig_CFPrefsDaemon_handleMessage(self,message,connection,replyHandler);
}

__attribute__((constructor))
static void cfprefsdInit(void) {
	initStaticData();
	MSImageRef cfImage=MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
	void *sym1=MSFindSymbol(cfImage,"__CFPrefsGetPathForTriplet");
	if(sym1) MSHookFunction(sym1,(void*)&new_CFPrefsGetPathForTriplet,(void**)&orig_CFPrefsGetPathForTriplet);
	void *sym2=MSFindSymbol(cfImage,"-[CFPrefsDaemon handleMessage:fromPeer:replyHandler:]");
	if(sym2) MSHookFunction(sym2,(void*)&new_CFPrefsDaemon_handleMessage,(void**)&orig_CFPrefsDaemon_handleMessage);
	%init();
}