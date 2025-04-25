//
//	DOUIManager.m
//	Dopamine
//
//	Created by tomt000 on 24/01/2024.
//

#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "NSString+Version.h"
#import <pthread.h>

@implementation DOUIManager

+ (id)sharedInstance
{
	static DOUIManager *sharedInstance = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sharedInstance = [[DOUIManager alloc] init];
	});
	return sharedInstance;
}

- (instancetype)init
{
	if (self = [super init]) {
		_preferenceManager = [DOPreferenceManager sharedManager];
		_logRecord         = [NSMutableArray new];
		_logLock           = [NSLock new];
	}
	return self;
}

- (NSArray *)availablePackageManagers
{
	NSString *path = [[NSBundle mainBundle] pathForResource:@"PkgManagers" ofType:@"plist"];
	return [NSArray arrayWithContentsOfFile:path];
}

- (NSArray *)enabledPackageManagerKeys
{
	NSArray       *enabledPkgManagers = [_preferenceManager preferenceValueForKey:@"enabledPkgManagers"] ?: @[];
	NSMutableArray *enabledKeys         = [NSMutableArray new];
	for (NSDictionary *obj in [self availablePackageManagers]) {
		NSString *key = obj[@"Key"];
		if ([enabledPkgManagers containsObject:key]) {
			[enabledKeys addObject:key];
		}
	}
	return enabledKeys;
}

- (NSArray *)enabledPackageManagers
{
	NSMutableArray *enabledPkgManagers = [NSMutableArray new];
	NSArray        *enabledKeys        = [self enabledPackageManagerKeys];
	for (NSDictionary *obj in [self availablePackageManagers]) {
		NSString *key = obj[@"Key"];
		if ([enabledKeys containsObject:key]) {
			[enabledPkgManagers addObject:obj];
		}
	}
	return enabledPkgManagers;
}

- (void)resetPackageManagers
{
	[_preferenceManager removePreferenceValueForKey:@"enabledPkgManagers"];
}

- (void)resetSettings
{
	[_preferenceManager removePreferenceValueForKey:@"verboseLogsEnabled"];
	[_preferenceManager removePreferenceValueForKey:@"tweakInjectionEnabled"];
	[self resetPackageManagers];
}

- (void)setPackageManager:(NSString *)key enabled:(BOOL)enabled
{
	NSMutableArray *pkgManagers = [self enabledPackageManagerKeys].mutableCopy;
	if (enabled) {
		if (![pkgManagers containsObject:key]) {
			[pkgManagers addObject:key];
		}
	} else {
		if ([pkgManagers containsObject:key]) {
			[pkgManagers removeObject:key];
		}
	}
	[_preferenceManager setPreferenceValue:pkgManagers forKey:@"enabledPkgManagers"];
}

- (BOOL)isDebug
{
	NSNumber *debug = [_preferenceManager preferenceValueForKey:@"verboseLogsEnabled"];
	return debug ? [debug boolValue] : NO;
}

- (BOOL)enableTweaks
{
	NSNumber *tweaks = [_preferenceManager preferenceValueForKey:@"tweakInjectionEnabled"];
	return tweaks ? [tweaks boolValue] : YES;
}

- (void)sendLog:(NSString *)log debug:(BOOL)debug
{
	if (!self.logView || !log) return;

	[_logLock lock];
	[self.logRecord addObject:log];

	BOOL isDebugView = [self.logView isKindOfClass:[DODebugLogView class]];
	if (debug && !isDebugView) {
		[_logLock unlock];
		return;
	}

	if ([self.logView respondsToSelector:@selector(showLog:)]) {
		[self.logView showLog:log];
	}

	[_logLock unlock];
}

- (void)shareLogRecordFromView:(UIView *)sourceView
{
	if (self.logRecord.count == 0) return;

	NSString *log = [self.logRecord componentsJoinedByString:@"\n"];
	UIActivityViewController *activityVC =
		[[UIActivityViewController alloc] initWithActivityItems:@[log] applicationActivities:nil];
	activityVC.popoverPresentationController.sourceView = sourceView;
	activityVC.popoverPresentationController.sourceRect = sourceView.bounds;
	[[UIApplication sharedApplication].keyWindow.rootViewController
		presentViewController:activityVC animated:YES completion:nil];
}

- (void)completeJailbreak
{
	if (!self.logView) return;
	[self.logView didComplete];
}

- (void)observeFileDescriptor:(int)fd withCallback:(void (^)(char *line))callbackBlock
{
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		int stdout_pipe[2], stdout_orig[2];
		if (pipe(stdout_pipe) != 0 || pipe(stdout_orig) != 0) return;

		dup2(fd, stdout_orig[1]);
		close(stdout_orig[0]);

		dup2(stdout_pipe[1], fd);
		close(stdout_pipe[1]);

		char    cur        = 0;
		char    line[1024];
		int     line_index = 0;
		ssize_t bytes_read;

		while ((bytes_read = read(stdout_pipe[0], &cur, sizeof(cur))) > 0) {
			@autoreleasepool {
				write(stdout_orig[1], &cur, bytes_read);

				if (cur == '\n') {
					line[line_index] = '\0';
					callbackBlock(line);
					line_index = 0;
				} else if (line_index < (int)sizeof(line) - 1) {
					line[line_index++] = cur;
				}
			}
		}
		close(stdout_pipe[0]);
	});
}

- (void)startLogCapture
{
	[self observeFileDescriptor:STDOUT_FILENO withCallback:^(char *line) {
		NSString *str = [NSString stringWithUTF8String:line];
		[self sendLog:str debug:YES];
	}];
	[self observeFileDescriptor:STDERR_FILENO withCallback:^(char *line) {
		NSString *str = [NSString stringWithUTF8String:line];
		[self sendLog:str debug:YES];
	}];
}

- (NSString *)localizedStringForKey:(NSString *)key
{
	NSString *candidate = NSLocalizedString(key, nil);
	if ([candidate isEqualToString:key]) {
		if (!_fallbackLocalizations) {
			NSString *path = [[NSBundle mainBundle].bundlePath
							  stringByAppendingPathComponent:@"en.lproj/Localizable.strings"];
			_fallbackLocalizations = [NSDictionary dictionaryWithContentsOfFile:path];
		}
		candidate = _fallbackLocalizations[key] ?: key;
	}
	return candidate;
}

@end

NSString *DOLocalizedString(NSString *key)
{
	return [[DOUIManager sharedInstance] localizedStringForKey:key];
}
