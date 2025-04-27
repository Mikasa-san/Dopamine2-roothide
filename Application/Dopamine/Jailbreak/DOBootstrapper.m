#import "DOBootstrapper.h"
#import "DOEnvironmentManager.h"
#import "DOUIManager.h"
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import "zstd.h"
#import <sys/mount.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import "NSString+Version.h"

#define LIBKRW_DOPAMINE_BUNDLED_VERSION @"1.1.4"
#define LIBROOT_DOPAMINE_BUNDLED_VERSION @"1.0.1"
#define BASEBIN_LINK_BUNDLED_VERSION @"1.0.0"

static NSDictionary *gBundledPackages = @{
	@"libkrw0-dopamine" : LIBKRW_DOPAMINE_BUNDLED_VERSION,
	@"libroot-dopamine" : LIBROOT_DOPAMINE_BUNDLED_VERSION,
	@"dopamine-basebin-link" : BASEBIN_LINK_BUNDLED_VERSION,
};

struct hfs_mount_args {
	char	*fspec;
	uid_t	hfs_uid;		
	gid_t	hfs_gid;		
	mode_t	hfs_mask;		
	uint32_t hfs_encoding;		
	struct	timezone hfs_timezone;	
	int		flags;			
	int	 journal_tbuffer_size;   
	int		journal_flags;		  
	int		journal_disable;		
};

NSString *const bootstrapErrorDomain = @"BootstrapErrorDomain";
typedef NS_ENUM(NSInteger, JBErrorCode) {
	BootstrapErrorCodeFailedToGetURL			= -1,
	BootstrapErrorCodeFailedToDownload		  = -2,
	BootstrapErrorCodeFailedDecompressing	   = -3,
	BootstrapErrorCodeFailedExtracting		  = -4,
	BootstrapErrorCodeFailedRemount			 = -5,
	BootstrapErrorCodeFailedFinalising		  = -6,
	BootstrapErrorCodeFailedReplacing		   = -7,
};

#define BUFFER_SIZE 8192

@implementation DOBootstrapper

- (instancetype)init
{
	self = [super init];
	if (self) {

	}
	return self;
}

- (NSError *)decompressZstd:(NSString *)zstdPath toTar:(NSString *)tarPath
{

	FILE *input_file = fopen(zstdPath.fileSystemRepresentation, "rb");
	if (input_file == NULL) {
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to open input file %@: %s", zstdPath, strerror(errno)]}];
	}

	FILE *output_file = fopen(tarPath.fileSystemRepresentation, "wb");
	if (output_file == NULL) {
		fclose(input_file);
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to open output file %@: %s", tarPath, strerror(errno)]}];
	}

	ZSTD_DCtx *dctx = ZSTD_createDCtx();
	if (dctx == NULL) {
		fclose(input_file);
		fclose(output_file);
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : @"Failed to create ZSTD decompression context"}];
	}

	uint8_t *input_buffer = (uint8_t *) malloc(BUFFER_SIZE);
	if (input_buffer == NULL) {
		ZSTD_freeDCtx(dctx);
		fclose(input_file);
		fclose(output_file);
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : @"Failed to allocate input buffer"}];
	}

	uint8_t *output_buffer = (uint8_t *) malloc(BUFFER_SIZE);
	if (output_buffer == NULL) {
		free(input_buffer);
		ZSTD_freeDCtx(dctx);
		fclose(input_file);
		fclose(output_file);
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : @"Failed to allocate output buffer"}];
	}

	ZSTD_inBuffer in = {0};
	ZSTD_outBuffer out = {0};
	ZSTD_DStream *dstream = ZSTD_createDStream();
	if (dstream == NULL) {
		free(output_buffer);
		free(input_buffer);
		ZSTD_freeDCtx(dctx);
		fclose(input_file);
		fclose(output_file);
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : @"Failed to create ZSTD decompression stream"}];
	}

	size_t ret = ZSTD_initDStream(dstream);
	if (ZSTD_isError(ret)) {
		ZSTD_freeDStream(dstream);
		free(output_buffer);
		free(input_buffer);
		ZSTD_freeDCtx(dctx);
		fclose(input_file);
		fclose(output_file);
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to initialize ZSTD decompression stream: %s", ZSTD_getErrorName(ret)]}];
	}

	size_t total_bytes_read = 0;
	size_t total_bytes_written = 0;
	size_t bytes_read;
	size_t bytes_written;
	while (1) {

		bytes_read = fread(input_buffer, 1, BUFFER_SIZE, input_file);
		if (bytes_read == 0) {
			if (feof(input_file)) {

				break;
			} else {
				ZSTD_freeDStream(dstream);
				free(output_buffer);
				free(input_buffer);
				ZSTD_freeDCtx(dctx);
				fclose(input_file);
				fclose(output_file);
				return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to read input file: %s", strerror(errno)]}];
			}
		}

		in.src = input_buffer;
		in.size = bytes_read;
		in.pos = 0;

		while (in.pos < in.size) {

			out.dst = output_buffer;
			out.size = BUFFER_SIZE;
			out.pos = 0;

			ret = ZSTD_decompressStream(dstream, &out, &in);
			if (ZSTD_isError(ret)) {
				ZSTD_freeDStream(dstream);
				free(output_buffer);
				free(input_buffer);
				ZSTD_freeDCtx(dctx);
				fclose(input_file);
				fclose(output_file);
				return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to decompress input data: %s", ZSTD_getErrorName(ret)]}];
			}

			bytes_written = fwrite(output_buffer, 1, out.pos, output_file);
			if (bytes_written != out.pos) {
				ZSTD_freeDStream(dstream);
				free(output_buffer);
				free(input_buffer);
				ZSTD_freeDCtx(dctx);
				fclose(input_file);
				fclose(output_file);
				return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to write output file: %s", strerror(errno)]}];
			}

			total_bytes_written += bytes_written;
		}

		total_bytes_read += bytes_read;
	}

	ZSTD_freeDStream(dstream);
	free(output_buffer);
	free(input_buffer);
	ZSTD_freeDCtx(dctx);
	fclose(input_file);
	fclose(output_file);

	return nil;
}

- (NSError *)extractTar:(NSString *)tarPath toPath:(NSString *)destinationPath
{
	int r = libarchive_unarchive(tarPath.fileSystemRepresentation, destinationPath.fileSystemRepresentation);
	if (r != 0) {
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"libarchive returned %d", r]}];
	}
	return nil;
}

- (BOOL)deleteSymlinkAtPath:(NSString *)path error:(NSError **)error
{
	NSDictionary<NSFileAttributeKey, id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:error];
	if (!attributes) return YES;
	if (attributes[NSFileType] == NSFileTypeSymbolicLink) {
		return [[NSFileManager defaultManager] removeItemAtPath:path error:error];
	}
	return NO;
}

- (BOOL)fileOrSymlinkExistsAtPath:(NSString *)path
{
	if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return YES;

	NSDictionary<NSFileAttributeKey, id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
	if (attributes) {
		if (attributes[NSFileType] == NSFileTypeSymbolicLink) {
			return YES;
		}
	}

	return NO;
}

- (NSError *)createSymlinkAtPath:(NSString *)path toPath:(NSString *)destinationPath createIntermediateDirectories:(BOOL)createIntermediate
{
	NSError *error;
	NSString *parentPath = [path stringByDeletingLastPathComponent];
	if (![[NSFileManager defaultManager] fileExistsAtPath:parentPath]) {
		if (!createIntermediate) return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed create %@->%@ symlink: Parent dir does not exists", path, destinationPath]}];
		if (![[NSFileManager defaultManager] createDirectoryAtPath:parentPath withIntermediateDirectories:YES attributes:nil error:&error]) return error;
	}

	[[NSFileManager defaultManager] createSymbolicLinkAtPath:path withDestinationPath:destinationPath error:&error];
	return error;
}

- (void)patchBasebinDaemonPlist:(NSString *)plistPath
{
	NSMutableDictionary *plistDict = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
	if (plistDict) {
		bool madeChanges = NO;
		NSMutableArray *programArguments = ((NSArray *)plistDict[@"ProgramArguments"]).mutableCopy;
		for (NSString *argument in [programArguments reverseObjectEnumerator]) {
			if ([argument containsString:@"@JBROOT@"]) {
				programArguments[[programArguments indexOfObject:argument]] = [argument stringByReplacingOccurrencesOfString:@"@JBROOT@" withString:JBROOT_PATH(@"/")];
				madeChanges = YES;
			}
		}
		if (madeChanges) {
			plistDict[@"ProgramArguments"] = programArguments.copy;
			[plistDict writeToFile:plistPath atomically:NO];
		}
	}
}

- (void)patchBasebinDaemonPlists
{
	NSURL *basebinDaemonsURL = [NSURL fileURLWithPath:JBROOT_PATH(@"/basebin/LaunchDaemons")];
	for (NSURL *basebinDaemonURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:basebinDaemonsURL includingPropertiesForKeys:nil options:0 error:nil]) {
		[self patchBasebinDaemonPlist:basebinDaemonURL.path];
	}
}

- (NSString *)bootstrapVersion
{
	uint64_t cfver = (((uint64_t)kCFCoreFoundationVersionNumber / 100) * 100);
	if (cfver >= 2000) {
		return nil;
	}
	return [NSString stringWithFormat:@"%llu", cfver];
}

- (NSURL *)bootstrapURL
{
	return [NSURL URLWithString:[NSString stringWithFormat:@"https://apt.procurs.us/bootstraps/%@/bootstrap-ssh-iphoneos-arm64.tar.zst", [self bootstrapVersion]]];
}

#if 0
- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion
{
	[[DOUIManager sharedInstance] sendLog:@"Updating BaseBin" debug:NO];

	NSError *error = [self ensurePrivatePrebootIsWritable];
	if (error) {
		completion(error);
		return;
	}

	[self fixupPathPermissions];

	if (![self deleteSymlinkAtPath:@"/var/jb" error:&error]) {
		if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
			if (![[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:&error]) {
				completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb directory failed with error: %@", error]}]);
				return;
			}
		}
		else {
			completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb symlink failed with error: %@", error]}]);
			return;
		}
	}

	if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/.keep_symlinks"]) {
		NSArray *xinaLeftoverSymlinks = @[
			@"/var/alternatives",
			@"/var/ap",
			@"/var/apt",
			@"/var/bin",
			@"/var/bzip2",
			@"/var/cache",
			@"/var/dpkg",
			@"/var/etc",
			@"/var/gzip",
			@"/var/lib",
			@"/var/Lib",
			@"/var/libexec",
			@"/var/Library",
			@"/var/LIY",
			@"/var/Liy",
			@"/var/local",
			@"/var/newuser",
			@"/var/profile",
			@"/var/sbin",
			@"/var/suid_profile",
			@"/var/sh",
			@"/var/sy",
			@"/var/share",
			@"/var/ssh",
			@"/var/sudo_logsrvd.conf",
			@"/var/suid_profile",
			@"/var/sy",
			@"/var/usr",
			@"/var/zlogin",
			@"/var/zlogout",
			@"/var/zprofile",
			@"/var/zshenv",
			@"/var/zshrc",
			@"/var/log/dpkg",
			@"/var/log/apt",
		];
		NSArray *xinaLeftoverFiles = @[
			@"/var/lib",
			@"/var/master.passwd"
		];

		for (NSString *xinaLeftoverSymlink in xinaLeftoverSymlinks) {
			[self deleteSymlinkAtPath:xinaLeftoverSymlink error:nil];
		}

		for (NSString *xinaLeftoverFile in xinaLeftoverFiles) {
			if ([[NSFileManager defaultManager] fileExistsAtPath:xinaLeftoverFile]) {
				[[NSFileManager defaultManager] removeItemAtPath:xinaLeftoverFile error:nil];
			}
		}
	}

	NSString *basebinPath = JBROOT_PATH(@"/basebin");
	NSString *installedPath = JBROOT_PATH(@"/.installed_dopamine");
	error = [self createSymlinkAtPath:@"/var/jb" toPath:JBROOT_PATH(@"/") createIntermediateDirectories:YES];
	if (error) {
		completion(error);
		return;
	}

	if ([[NSFileManager defaultManager] fileExistsAtPath:basebinPath]) {
		if (![[NSFileManager defaultManager] removeItemAtPath:basebinPath error:&error]) {
			completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed deleting existing basebin file with error: %@", error.localizedDescription]}]);
			return;
		}
	}
	error = [self extractTar:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"] toPath:JBROOT_PATH(@"/")];
	if (error) {
		completion(error);
		return;
	}
	[self patchBasebinDaemonPlists];
	[[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/basebin/basebin.tc") error:nil];

	void (^bootstrapFinishedCompletion)(NSError *) = ^(NSError *error){
		if (error) {
			completion(error);
			return;
		}

		NSString *defaultSources = @"Types: deb\n"
			@"URIs: https://repo.chariz.com/\n"
			@"Suites: ./\n"
			@"Components:\n"
			@"\n"
			@"Types: deb\n"
			@"URIs: https://havoc.app/\n"
			@"Suites: ./\n"
			@"Components:\n"
			@"\n"
			@"Types: deb\n"
			@"URIs: http://apt.thebigboss.org/repofiles/cydia/\n"
			@"Suites: stable\n"
			@"Components: main\n"
			@"\n"
			@"Types: deb\n"
			@"URIs: https://ellekit.space/\n"
			@"Suites: ./\n"
			@"Components:\n";
		[defaultSources writeToFile:JBROOT_PATH(@"/etc/apt/sources.list.d/default.sources") atomically:NO encoding:NSUTF8StringEncoding error:nil];

		NSString *mobilePreferencesPath = JBROOT_PATH(@"/var/mobile/Library/Preferences");
		if (![[NSFileManager defaultManager] fileExistsAtPath:mobilePreferencesPath]) {
			NSDictionary<NSFileAttributeKey, id> *attributes = @{
				NSFilePosixPermissions : @0755,
				NSFileOwnerAccountID : @501,
				NSFileGroupOwnerAccountID : @501,
			};
			[[NSFileManager defaultManager] createDirectoryAtPath:mobilePreferencesPath withIntermediateDirectories:YES attributes:attributes error:nil];
		}

		JBFixMobilePermissions();

		completion(nil);
	};

	BOOL needsBootstrap = ![[NSFileManager defaultManager] fileExistsAtPath:installedPath];
	if (needsBootstrap) {

		for (NSURL *subItemURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:JBROOT_PATH(@"/")] includingPropertiesForKeys:nil options:0 error:nil]) {
			if (![subItemURL.lastPathComponent isEqualToString:@"basebin"]) {
				[[NSFileManager defaultManager] removeItemAtURL:subItemURL error:nil];
			}
		}

		[[DOUIManager sharedInstance] sendLog:@"Extracting Bootstrap" debug:NO];

		NSString *bootstrapZstdPath = [NSString stringWithFormat:@"%@/bootstrap_%@.tar.zst", [NSBundle mainBundle].bundlePath, [self bootstrapVersion]];
		[self extractBootstrap:bootstrapZstdPath withCompletion:bootstrapFinishedCompletion];

	}
	else {
		bootstrapFinishedCompletion(nil);
	}
}
#endif

- (int)installPackage:(NSString *)packagePath
{
	if (getuid() == 0) {
		return exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-i", packagePath.fileSystemRepresentation, NULL);
	}
	else {

		exec_cmd(JBROOT_PATH("/basebin/jbctl"), "internal", "install_pkg", packagePath.fileSystemRepresentation, NULL);
		return 0;
	}
}

- (int)uninstallPackageWithIdentifier:(NSString *)identifier
{
	return exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-r", identifier.UTF8String, NULL);
}

- (NSString *)installedVersionForPackageWithIdentifier:(NSString *)identifier
{
	NSString *dpkgStatus = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/var/lib/dpkg/status") encoding:NSUTF8StringEncoding error:nil];
	NSString *packageStartLine = [NSString stringWithFormat:@"Package: %@", identifier];

	NSArray *packageInfos = [dpkgStatus componentsSeparatedByString:@"\n\n"];
	for (NSString *packageInfo in packageInfos) {
		if ([packageInfo hasPrefix:packageStartLine]) {
			__block NSString *version = nil;
			[packageInfo enumerateLinesUsingBlock:^(NSString * _Nonnull line, BOOL * _Nonnull stop) {
				if ([line hasPrefix:@"Version: "]) {
					version = [line substringFromIndex:9];
				}
			}];
			return version;
		}
	}
	return nil;
}

- (NSError *)installPackageManagers
{
	NSArray *enabledPackageManagers = [[DOUIManager sharedInstance] enabledPackageManagers];
	for (NSDictionary *packageManagerDict in enabledPackageManagers) {
		NSString *path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:packageManagerDict[@"Package"]];
		NSString *name = packageManagerDict[@"Display Name"];
		int r = [self installPackage:path];
		if (r != 0) {
			return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install %@: %d\n", name, r]}];
		}
	}
	return nil;
}

- (BOOL)shouldInstallPackage:(NSString *)identifier
{
	NSString *bundledVersion = gBundledPackages[identifier];
	if (!bundledVersion) return NO;

	NSString *installedVersion = [self installedVersionForPackageWithIdentifier:identifier];
	if (!installedVersion) return YES;

	return [installedVersion numericalVersionRepresentation] < [bundledVersion numericalVersionRepresentation];
}

- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)downloadTask didWriteData:(int64_t)bytesWritten totalBytesWritten:(int64_t)totalBytesWritten totalBytesExpectedToWrite:(int64_t)totalBytesExpectedToWrite
{
	if (downloadTask == _bootstrapDownloadTask) {
		NSString *sizeString = [NSByteCountFormatter stringFromByteCount:totalBytesWritten countStyle:NSByteCountFormatterCountStyleFile];
		NSString *writtenBytesString = [NSByteCountFormatter stringFromByteCount:totalBytesExpectedToWrite countStyle:NSByteCountFormatterCountStyleFile];

		[[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Downloading Bootstrap (%@/%@)", sizeString, writtenBytesString] debug:NO update:YES];
	}
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
	_downloadCompletionBlock(nil, error);
}

- (void)URLSession:(nonnull NSURLSession *)session downloadTask:(nonnull NSURLSessionDownloadTask *)downloadTask didFinishDownloadingToURL:(nonnull NSURL *)location
{
	_downloadCompletionBlock(location, nil);
}

@end

uint64_t jbrand_new();
uint64_t jbrand_current();
int is_jbroot_name(char* name);
NSString* find_jbroot(BOOL force);

NSString* jbrootPrefix(NSString *path);
NSString* rootfsPrefix(NSString* path);

@implementation DOBootstrapper(roothide)

uint64_t jbrand_new()
{
	uint64_t value = ((uint64_t)arc4random()) | ((uint64_t)arc4random())<<32;
	uint8_t check = value>>8 ^ value >> 16 ^ value>>24 ^ value>>32 ^ value>>40 ^ value>>48 ^ value>>56;
	return (value & ~0xFF) | check;
}

int is_jbrand_value(uint64_t value)
{
   uint8_t check = value>>8 ^ value >> 16 ^ value>>24 ^ value>>32 ^ value>>40 ^ value>>48 ^ value>>56;
   return check == (uint8_t)value;
}

#define JB_ROOT_PREFIX ".jbroot-"
#define JB_RAND_LENGTH  (sizeof(uint64_t)*sizeof(char)*2)

int is_jbroot_name(char* name)
{
	if(strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
		return 0;

	if(strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
		return 0;

	char* endp=NULL;
	uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
	if(!endp || *endp!='\0')
		return 0;

	if(!is_jbrand_value(value))
		return 0;

	return 1;
}

uint64_t resolve_jbrand_value(const char* name)
{
	if(strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
		return 0;

	if(strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
		return 0;

	char* endp=NULL;
	uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
	if(!endp || *endp!='\0')
		return 0;

	if(!is_jbrand_value(value))
		return 0;

	return value;
}

NSString* find_jbroot(BOOL force)
{
	static NSString* cached_jbroot = nil;
	if(!force && cached_jbroot) {
		return cached_jbroot;
	}
	@synchronized(@"find_jbroot_lock")
	{

		NSString * jbroot = nil;
		NSArray *subItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/Application/" error:nil];
		for (NSString *subItem in subItems) {
			if (is_jbroot_name(subItem.UTF8String))
			{
				NSString* path = [@"/var/containers/Bundle/Application/" stringByAppendingPathComponent:subItem];
				jbroot = path;
				break;
			}
		}
		cached_jbroot = jbroot;
	}
	return cached_jbroot;
}

uint64_t jbrand_current()
{
	NSString* jbroot = find_jbroot(NO);
	assert(jbroot != NULL);
	return resolve_jbrand_value([jbroot lastPathComponent].UTF8String);
}

NSString* jbrootPrefix(NSString *path)
{
	if(!path || path.UTF8String[0]!='/') {
		return path;
	}
	NSString* jbroot = find_jbroot(NO);
	assert(jbroot != NULL); 
	return [jbroot stringByAppendingPathComponent:path];
}

NSString* rootfsPrefix(NSString* path)
{
	if(!path || path.UTF8String[0]!='/') {
		return path;
	}
	return [@"/rootfs/" stringByAppendingPathComponent:path];
}

#define DOPAMINE_INSTALL_VERSION	2

#define DEFAULT_SOURCES "\
Types: deb\n\
URIs: https:
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: https:
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: https:
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: http:
Suites: stable\n\
Components: main\n\
\n\
Types: deb\n\
URIs: https:
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: https:
Suites: iphoneos-arm64e/%d\n\
Components: main\n\
"

#define ALT_SOURCES "\
Types: deb\n\
URIs: https:
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: https:
Suites: iphoneos-arm64e/%d\n\
Components: main\n\
"

#define ZEBRA_SOURCES "\
# Zebra Sources List\n\
deb https:
deb https:
deb https:
deb https:
deb https:
deb https:
\n\
"

int getCFMajorVersion(void)
{
	return ((int)kCFCoreFoundationVersionNumber / 100) * 100;
}

#define STRAPLOG(...)   [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@__VA_ARGS__] debug:YES];
#define ASSERT(...)	 do{if(!(__VA_ARGS__)) {completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"ABORT: %s (%d): %s", __FILE_NAME__, __LINE__, #__VA_ARGS__]}]);return -1;}} while(0)

-(int) buildPackageSources:(void (^)(NSError *))completion
{
	NSFileManager* fm = NSFileManager.defaultManager;

	ASSERT([[NSString stringWithFormat:@(DEFAULT_SOURCES), getCFMajorVersion()] writeToFile:jbrootPrefix(@"/etc/apt/sources.list.d/default.sources") atomically:YES encoding:NSUTF8StringEncoding error:nil]);

	if([NSLocale.currentLocale.countryCode isEqualToString:@"CN"]) {
		ASSERT([[NSString stringWithFormat:@(ALT_SOURCES), getCFMajorVersion()] writeToFile:jbrootPrefix(@"/etc/apt/sources.list.d/sileo.sources") atomically:YES encoding:NSUTF8StringEncoding error:nil]);
	}

	if(![fm fileExistsAtPath:jbrootPrefix(@"/var/mobile/Library/Application Support/xyz.willy.Zebra")])
	{
		NSDictionary* attr = @{NSFilePosixPermissions:@(0755), NSFileOwnerAccountID:@(501), NSFileGroupOwnerAccountID:@(501)};
		ASSERT([fm createDirectoryAtPath:jbrootPrefix(@"/var/mobile/Library/Application Support/xyz.willy.Zebra") withIntermediateDirectories:YES attributes:attr error:nil]);
	}

	ASSERT([[NSString stringWithFormat:@(ZEBRA_SOURCES), getCFMajorVersion()] writeToFile:jbrootPrefix(@"/var/mobile/Library/Application Support/xyz.willy.Zebra/sources.list") atomically:YES encoding:NSUTF8StringEncoding error:nil]);

	return 0;
}

-(int) InstallBootstrap:(NSString*)installPath WithCompletion:(void (^)(NSError *))completion
{
	[[DOUIManager sharedInstance] sendLog:@"Extracting Bootstrap" debug:NO];

	NSFileManager* fm = NSFileManager.defaultManager;

	NSString* jbroot_path = installPath;

	ASSERT(mkdir(jbroot_path.fileSystemRepresentation, 0755) == 0);
	ASSERT(chown(jbroot_path.fileSystemRepresentation, 0, 0) == 0);

	find_jbroot(YES); 

	NSString* bootstrapZstFile = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:
								  [NSString stringWithFormat:@"bootstrap_%d.tar.zst", getCFMajorVersion()]];

	ASSERT([fm fileExistsAtPath:bootstrapZstFile]);

	NSString* bootstrapTarFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"bootstrap.tar"];
	if([fm fileExistsAtPath:bootstrapTarFile])
		ASSERT([fm removeItemAtPath:bootstrapTarFile error:nil]);

	NSError* error = [self decompressZstd:bootstrapZstFile toTar:bootstrapTarFile];
	if(error) {
		completion(error);
		return -1;
	}

	NSError* decompressionError = [self extractTar:bootstrapTarFile toPath:jbroot_path];
	if (decompressionError) {
		completion(decompressionError);
		return -1;
	}

	NSString* jbroot_secondary = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX", jbrand_current()];
	ASSERT(mkdir(jbroot_secondary.fileSystemRepresentation, 0755) == 0);
	ASSERT(chown(jbroot_secondary.fileSystemRepresentation, 0, 0) == 0);

	ASSERT([fm moveItemAtPath:jbrootPrefix(@"/var") toPath:[jbroot_secondary stringByAppendingPathComponent:@"/var"] error:nil]);
	ASSERT([fm createSymbolicLinkAtPath:jbrootPrefix(@"/var") withDestinationPath:@"private/var" error:nil]);

	ASSERT([fm removeItemAtPath:jbrootPrefix(@"/private/var") error:nil]);
	ASSERT([fm createSymbolicLinkAtPath:jbrootPrefix(@"/private/var") withDestinationPath:[jbroot_secondary stringByAppendingPathComponent:@"/var"] error:nil]);

	ASSERT([fm removeItemAtPath:[jbroot_secondary stringByAppendingPathComponent:@"/var/tmp"] error:nil]);
	ASSERT([fm moveItemAtPath:jbrootPrefix(@"/tmp") toPath:[jbroot_secondary stringByAppendingPathComponent:@"/var/tmp"] error:nil]);
	ASSERT([fm createSymbolicLinkAtPath:jbrootPrefix(@"/tmp") withDestinationPath:@"var/tmp" error:nil]);

	ASSERT([fm createSymbolicLinkAtPath:[jbroot_secondary stringByAppendingPathComponent:@".jbroot"]
					withDestinationPath:jbroot_path error:nil]);

	if(![fm fileExistsAtPath:jbrootPrefix(@"/var/mobile/Library/Preferences")])
	{
		NSDictionary* attr = @{NSFilePosixPermissions:@(0755), NSFileOwnerAccountID:@(501), NSFileGroupOwnerAccountID:@(501)};
		ASSERT([fm createDirectoryAtPath:jbrootPrefix(@"/var/mobile/Library/Preferences") withIntermediateDirectories:YES attributes:attr error:nil]);
	}

	if([self buildPackageSources:completion] != 0) {
		return -1;
	}

	STRAPLOG("Status: Bootstrap Installed");

	return 0;
}

-(int) ReRandomizeBootstrap:(void (^)(NSError *))completion
{
	[[DOUIManager sharedInstance] sendLog:@"ReRandomizing Bootstrap" debug:NO];

	uint64_t new_jbrand = jbrand_new();
	uint64_t prev_jbrand = jbrand_current();

	NSFileManager* fm = NSFileManager.defaultManager;

	ASSERT( [fm moveItemAtPath:[NSString stringWithFormat:@"/var/containers/Bundle/Application/.jbroot-%016llX", prev_jbrand]
						toPath:[NSString stringWithFormat:@"/var/containers/Bundle/Application/.jbroot-%016llX", new_jbrand] error:nil] );

	ASSERT([fm moveItemAtPath:[NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX", prev_jbrand]
					   toPath:[NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX", new_jbrand] error:nil]);

	NSString* jbroot_path = [NSString stringWithFormat:@"/var/containers/Bundle/Application/.jbroot-%016llX", new_jbrand];
	NSString* jbroot_secondary = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX", new_jbrand];

	ASSERT([fm removeItemAtPath:[jbroot_path stringByAppendingPathComponent:@"/private/var"] error:nil]);
	ASSERT([fm createSymbolicLinkAtPath:[jbroot_path stringByAppendingPathComponent:@"/private/var"]
					withDestinationPath:[jbroot_secondary stringByAppendingPathComponent:@"/var"] error:nil]);

	ASSERT([fm removeItemAtPath:[jbroot_secondary stringByAppendingPathComponent:@".jbroot"] error:nil]);
	ASSERT([fm createSymbolicLinkAtPath:[jbroot_secondary stringByAppendingPathComponent:@".jbroot"]
					withDestinationPath:jbroot_path error:nil]);

	find_jbroot(YES); 

	return 0;
}

-(int) doBootstrap:(void (^)(NSError *))completion {

	NSFileManager* fm = NSFileManager.defaultManager;

	int installedCount=0;
	NSString* dirpath = @"/var/containers/Bundle/Application/";
	NSArray *subItems = [fm contentsOfDirectoryAtPath:dirpath error:nil];
	for (NSString *subItem in subItems)
	{
		if (!is_jbroot_name(subItem.UTF8String)) continue;

		NSString* jbroot_path = [dirpath stringByAppendingPathComponent:subItem];

		if([fm fileExistsAtPath:[jbroot_path stringByAppendingPathComponent:@"/.bootstrapped"]]
		   || [fm fileExistsAtPath:[jbroot_path stringByAppendingPathComponent:@"/.thebootstrapped"]]) {
			completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : @"\n\nYour device has been bootstrapped through the Bootstrap app, please disable tweak for apps in AppList and UnBootstrap before jailbreaking.\n\n\n"}]);
			return -1;
		}

		if([fm fileExistsAtPath:[jbroot_path stringByAppendingPathComponent:@"/.installed_dopamine"]]) {
			installedCount++;
			continue;
		}

		STRAPLOG("remove unknown/unfinished jbroot %@", subItem);

		NSString* jbroot_secondary = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/%@", subItem];
		if([fm fileExistsAtPath:jbroot_secondary]) {
			ASSERT([fm removeItemAtPath:jbroot_secondary error:nil]);
		}

		ASSERT([fm removeItemAtPath:jbroot_path error:nil]);
	}

	if(installedCount > 1) {
		completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : @"\n\nThere are multi jbroot in /var/containers/Bundle/Applicaton/\n\n\n"}]);
		return -1;
	}

	NSString* jbroot_path = find_jbroot(YES);

	if(!jbroot_path) {
		STRAPLOG("device is not strapped...");

		jbroot_path = [NSString stringWithFormat:@"/var/containers/Bundle/Application/.jbroot-%016llX", jbrand_new()];

		STRAPLOG("bootstrap @ %@", jbroot_path);

		if([self InstallBootstrap:jbroot_path WithCompletion:completion] != 0) {
			return -1;
		}

	} else {
		STRAPLOG("device is strapped: %@", jbroot_path);

		ASSERT([fm fileExistsAtPath:jbrootPrefix(@"/.installed_dopamine")]);

		STRAPLOG("Status: Rerandomize jbroot");

		if([self ReRandomizeBootstrap:completion] != 0) {
			return -1;
		}
	}

	STRAPLOG("Status: Bootstrap Successful");

	return 0;
}

- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion
{

	NSError *error=nil;
	if (![self deleteSymlinkAtPath:@"/var/jb" error:&error]) {
		if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
			if (![[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:&error]) {
				completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb directory failed with error: %@", error]}]);
				return;
			}
		}
		else {
			completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb symlink failed with error: %@", error]}]);
			return;
		}
	}

		NSArray *xinaLeftoverSymlinks = @[
			@"/var/alternatives",
			@"/var/ap",
			@"/var/apt",
			@"/var/bin",
			@"/var/bzip2",
			@"/var/cache",
			@"/var/dpkg",
			@"/var/etc",
			@"/var/gzip",
			@"/var/lib",
			@"/var/Lib",
			@"/var/libexec",
			@"/var/Library",
			@"/var/LIY",
			@"/var/Liy",
			@"/var/local",
			@"/var/newuser",
			@"/var/profile",
			@"/var/sbin",
			@"/var/suid_profile",
			@"/var/sh",
			@"/var/sy",
			@"/var/share",
			@"/var/ssh",
			@"/var/sudo_logsrvd.conf",
			@"/var/suid_profile",
			@"/var/sy",
			@"/var/usr",
			@"/var/zlogin",
			@"/var/zlogout",
			@"/var/zprofile",
			@"/var/zshenv",
			@"/var/zshrc",
			@"/var/log/dpkg",
			@"/var/log/apt",
		];
		NSArray *xinaLeftoverFiles = @[
			@"/var/lib",
			@"/var/master.passwd",
			@"/var/.keep_symlinks",
		];

		for (NSString *xinaLeftoverSymlink in xinaLeftoverSymlinks) {
			[self deleteSymlinkAtPath:xinaLeftoverSymlink error:nil];
		}

		for (NSString *xinaLeftoverFile in xinaLeftoverFiles) {
			if ([[NSFileManager defaultManager] fileExistsAtPath:xinaLeftoverFile]) {
				[[NSFileManager defaultManager] removeItemAtPath:xinaLeftoverFile error:nil];
			}
		}

	if([self doBootstrap:completion] == 0) {

		[[DOEnvironmentManager sharedManager] locateJailbreakRoot];

		[[DOUIManager sharedInstance] sendLog:@"Updating BaseBin" debug:NO];

		NSError* error=nil;
		if ([[NSFileManager defaultManager] fileExistsAtPath:jbrootPrefix(@"/basebin")]) {
			if (![[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/basebin") error:&error]) {
				completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed deleting existing basebin file with error: %@", error.localizedDescription]}]);
				return;
			}
		}
		error = [self extractTar:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"] toPath:jbrootPrefix(@"/")];
		if (error) {
			completion(error);
			return;
		}
		[self patchBasebinDaemonPlists];
		[[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/basebin/basebin.tc") error:nil];

		JBFixMobilePermissions();

		completion(nil);
	}
}

-(int) fixBootstrapSymlink:(NSString*)path
{
	const char* jbpath = jbrootPrefix(path).fileSystemRepresentation;

	struct stat st={0};
	assert(lstat(jbpath, &st) == 0);
	if (!S_ISLNK(st.st_mode)) {
		return 0;
	}

	char link[PATH_MAX+1] = {0};
	assert(readlink(jbpath, link, sizeof(link)-1) > 0);
	if(link[0] != '/') {
		return 0;
	}

	NSString* _link = @(link).stringByStandardizingPath.stringByResolvingSymlinksInPath;

	NSString *pattern = @"^(?:/private)?/var/containers/Bundle/Application/\\.jbroot-[0-9A-Z]{16}(/.+)$";
	NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
	NSTextCheckingResult *match = [regex firstMatchInString:_link options:0 range:NSMakeRange(0, [_link length])];
	assert(match != nil);

	NSString* target = [_link substringWithRange:[match rangeAtIndex:1]];
	NSString* newlink = [@".jbroot" stringByAppendingPathComponent:target];

	assert(unlink(jbpath) == 0);
	assert(symlink(newlink.fileSystemRepresentation, jbpath) == 0);
	assert(access(jbpath, F_OK) == 0);

	return 0;
}

- (NSError *)finalizeBootstrap
{

	if ([[NSFileManager defaultManager] fileExistsAtPath:jbrootPrefix(@"/prep_bootstrap.sh")]) {
		[[DOUIManager sharedInstance] sendLog:@"Finalizing Bootstrap" debug:NO];
		int r = exec_cmd_trusted(JBROOT_PATH("/bin/sh"), "/prep_bootstrap.sh", NULL);
		if (r != 0) {
			return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"prep_bootstrap.sh returned %d\n", r]}];
		}

		NSError *error = [self installPackageManagers];
		if (error) return error;

		NSString *roothideManager = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"roothideapp.deb"];
		 r = [self installPackage:roothideManager];
		if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install roothideManager: %d\n", r]}];
	}
	else
	{
		[[DOUIManager sharedInstance] sendLog:@"Updating Symlinks" debug:NO];
		[self fixBootstrapSymlink:@"/bin/sh"];
		[self fixBootstrapSymlink:@"/usr/bin/sh"];
		int r = exec_cmd_trusted(JBROOT_PATH("/bin/sh"), "/usr/libexec/updatelinks.sh", NULL);
		if (r != 0) {
			return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"updatelinks.sh returned %d\n", r]}];
		}
	}

	BOOL shouldInstallLibkrw = [self shouldInstallPackage:@"libkrw0-dopamine"];
	BOOL shouldInstallBasebinLink = [self shouldInstallPackage:@"dopamine-basebin-link"];

	if (shouldInstallLibkrw || shouldInstallBasebinLink) {
		[[DOUIManager sharedInstance] sendLog:@"Updating Bundled Packages" debug:NO];

		if (shouldInstallLibkrw) {
			NSString *libkrwPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libkrw-dopamine.deb"];
			int r = [self installPackage:libkrwPath];
			if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install the libkrw plugin: %d\n", r]}];
		}

		if (shouldInstallBasebinLink) {

			if (![self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/bin/opainject")]) {
				[[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/bin/opainject") error:nil];
			}
			if (![self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/bin/jbctl")]) {
				[[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/bin/jbctl") error:nil];
			}
			if (![self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/lib/libjailbreak.dylib")]) {
				[[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/lib/libjailbreak.dylib") error:nil];
			}
			if (![self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/bin/libjailbreak.dylib")]) {

				[[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/bin/libjailbreak.dylib") error:nil];
			}

			NSString *basebinLinkPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin-link.deb"];
			int r = [self installPackage:basebinLinkPath];
			if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install basebin link: %d\n", r]}];
		}
	}

	if ([self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/lib/libroot.dylib")]) {
		[[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/lib/libroot.dylib") error:nil];
	}
	NSString *librootPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libroot.deb"];
	NSString* unpackedPath = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
	int ret = exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg-deb"), "-R", rootfsPrefix(librootPath).fileSystemRepresentation, rootfsPrefix(unpackedPath).fileSystemRepresentation, NULL);
	if (ret != 0) {
		return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to unpack deb: %d\n", ret]}];
	}
	NSError* error=nil;
	[[NSFileManager defaultManager] copyItemAtPath:[unpackedPath stringByAppendingPathComponent:@"/var/jb/usr/lib/libroot.dylib"] toPath:jbrootPrefix(@"/usr/lib/libroot.dylib") error:&error];
	if(error) {
		return error;
	}

	[[NSString stringWithFormat:@"%d",DOPAMINE_INSTALL_VERSION] writeToFile:jbrootPrefix(@"/.installed_dopamine") atomically:YES encoding:NSUTF8StringEncoding error:nil];

	if(jbclient_palehide_present()) {
		[@"" writeToFile:jbrootPrefix(@"/.installed_palera1n") atomically:YES encoding:NSUTF8StringEncoding error:nil];
	} else {
		[[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/.installed_palera1n") error:nil];
	}

	return nil;
}

- (NSError *)deleteBootstrap
{

	NSError* error=nil;
	NSFileManager* fm = NSFileManager.defaultManager;

	NSString* dirpath = @"/var/containers/Bundle/Application/";
	for(NSString* item in [fm directoryContentsAtPath:dirpath])
	{
		if(is_jbroot_name(item.UTF8String)) {
			STRAPLOG("remove %@ @ %@", item, dirpath);
			if(![fm removeItemAtPath:[dirpath stringByAppendingPathComponent:item] error:&error])
				return error;
		}
	}

	dirpath = @"/var/mobile/Containers/Shared/AppGroup/";
	for(NSString* item in [fm directoryContentsAtPath:dirpath])
	{
		if(is_jbroot_name(item.UTF8String)) {
			STRAPLOG("remove %@ @ %@", item, dirpath);
			if(![fm removeItemAtPath:[dirpath stringByAppendingPathComponent:item] error:&error])
				return error;
		}
	}

	return nil;
}

@end

@implementation DOEnvironmentManager(roothide)
- (void)locateJailbreakRoot
{
	if(gSystemInfo.jailbreakInfo.rootPath) free(gSystemInfo.jailbreakInfo.rootPath);

	NSString* jbroot_path = find_jbroot(YES);
	if(jbroot_path) {
		gSystemInfo.jailbreakInfo.rootPath = strdup(jbroot_path.fileSystemRepresentation);
		gSystemInfo.jailbreakInfo.jbrand = jbrand_current();
	}
}
- (NSError *)ensureJailbreakRootExists
{
	return nil;
}
@end