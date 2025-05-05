#import <Foundation/Foundation.h>
#import <kern_memorystatus.h>
#import <mach-o/dyld.h>
#import <libproc.h>
#import <spawn.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/roothider.h>

extern char **environ;

static void fatal(const char *msg, int code) {
	perror(msg);
	exit(code);
}

static void setJetsam(bool on) {
	if (memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK,
	                         getpid(), on ? 10 : -1, NULL, 0) < 0) {
		fatal("memorystatus_control", code);
	}
}

int main(int argc, char *argv[]) {
	crashreporter_start();
#ifdef ENABLE_LOGS
	enableXPCLog(JBLogDebugFunction, JBLogErrorFunction);
	enableJBDLog(JBLogDebugFunction, JBLogErrorFunction);
#endif
	JBLogDebug("jailbreakd uid=%d pid=%d ppid=%d", getuid(), getpid(), getppid());

	@autoreleasepool {
		setJetsam(true);

		mach_port_t *ports;
		mach_msg_type_number_t count;
		if (mach_ports_lookup(mach_task_self(), &ports, &count) != KERN_SUCCESS || count < 3) {
			fatal("mach_ports_lookup", 1);
		}

		mach_port_t boot = ports[2];
		if (!MACH_PORT_VALID(boot)) {
			fatal("invalid bootstrap port", 2);
		}

		// unregister the bootstrap port from our task and re-register without it
		ports[2] = MACH_PORT_NULL;
		mach_ports_register(mach_task_self(), ports, count);

		// initialize jailbreak primitives
		jbclient_xpc_set_custom_port(boot);
		if (jbclient_initialize_primitives() != 0) {
			fatal("init primitives", 3);
		}

		// handle respawn if requested
		if (getenv("RESPAWN_REQUIRED")) {
			unsetenv("RESPAWN_REQUIRED");

			char path[PATH_MAX];
			uint32_t sz = sizeof(path);
			_NSGetExecutablePath(path, &sz);

			posix_spawnattr_t attr;
			posix_spawnattr_init(&attr);
			posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
			posix_spawnattr_set_registered_ports_np(&attr,
			    (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, boot }, 3);

			pid_t pid;
			int res = posix_spawn(&pid, path, NULL, &attr, argv, environ);
			posix_spawnattr_destroy(&attr);
			if (res) {
				JBLogError("spawn failed: %d (%s)", res, strerror(res));
				return 4;
			}

			JBLogDebug("respawned jailbrkd: %d", pid);
			if (unrestrict(pid, roothide_patch_proc, true) != 0) {
				JBLogError("failed to unrestrict %d", pid);
				return 5;
			}
			return 0;
		}

		// check in with the daemon
		mach_port_t server = jbclient_jailbreakd_checkin();
		if (!MACH_PORT_VALID(server)) {
			fatal("checkin failed", 6);
		}

		// start listening for messages
		dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV,
		                                              (uintptr_t)server, 0,
		                                              dispatch_get_main_queue());
		dispatch_source_set_event_handler(src, ^{
			jailbreakd_received_message(server);
		});
		dispatch_resume(src);
		dispatch_main();
	}

	return 0;
}