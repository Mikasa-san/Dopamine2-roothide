#import <Foundation/Foundation.h>
#import <bsm/libbsm.h>
#import <libproc.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/roothider.h>

static void send_reply(JBD_MESSAGE_ID msgId, xpc_object_t reply) {
	char *desc = xpc_copy_description(reply);
	JBLogDebug("reply %u: %s", msgId, desc);
	free(desc);
	if (int err = xpc_pipe_routine_reply(reply))
		JBLogError("reply error %d", err);
}

void jailbreakd_received_message(mach_port_t port) {
	@autoreleasepool {
		xpc_object_t msg = NULL;
		if (int err = xpc_pipe_receive(port, &msg)) {
			JBLogError("receive error %d", err);
			return;
		}
		if (xpc_get_type(msg) != XPC_TYPE_DICTIONARY)
			return;

		JBD_MESSAGE_ID msgId = xpc_dictionary_get_uint64(msg, "id");
		xpc_object_t reply = xpc_dictionary_create_reply(msg);

		audit_token_t token;
		xpc_dictionary_get_audit_token(msg, &token);
		uid_t uid = audit_token_to_euid(token);
		pid_t pid = audit_token_to_pid(token);

		char *desc = xpc_copy_description(msg);
		JBLogDebug("msg %u from %d (%s): %s",
		           msgId, pid, proc_get_path(pid, NULL), desc);
		free(desc);

		switch (msgId) {
		case JBD_MSG_SPAWN_PATCH_CHILD: {
			pid_t child = xpc_dictionary_get_int64(msg, "pid");
			bool resume = xpc_dictionary_get_bool(msg, "resume");
			pid_t ppid = proc_get_ppid(child);
			int64_t res = -1;
			if (ppid == pid && roothide_patch_proc(child) == 0) {
				if (resume) kill(child, SIGCONT);
				res = 0;
			} else {
				JBLogError("spawn patch denied/failed for %d", child);
			}
			xpc_dictionary_set_int64(reply, "result", res);
			break;
		}
		case JBD_MSG_SPAWN_EXEC_START: {
			bool resume = xpc_dictionary_get_bool(msg, "resume");
			int64_t res = spawnExecPatchAdd(pid, resume);
			xpc_dictionary_set_int64(reply, "result", res);
			break;
		}
		case JBD_MSG_SPAWN_EXEC_CANCEL:
			xpc_dictionary_set_int64(reply, "result",
			                         spawnExecPatchDel(pid));
			break;

		case JBD_MSG_EXEC_TRACE_START: {
			uint64_t traceId = xpc_dictionary_get_uint64(msg, "traced");
			dispatch_async(dispatch_get_global_queue(0,0), ^{
				xpc_object_t r = xpc_dictionary_create_reply(msg);
				int64_t res = execTraceProcess(pid, traceId);
				xpc_dictionary_set_int64(r, "result", res);
				send_reply(msgId, r);
			});
			reply = NULL; // deferred
			break;
		}
		case JBD_MSG_EXEC_TRACE_CANCEL:
			xpc_dictionary_set_int64(reply, "result",
			                         execTraceCancel(pid));
			break;

#ifdef ENABLE_LOGS
		case JBD_MSG_SYSTEMWIDE_LOG: {
			const char *path = proc_get_path(pid, NULL);
			const char *prog = path && (strrchr(path, '/')+1) ? 
			                   strrchr(path, '/')+1 : path;
			uint64_t tid = xpc_dictionary_get_uint64(msg, "tid");
			const char *log = xpc_dictionary_get_string(msg, "log");
			JBLogFunction(JBLogGetLogFilePath("systemwide",NULL),
			              pid, tid, prog ? prog : "(nil)", "%s", log);
			xpc_dictionary_set_int64(reply, "result", 0);
			break;
		}
#endif

		case JBD_MSG_TEST_CALL: {
			int64_t v = xpc_dictionary_get_int64(msg, "value");
			JBLogDebug("test %llu from %d", v, pid);
			xpc_dictionary_set_int64(reply, "result", v*2);
			if (uid == 0) abort(); // crashreporter test
			break;
		}

		default:
			JBLogError("unknown msg %u", msgId);
		}

		if (reply)
			send_reply(msgId, reply);
	}
}