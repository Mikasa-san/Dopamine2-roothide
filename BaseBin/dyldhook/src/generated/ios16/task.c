#include <mach/mach.h>

#define MACH64_SEND_KOBJECT_CALL 0x0000000200000000ull

mach_msg_return_t mach_msg2(
	void *data,
	uint64_t option64,
	mach_msg_header_t header,
	mach_msg_size_t send_size,
	mach_msg_size_t rcv_size,
	mach_port_t rcv_name,
	uint64_t timeout,
	uint32_t priority);

#undef mach_msg
#define mach_msg mig_mach_msg
static inline mach_msg_return_t
mig_mach_msg(
	mach_msg_header_t *msg,
	mach_msg_option_t option,
	mach_msg_size_t send_size,
	mach_msg_size_t rcv_size,
	mach_port_name_t rcv_name,
	mach_msg_timeout_t timeout,
	mach_port_name_t notify)
{
	(void)notify;
	return mach_msg2(
		msg,
		option | MACH64_SEND_KOBJECT_CALL,
		*msg,
		send_size,
		rcv_size,
		rcv_name,
		timeout,
		0
	);
}

kern_return_t
task_get_special_port(
	task_inspect_t task,
	int which_port,
	mach_port_t *special_port)
{
	typedef struct {
		mach_msg_header_t Head;
		int which_port;
	} Request;

	typedef struct {
		mach_msg_header_t Head;
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t special_port;
	} Reply;

	union {
		Request In;
		Reply Out;
	} Mess;

	Request *InP = &Mess.In;
	Reply   *OutP = &Mess.Out;
	mach_msg_return_t result;

	InP->which_port       = which_port;
	InP->Head.msgh_bits   = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	InP->Head.msgh_size   = sizeof(*InP);
	InP->Head.msgh_request_port = task;
	InP->Head.msgh_reply_port   = mig_get_reply_port();
	InP->Head.msgh_id     = 3409;

	result = mach_msg(
		&InP->Head,
		MACH_SEND_MSG | MACH_RCV_MSG,
		InP->Head.msgh_size,
		sizeof(*OutP),
		InP->Head.msgh_reply_port,
		MACH_MSG_TIMEOUT_NONE,
		MACH_PORT_NULL
	);

	if (result != MACH_MSG_SUCCESS) {
		return result;
	}

	*special_port = OutP->special_port.name;
	return KERN_SUCCESS;
}
