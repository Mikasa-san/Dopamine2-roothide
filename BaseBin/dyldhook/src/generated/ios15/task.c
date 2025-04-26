#include <mach/mach.h>

#define __DeclareSendRpc(...)
#define __BeforeSendRpc(...)
#define __AfterSendRpc(...)
#define __MachMsgErrorWithoutTimeout(...)

#define msgh_request_port    msgh_remote_port
#define msgh_reply_port      msgh_local_port

kern_return_t
task_get_special_port(task_inspect_t task, int which_port, mach_port_t *special_port)
{
	mach_msg_return_t msg_result;
#ifdef __MIG_check__Reply__task_get_special_port_t__defined
	kern_return_t check_result;
#endif

#ifdef __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		NDR_record_t      NDR;
		int               which_port;
	} Request __attribute__((unused));

	typedef struct {
		mach_msg_header_t           Head;
		mach_msg_body_t             msgh_body;
		mach_msg_port_descriptor_t  special_port;
		mach_msg_trailer_t          trailer;
	} Reply __attribute__((unused));

	typedef struct {
		mach_msg_header_t          Head;
		mach_msg_body_t            msgh_body;
		mach_msg_port_descriptor_t special_port;
	} __Reply __attribute__((unused));
#ifdef __MigPackStructs
#pragma pack(pop)
#endif

	union {
		Request In;
		Reply   Out;
	} Mess;

	Request *InP = &Mess.In;
	Reply   *OutP = &Mess.Out;

	__DeclareSendRpc(3409, "task_get_special_port")

	InP->which_port         = which_port;
	InP->Head.msgh_reply_port = mig_get_reply_port();
	InP->Head.msgh_bits       = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	InP->Head.msgh_request_port = task;
	InP->Head.msgh_id         = 3409;
	InP->Head.msgh_reserved   = 0;

#ifdef USING_VOUCHERS
	if (voucher_mach_msg_set)
		voucher_mach_msg_set(&InP->Head);
#endif

	__BeforeSendRpc(3409, "task_get_special_port")
	msg_result = mach_msg(&InP->Head,
	                      MACH_SEND_MSG | MACH_RCV_MSG | MACH_MSG_OPTION_NONE,
	                      (mach_msg_size_t)sizeof(Request),
	                      (mach_msg_size_t)sizeof(Reply),
	                      InP->Head.msgh_reply_port,
	                      MACH_MSG_TIMEOUT_NONE,
	                      MACH_PORT_NULL);
	__AfterSendRpc(3409, "task_get_special_port")

	if (msg_result != MACH_MSG_SUCCESS) {
		__MachMsgErrorWithoutTimeout(msg_result);
		return msg_result;
	}

#ifdef __MIG_check__Reply__task_get_special_port_t__defined
	check_result = __MIG_check__Reply__task_get_special_port_t((__Reply__task_get_special_port_t *)&Mess.Out);
	if (check_result != MACH_MSG_SUCCESS) {
		mach_msg_destroy(&OutP->Head);
		return check_result;
	}
#endif

	*special_port = OutP->special_port.name;
	return KERN_SUCCESS;
}