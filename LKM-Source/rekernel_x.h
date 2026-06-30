#ifndef REKERNEL_X_H
#define REKERNEL_X_H

#include <linux/types.h>
#include <linux/uidgid.h>

struct task_struct;

#ifndef REKERNEL_X_VERSION
#define REKERNEL_X_VERSION "dev"
#endif

#define CLEAN_UP_ASYNC_BINDER

#define MIN_USERAPP_UID                 (10000)
#define MAX_SYSTEM_UID                  (2000)
#define SYSTEM_APP_UID                  (1000)
#define RESERVE_ORDER					17
#define WARN_AHEAD_SPACE				(1 << RESERVE_ORDER)
#define INTERFACETOKEN_BUFF_SIZE        (140)
#define PARCEL_OFFSET                   (16) /* sync with the writeInterfaceToken */
#define LINE_ERROR                      (-1)
#define LINE_SUCCESS                    (0)

/*
 * Generic Netlink protocol (ABI contract with the userspace daemon).
 * The daemon resolves the "rekernel_x" family by name via CTRL_CMD_GETFAMILY,
 * joins the "events" multicast group to receive events, and sends
 * ADD_MONITOR_NET / DEL_MONITOR_NET commands.
 *
 * Events are sent as nested netlink attributes (NLA_NESTED):
 *
 *   REKERNEL_X_C_EVENT
 *     └─ REKERNEL_X_A_EVENT (NLA_NESTED)
 *          ├─ REKERNEL_X_A_EVENT_TYPE  (NLA_U8)
 *          └─ One of (NLA_NESTED):
 *               REKERNEL_X_A_BINDER   → sub-attrs: TYPE, FROM_PID, ...
 *               REKERNEL_X_A_SIGNAL   → sub-attrs: SIGNAL, KILLER_PID, ...
 *               REKERNEL_X_A_NETWORK  → sub-attrs: PROTO, TARGET_UID, ...
 */
#define REKERNEL_X_GENL_FAMILY_NAME       "rekernel_x"
#define REKERNEL_X_GENL_VERSION           1
#define REKERNEL_X_GENL_MCGRP_NAME        "events"

/* generic netlink commands */
enum rekernel_x_genl_cmd {
	REKERNEL_X_C_UNSPEC,
	REKERNEL_X_C_EVENT,            /* kernel -> user, multicast event (REKERNEL_X_A_EVENT) */
	REKERNEL_X_C_ADD_MONITOR_NET,  /* user -> kernel, add uid (carries REKERNEL_X_A_UID) */
	REKERNEL_X_C_DEL_MONITOR_NET,  /* user -> kernel, remove uid (carries REKERNEL_X_A_UID) */
	__REKERNEL_X_C_MAX,
};
#define REKERNEL_X_C_MAX (__REKERNEL_X_C_MAX - 1)

/* generic netlink attributes — range-blocked for extensibility (10 per group) */
enum rekernel_x_genl_attr {
	REKERNEL_X_A_UNSPEC,

	/* 1–9: top-level event container */
	REKERNEL_X_A_EVENT          = 1,  /* NLA_NESTED: contains event-type + payload */
	REKERNEL_X_A_EVENT_TYPE     = 2,  /* NLA_U8: enum rekernel_x_event_type */

	/* 10–19: binder event sub-attributes (inside REKERNEL_X_A_BINDER) */
	REKERNEL_X_A_BINDER         = 10, /* NLA_NESTED: binder event fields */
	REKERNEL_X_A_BINDER_TYPE    = 11, /* NLA_U32: enum rekernel_x_binder_type */
	REKERNEL_X_A_BINDER_ONEWAY  = 12, /* NLA_U32 */
	REKERNEL_X_A_BINDER_FROM_PID   = 13, /* NLA_S32 */
	REKERNEL_X_A_BINDER_FROM_UID   = 14, /* NLA_U32 */
	REKERNEL_X_A_BINDER_TARGET_PID = 15, /* NLA_S32 */
	REKERNEL_X_A_BINDER_TARGET_UID = 16, /* NLA_U32 */
	REKERNEL_X_A_BINDER_CODE    = 17, /* NLA_S32 */
	REKERNEL_X_A_BINDER_RPC_NAME = 18, /* NLA_NUL_STRING */

	/* 20–29: signal event sub-attributes (inside REKERNEL_X_A_SIGNAL) */
	REKERNEL_X_A_SIGNAL         = 20, /* NLA_NESTED: signal event fields */
	REKERNEL_X_A_SIGNAL_SIGNAL  = 21, /* NLA_S32: signal number */
	REKERNEL_X_A_SIGNAL_KILLER_PID = 22, /* NLA_S32 */
	REKERNEL_X_A_SIGNAL_KILLER_UID = 23, /* NLA_U32 */
	REKERNEL_X_A_SIGNAL_DST_PID = 24, /* NLA_S32 */
	REKERNEL_X_A_SIGNAL_DST_UID = 25, /* NLA_U32 */

	/* 30–39: network event sub-attributes (inside REKERNEL_X_A_NETWORK) */
	REKERNEL_X_A_NETWORK        = 30, /* NLA_NESTED: network event fields */
	REKERNEL_X_A_NETWORK_PROTO  = 31, /* NLA_U32: enum rekernel_x_net_proto */
	REKERNEL_X_A_NETWORK_TARGET_UID = 32, /* NLA_U32 */
	REKERNEL_X_A_NETWORK_DATA_LEN   = 33, /* NLA_S32 */

	/* 40+: user -> kernel command attributes */
	REKERNEL_X_A_UID            = 40, /* NLA_U32: uid to monitor for MONITOR_NET */

	__REKERNEL_X_A_MAX = 49,  /* reserve command attrs through 49 */
};
#define REKERNEL_X_A_MAX __REKERNEL_X_A_MAX

/* event types carried in struct rekernel_x_event.type */
enum rekernel_x_event_type {
	REKERNEL_X_EVT_BINDER  = 1,
	REKERNEL_X_EVT_SIGNAL  = 2,
	REKERNEL_X_EVT_NETWORK = 3,
};

/* binder sub-types (struct rekernel_x_binder_event.binder_type) */
enum rekernel_x_binder_type {
	REKERNEL_X_BINDER_TRANSACTION      = 1,
	REKERNEL_X_BINDER_REPLY            = 2,
	REKERNEL_X_BINDER_FREE_BUFFER_FULL = 3,
};

/* network protocol (struct rekernel_x_network_event.proto) */
enum rekernel_x_net_proto {
	REKERNEL_X_NET_PROTO_IPV4 = 4,
	REKERNEL_X_NET_PROTO_IPV6 = 6,
};

/*
 * Internal event structs — used inside the kernel module only, NOT on the
 * wire. The wire format uses nested netlink attributes (see above). These
 * structs are kept for convenient field collection before sendMessage()
 * serialises them into NLA attributes.  No packed attribute needed since
 * these structs are never serialised as a blob.
 */
struct rekernel_x_binder_event {
	__u8  binder_type;
	__u8  oneway;
	__s32 from_pid;
	__u32 from_uid;
	__s32 target_pid;
	__u32 target_uid;
	__s32 code;
	char  rpc_name[INTERFACETOKEN_BUFF_SIZE];
};

struct rekernel_x_signal_event {
	__s32 signal;
	__s32 killer_pid;
	__u32 killer_uid;
	__s32 dst_pid;
	__u32 dst_uid;
};

struct rekernel_x_network_event {
	__u8  proto;
	__u32 target_uid;
	__s32 data_len;
};

struct rekernel_x_event {
	__u8 type;
	union {
		struct rekernel_x_binder_event  binder;
		struct rekernel_x_signal_event  signal;
		struct rekernel_x_network_event network;
	} u;
};

/*
 * Cross-file interface for the rekernel module. The implementations live in
 * separate translation units; this section declares the symbols each unit
 * exports to the others.
 */

/* genl.c — generic netlink transport */
bool rekernel_x_netlink_ready(void);
int sendMessage(struct rekernel_x_event *event);
int register_genl(void);
void unregister_genl(void);

/* net_uid.c — network-monitor uid hashmap */
bool net_uid_monitored_rcu(uid_t uid);
void net_uid_add(uid_t uid);
void net_uid_del(uid_t uid);
void net_uid_init(void);
void net_uid_destroy(void);

/* frozen.c — task frozen-state predicate (version-compatible) */
bool line_is_frozen(struct task_struct *task);

/* binder.c / signal.c / netfilter.c / binder_kp.c — subsystem (un)registration */
int register_binder(void);
void unregister_binder(void);

int register_signal(void);
void unregister_signal(void);

int register_netfilter(void);
void unregister_netfilter(void);

void register_binder_kp(void);
void unregister_binder_kp(void);

#endif
