/*
 * ReKernelX JNI — Generic Netlink client for ReKernel-X LKM.
 *
 * Connects to the kernel "rekernel_x" genl family, joins the "events" multicast
 * group, receives nested-attribute event messages and dispatches them to the
 * Java ReKernelXCallback interface.
 *
 * ABI contract: attribute IDs must stay in sync with LKM-Source/rekernel_x.h.
 */
#include <jni.h>
#include <android/log.h>

#include <atomic>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <mutex>

#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#define TAG "ReKernelX-JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ==========================================================================
 *  ABI mirror — attribute IDs must match LKM-Source/rekernel_x.h.
 * ========================================================================== */

/* SOL_NETLINK / NETLINK_ADD_MEMBERSHIP come from the system headers
 * (<sys/socket.h>, <linux/netlink.h>) — no local fallback. */

/* rekernel genl commands */
#define REKERNEL_X_C_EVENT                1
#define REKERNEL_X_C_ADD_MONITOR_NET      2
#define REKERNEL_X_C_DEL_MONITOR_NET      3

/* rekernel genl attributes — must match LKM-Source/rekernel_x.h (range-blocked) */
#define REKERNEL_X_A_EVENT                1
#define REKERNEL_X_A_EVENT_TYPE           2
#define REKERNEL_X_A_BINDER               10
#define REKERNEL_X_A_BINDER_TYPE          11
#define REKERNEL_X_A_BINDER_ONEWAY        12
#define REKERNEL_X_A_BINDER_FROM_PID      13
#define REKERNEL_X_A_BINDER_FROM_UID      14
#define REKERNEL_X_A_BINDER_TARGET_PID    15
#define REKERNEL_X_A_BINDER_TARGET_UID    16
#define REKERNEL_X_A_BINDER_CODE          17
#define REKERNEL_X_A_BINDER_RPC_NAME      18
#define REKERNEL_X_A_SIGNAL               20
#define REKERNEL_X_A_SIGNAL_SIGNAL        21
#define REKERNEL_X_A_SIGNAL_KILLER_PID    22
#define REKERNEL_X_A_SIGNAL_KILLER_UID    23
#define REKERNEL_X_A_SIGNAL_DST_PID       24
#define REKERNEL_X_A_SIGNAL_DST_UID       25
#define REKERNEL_X_A_NETWORK              30
#define REKERNEL_X_A_NETWORK_PROTO        31
#define REKERNEL_X_A_NETWORK_TARGET_UID   32
#define REKERNEL_X_A_NETWORK_DATA_LEN     33
#define REKERNEL_X_A_UID                  40

/* event types */
#define REKERNEL_X_EVT_BINDER             1
#define REKERNEL_X_EVT_SIGNAL             2
#define REKERNEL_X_EVT_NETWORK            3

/* binder sub-types */
#define REKERNEL_X_BINDER_TRANSACTION     1
#define REKERNEL_X_BINDER_REPLY           2
#define REKERNEL_X_BINDER_FREE_BUFFER_FULL 3

/* network protocol */
#define REKERNEL_X_NET_PROTO_IPV4         4
#define REKERNEL_X_NET_PROTO_IPV6         6

/* genl family metadata */
#define REKERNEL_X_GENL_FAMILY_NAME   "rekernel_x"
#define REKERNEL_X_GENL_MCGRP_NAME    "events"
#define REKERNEL_X_GENL_VERSION       1
#define REKERNEL_X_RPC_NAME_LEN       140

/* ==========================================================================
 *  NLA (NetLink Attribute) helpers
 *
 *  These mirror the kernel's nla_for_each_attr / nla_find patterns.
 * ========================================================================== */

static inline uint16_t nla_align(uint16_t len) {
    return (len + 3) & ~3;
}

/* Iterate NLA attributes in a raw byte buffer.
 *   pos  — current byte offset (updated by the macro)
 *   end  — one-past-last valid byte offset
 *   nla  — pointer to current struct nlattr
 */
#define NLA_FOR_EACH_ATTR(pos, end, nla, buf) \
    for (auto *nla = reinterpret_cast<struct nlattr *>(buf + (pos)); \
         (pos) + NLA_HDRLEN <= (end) && (nla)->nla_len >= NLA_HDRLEN; \
         (pos) += nla_align((nla)->nla_len), \
         nla = reinterpret_cast<struct nlattr *>(buf + (pos)))

/* Read the attribute's data pointer. */
static inline void *nla_data(struct nlattr *nla) {
    return reinterpret_cast<uint8_t *>(nla) + NLA_HDRLEN;
}

static inline int nla_datalen(struct nlattr *nla) {
    return nla->nla_len - NLA_HDRLEN;
}

/* ==========================================================================
 *  Global JNI state
 * ========================================================================== */

static JavaVM           *g_jvm              = nullptr;
static jobject           g_callback         = nullptr;
static jclass            g_cbClass          = nullptr;
static jmethodID         g_mid_disconnected = nullptr;
static jmethodID         g_mid_binder       = nullptr;
static jmethodID         g_mid_signal       = nullptr;
static jmethodID         g_mid_network      = nullptr;

static int               g_fd               = -1;
static uint16_t          g_family_id        = 0;
static uint32_t          g_mcast_group_id   = 0;
static std::atomic<uint32_t> g_seq{1};
static std::atomic<bool> g_running{false};
static pthread_t         g_thread           = 0;
static std::mutex        g_send_mutex;

/* ==========================================================================
 *  Netlink socket helpers
 * ========================================================================== */

static int nl_sendto(const void *buf, size_t len) {
    struct sockaddr_nl dst = {};
    dst.nl_family = AF_NETLINK;
    ssize_t n = sendto(g_fd, buf, len, 0,
                       reinterpret_cast<struct sockaddr *>(&dst), sizeof(dst));
    return (n == static_cast<ssize_t>(len)) ? 0 : -1;
}

static int nl_recv(void *buf, size_t bufsize) {
    struct sockaddr_nl src = {};
    socklen_t addrlen = sizeof(src);
    ssize_t n = recvfrom(g_fd, buf, bufsize, 0,
                         reinterpret_cast<struct sockaddr *>(&src), &addrlen);
    return static_cast<int>(n);
}

/* ==========================================================================
 *  genl family resolution
 * ========================================================================== */

/*
 * Find the multicast group ID matching `target_name` inside a
 * CTRL_ATTR_MCAST_GROUPS nested attribute.
 */
static uint32_t find_mcast_group_id(struct nlattr *mcast_attr,
                                    const char *target_name) {
    int pos = 0;
    int end = nla_datalen(mcast_attr);
    auto *base = static_cast<uint8_t *>(nla_data(mcast_attr));

    NLA_FOR_EACH_ATTR(pos, end, outer, base) {
        auto *group = static_cast<uint8_t *>(nla_data(outer));
        int gpos = 0, gend = nla_datalen(outer);
        char grp_name[64] = {};
        uint32_t grp_id = 0;
        bool have_name = false, have_id = false;

        NLA_FOR_EACH_ATTR(gpos, gend, inner, group) {
            int type = inner->nla_type & NLA_TYPE_MASK;
            if (type == CTRL_ATTR_MCAST_GRP_NAME && nla_datalen(inner) > 0) {
                int slen = nla_datalen(inner);
                if (slen > 63) slen = 63;
                memcpy(grp_name, nla_data(inner), slen);
                grp_name[slen] = '\0';
                have_name = true;
            } else if (type == CTRL_ATTR_MCAST_GRP_ID && nla_datalen(inner) >= 4) {
                grp_id = *static_cast<uint32_t *>(nla_data(inner));
                have_id = true;
            }
        }
        if (have_name && have_id && strcmp(grp_name, target_name) == 0)
            return grp_id;
    }
    return 0;
}

/*
 * Send CTRL_CMD_GETFAMILY for "rekernel_x", parse the reply to populate
 * g_family_id and g_mcast_group_id.
 */
static int resolveFamily() {
    /* Build request: nlmsghdr + genlmsghdr + CTRL_ATTR_FAMILY_NAME */
    const char *name = REKERNEL_X_GENL_FAMILY_NAME;
    uint16_t name_len  = static_cast<uint16_t>(strlen(name) + 1);
    uint16_t attr_len  = NLA_HDRLEN + name_len;
    uint16_t total     = NLMSG_HDRLEN + GENL_HDRLEN + nla_align(attr_len);

    uint8_t buf[256] = {};

    auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
    nlh->nlmsg_len   = total;
    nlh->nlmsg_type  = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = g_seq.fetch_add(1);
    nlh->nlmsg_pid   = 0;

    auto *ghdr = reinterpret_cast<struct genlmsghdr *>(buf + NLMSG_HDRLEN);
    ghdr->cmd     = CTRL_CMD_GETFAMILY;
    ghdr->version  = 1;
    ghdr->reserved = 0;

    auto *nla = reinterpret_cast<struct nlattr *>(buf + NLMSG_HDRLEN + GENL_HDRLEN);
    nla->nla_len  = attr_len;
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    memcpy(nla_data(nla), name, name_len);

    if (nl_sendto(buf, total) < 0) {
        LOGE("resolveFamily: sendto failed: %s", strerror(errno));
        return -1;
    }

    /* Temporary 3s recv timeout just for this reply, then restore blocking
     * default — the recv thread must stay blocked, not busy-poll. */
    struct timeval rcvto = {3, 0};
    setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));

    uint8_t reply[4096];
    int rlen = nl_recv(reply, sizeof(reply));

    struct timeval blockto = {0, 0};
    setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &blockto, sizeof(blockto));

    if (rlen < 0) {
        LOGE("resolveFamily: recv failed: %s", strerror(errno));
        return -1;
    }

    auto *rnlh = reinterpret_cast<struct nlmsghdr *>(reply);
    if (rnlh->nlmsg_type == NLMSG_ERROR) {
        LOGE("resolveFamily: got NLMSG_ERROR");
        return -1;
    }

    /* Parse reply attributes */
    uint16_t fid = 0;
    uint32_t gid = 0;
    bool have_fid = false;

    int pos = NLMSG_HDRLEN + GENL_HDRLEN;
    int end = static_cast<int>(rnlh->nlmsg_len);

    NLA_FOR_EACH_ATTR(pos, end, attr, reply) {
        int type = attr->nla_type & NLA_TYPE_MASK;

        if (type == CTRL_ATTR_FAMILY_ID && nla_datalen(attr) >= 2) {
            fid = *static_cast<uint16_t *>(nla_data(attr));
            have_fid = true;
        } else if (type == CTRL_ATTR_MCAST_GROUPS) {
            gid = find_mcast_group_id(attr, REKERNEL_X_GENL_MCGRP_NAME);
        }
    }

    if (!have_fid) {
        LOGE("resolveFamily: family_id not found");
        return -1;
    }
    if (gid == 0) {
        LOGE("resolveFamily: multicast group \"%s\" not found",
             REKERNEL_X_GENL_MCGRP_NAME);
        return -1;
    }

    g_family_id = fid;
    g_mcast_group_id = gid;
    LOGI("resolveFamily: family_id=%u mcast_group_id=%u", g_family_id, g_mcast_group_id);
    return 0;
}

/* ==========================================================================
 *  genl command sender (addMonitorNet / delMonitorNet)
 * ========================================================================== */

static int sendCommand(uint8_t cmd, uint32_t uid) {
    uint16_t total = NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN + 4;

    uint8_t buf[128] = {};

    auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
    nlh->nlmsg_len   = total;
    nlh->nlmsg_type  = g_family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = g_seq.fetch_add(1);
    nlh->nlmsg_pid   = 0;

    auto *ghdr = reinterpret_cast<struct genlmsghdr *>(buf + NLMSG_HDRLEN);
    ghdr->cmd     = cmd;
    ghdr->version  = REKERNEL_X_GENL_VERSION;
    ghdr->reserved = 0;

    auto *nla = reinterpret_cast<struct nlattr *>(buf + NLMSG_HDRLEN + GENL_HDRLEN);
    nla->nla_len  = NLA_HDRLEN + 4;
    nla->nla_type = REKERNEL_X_A_UID;
    *static_cast<uint32_t *>(nla_data(nla)) = uid;

    /* g_send_mutex guards the fd against concurrent close in cleanup_globals. */
    std::lock_guard<std::mutex> lock(g_send_mutex);
    if (g_fd < 0)
        return -1;
    return nl_sendto(buf, total);
}

/* ==========================================================================
 *  Event dispatch
 * ========================================================================== */

static void dispatch_event(JNIEnv *env, uint8_t event_type, struct nlattr *payload_attr) {
    if (!g_callback || !g_cbClass)
        return;

    switch (event_type) {
        case REKERNEL_X_EVT_BINDER: {
            int bpos = 0, bend = nla_datalen(payload_attr);
            auto *bbase = static_cast<uint8_t *>(nla_data(payload_attr));
            int32_t  binder_type = 0, oneway = 0, from_pid = 0, target_pid = 0, code = 0;
            uint32_t from_uid = 0, target_uid = 0;
            char rpc_name[REKERNEL_X_RPC_NAME_LEN + 1] = {};

            NLA_FOR_EACH_ATTR(bpos, bend, ba, bbase) {
                int btype = ba->nla_type & NLA_TYPE_MASK;
                switch (btype) {
                    case REKERNEL_X_A_BINDER_TYPE:     binder_type = *static_cast<int32_t *>(nla_data(ba)); break;
                    case REKERNEL_X_A_BINDER_ONEWAY:   oneway = *static_cast<int32_t *>(nla_data(ba)); break;
                    case REKERNEL_X_A_BINDER_FROM_PID: from_pid = *static_cast<int32_t *>(nla_data(ba)); break;
                    case REKERNEL_X_A_BINDER_FROM_UID: from_uid = *static_cast<uint32_t *>(nla_data(ba)); break;
                    case REKERNEL_X_A_BINDER_TARGET_PID: target_pid = *static_cast<int32_t *>(nla_data(ba)); break;
                    case REKERNEL_X_A_BINDER_TARGET_UID: target_uid = *static_cast<uint32_t *>(nla_data(ba)); break;
                    case REKERNEL_X_A_BINDER_CODE:     code = *static_cast<int32_t *>(nla_data(ba)); break;
                    case REKERNEL_X_A_BINDER_RPC_NAME: {
                        int slen = nla_datalen(ba);
                        if (slen > REKERNEL_X_RPC_NAME_LEN) slen = REKERNEL_X_RPC_NAME_LEN;
                        memcpy(rpc_name, nla_data(ba), slen);
                        rpc_name[slen] = '\0';
                        break;
                    }
                }
            }

            jstring jRpcName = env->NewStringUTF(rpc_name);
            env->CallVoidMethod(g_callback, g_mid_binder,
                                static_cast<jint>(binder_type),
                                static_cast<jint>(oneway),
                                static_cast<jint>(from_uid),
                                static_cast<jint>(from_pid),
                                static_cast<jint>(target_uid),
                                static_cast<jint>(target_pid),
                                jRpcName,
                                static_cast<jint>(code));
            if (jRpcName) env->DeleteLocalRef(jRpcName);
            break;
        }
        case REKERNEL_X_EVT_SIGNAL: {
            int spos = 0, send = nla_datalen(payload_attr);
            auto *sbase = static_cast<uint8_t *>(nla_data(payload_attr));
            int32_t  sig = 0, killer_pid = 0, dst_pid = 0;
            uint32_t killer_uid = 0, dst_uid = 0;

            NLA_FOR_EACH_ATTR(spos, send, sa, sbase) {
                int stype = sa->nla_type & NLA_TYPE_MASK;
                switch (stype) {
                    case REKERNEL_X_A_SIGNAL_SIGNAL:     sig = *static_cast<int32_t *>(nla_data(sa)); break;
                    case REKERNEL_X_A_SIGNAL_KILLER_PID: killer_pid = *static_cast<int32_t *>(nla_data(sa)); break;
                    case REKERNEL_X_A_SIGNAL_KILLER_UID: killer_uid = *static_cast<uint32_t *>(nla_data(sa)); break;
                    case REKERNEL_X_A_SIGNAL_DST_PID:    dst_pid = *static_cast<int32_t *>(nla_data(sa)); break;
                    case REKERNEL_X_A_SIGNAL_DST_UID:    dst_uid = *static_cast<uint32_t *>(nla_data(sa)); break;
                }
            }

            env->CallVoidMethod(g_callback, g_mid_signal,
                                static_cast<jint>(sig),
                                static_cast<jint>(killer_uid),
                                static_cast<jint>(killer_pid),
                                static_cast<jint>(dst_uid),
                                static_cast<jint>(dst_pid));
            break;
        }
        case REKERNEL_X_EVT_NETWORK: {
            int npos = 0, nend = nla_datalen(payload_attr);
            auto *nbase = static_cast<uint8_t *>(nla_data(payload_attr));
            int32_t  proto = 0, data_len = 0;
            uint32_t target_uid = 0;

            NLA_FOR_EACH_ATTR(npos, nend, na, nbase) {
                int ntype = na->nla_type & NLA_TYPE_MASK;
                switch (ntype) {
                    case REKERNEL_X_A_NETWORK_PROTO:       proto = *static_cast<int32_t *>(nla_data(na)); break;
                    case REKERNEL_X_A_NETWORK_TARGET_UID:  target_uid = *static_cast<uint32_t *>(nla_data(na)); break;
                    case REKERNEL_X_A_NETWORK_DATA_LEN:    data_len = *static_cast<int32_t *>(nla_data(na)); break;
                }
            }

            env->CallVoidMethod(g_callback, g_mid_network,
                                static_cast<jint>(proto),
                                static_cast<jint>(target_uid),
                                static_cast<jint>(data_len));
            break;
        }
        default:
            LOGE("dispatch_event: unknown type %u", event_type);
            break;
    }

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

/* ==========================================================================
 *  Receive loop (runs on g_thread)
 * ========================================================================== */

static void *recv_thread(void *) {
    JNIEnv *env = nullptr;
    bool attached = false;

    if (g_jvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
            attached = true;
        } else {
            LOGE("recv_thread: AttachCurrentThread failed");
            return nullptr;
        }
    }

    uint8_t rbuf[8192];
    bool had_error = false;

    while (g_running.load()) {
        int rlen = nl_recv(rbuf, sizeof(rbuf));
        if (rlen < 0) {
            /* EINTR/EAGAIN/ENOBUFS are transient — retry, don't disconnect. */
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)
                continue;
            had_error = true;
            LOGE("recv_thread: recv error: %s", strerror(errno));
            break;
        }
        if (rlen == 0)
            continue;

        /* Iterate netlink messages in the datagram */
        for (auto *nlh = reinterpret_cast<struct nlmsghdr *>(rbuf);
             NLMSG_OK(nlh, static_cast<size_t>(rlen));
             nlh = NLMSG_NEXT(nlh, rlen)) {

            if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_DONE)
                continue;
            if (nlh->nlmsg_type != g_family_id)
                continue;
            if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
                continue;

            auto *ghdr = reinterpret_cast<struct genlmsghdr *>(
                reinterpret_cast<uint8_t *>(nlh) + NLMSG_HDRLEN);
            if (ghdr->cmd != REKERNEL_X_C_EVENT)
                continue;

            /* Find REKERNEL_X_A_EVENT (nested) attribute */
            int pos = NLMSG_HDRLEN + GENL_HDRLEN;
            int end = static_cast<int>(nlh->nlmsg_len);

            NLA_FOR_EACH_ATTR(pos, end, attr, reinterpret_cast<uint8_t *>(nlh)) {
                int atype = attr->nla_type & NLA_TYPE_MASK;
                if (atype != REKERNEL_X_A_EVENT || nla_datalen(attr) < NLA_HDRLEN)
                    continue;

                /* Parse inside the REKERNEL_X_A_EVENT nest */
                int epos = 0, eend = nla_datalen(attr);
                auto *ebase = static_cast<uint8_t *>(nla_data(attr));
                uint8_t event_type = 0;
                struct nlattr *payload_attr = nullptr;

                NLA_FOR_EACH_ATTR(epos, eend, ea, ebase) {
                    int etype = ea->nla_type & NLA_TYPE_MASK;
                    if (etype == REKERNEL_X_A_EVENT_TYPE && nla_datalen(ea) >= 1) {
                        event_type = *static_cast<uint8_t *>(nla_data(ea));
                    } else if (etype == REKERNEL_X_A_BINDER ||
                               etype == REKERNEL_X_A_SIGNAL ||
                               etype == REKERNEL_X_A_NETWORK) {
                        payload_attr = ea;
                    }
                }

                if (event_type > 0 && payload_attr) {
                    dispatch_event(env, event_type, payload_attr);
                }
            }
        }
    }

    /* Clean stop (g_running cleared) doesn't fire disconnected; only a recv
     * error while still running does. */
    const bool clean_shutdown = had_error ? !g_running.load() : true;
    if (!clean_shutdown) {
        /* Close the fd so a later sendCommand fails fast; keep g_running true
         * so stopListening() still does full teardown. */
        {
            std::lock_guard<std::mutex> lock(g_send_mutex);
            if (g_fd >= 0) {
                shutdown(g_fd, SHUT_RDWR);
                close(g_fd);
                g_fd = -1;
            }
        }
        /* Callback outside the mutex — the handler may reenter native. */
        if (g_callback && g_mid_disconnected)
            env->CallVoidMethod(g_callback, g_mid_disconnected);
    }

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }

    if (attached)
        g_jvm->DetachCurrentThread();

    LOGI("recv_thread: exiting");
    return nullptr;
}

/* ==========================================================================
 *  JNI lifecycle
 * ========================================================================== */

static void cleanup_globals(JNIEnv *env) {
    g_running.store(false);

    /* shutdown() wakes the recv thread; close under g_send_mutex to exclude
     * concurrent sendCommand. */
    {
        std::lock_guard<std::mutex> lock(g_send_mutex);
        if (g_fd >= 0) {
            shutdown(g_fd, SHUT_RDWR);
            close(g_fd);
            g_fd = -1;
        }
    }
    if (g_thread) {
        pthread_join(g_thread, nullptr);
        g_thread = 0;
    }
    if (g_callback) {
        env->DeleteGlobalRef(g_callback);
        g_callback = nullptr;
    }
    if (g_cbClass) {
        env->DeleteGlobalRef(g_cbClass);
        g_cbClass = nullptr;
    }

    g_mid_disconnected = nullptr;
    g_mid_binder       = nullptr;
    g_mid_signal       = nullptr;
    g_mid_network      = nullptr;
    g_family_id        = 0;
    g_mcast_group_id   = 0;
    g_seq.store(1);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_cn_myflv_kernel_ReKernelX_startListening(
        JNIEnv *env, jclass /* clazz */, jobject callback) {

    if (g_running.load()) {
        LOGI("startListening: already running");
        return JNI_FALSE;
    }

    env->GetJavaVM(&g_jvm);

    /* Resolve callback method IDs (must run on app thread for FindClass) */
    jclass cls = env->FindClass("cn/myflv/kernel/ReKernelXCallback");
    if (!cls) {
        LOGE("startListening: FindClass failed");
        return JNI_FALSE;
    }
    g_cbClass = (jclass) env->NewGlobalRef(cls);

    g_mid_disconnected = env->GetMethodID(cls, "disconnected", "()V");
    g_mid_binder       = env->GetMethodID(cls, "binder",
        "(IIIIIILjava/lang/String;I)V");
    g_mid_signal       = env->GetMethodID(cls, "signal",       "(IIIII)V");
    g_mid_network      = env->GetMethodID(cls, "network",      "(III)V");

    if (!g_mid_disconnected || !g_mid_binder ||
        !g_mid_signal || !g_mid_network) {
        LOGE("startListening: GetMethodID failed");
        env->DeleteGlobalRef(g_cbClass);
        g_cbClass = nullptr;
        return JNI_FALSE;
    }

    g_callback = env->NewGlobalRef(callback);

    /* Create and bind netlink socket */
    g_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
    if (g_fd < 0) {
        LOGE("startListening: socket() failed: %s", strerror(errno));
        cleanup_globals(env);
        return JNI_FALSE;
    }

    int rcvbuf = 64 * 1024;
    setsockopt(g_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_nl local = {};
    local.nl_family = AF_NETLINK;
    if (bind(g_fd, reinterpret_cast<struct sockaddr *>(&local), sizeof(local)) < 0) {
        LOGE("startListening: bind() failed: %s", strerror(errno));
        cleanup_globals(env);
        return JNI_FALSE;
    }

    /* Resolve genl family and join multicast group */
    if (resolveFamily() < 0) {
        LOGE("startListening: resolveFamily failed — kernel module not loaded?");
        cleanup_globals(env);
        return JNI_FALSE;
    }

    if (g_mcast_group_id > 0) {
        if (setsockopt(g_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                       &g_mcast_group_id, sizeof(g_mcast_group_id)) < 0) {
            LOGE("startListening: NETLINK_ADD_MEMBERSHIP failed: %s", strerror(errno));
            cleanup_globals(env);
            return JNI_FALSE;
        }
    }

    /* Start receive thread */
    g_running.store(true);
    if (pthread_create(&g_thread, nullptr, recv_thread, nullptr) != 0) {
        LOGE("startListening: pthread_create failed: %s", strerror(errno));
        cleanup_globals(env);
        return JNI_FALSE;
    }

    LOGI("startListening: started (family_id=%u)", g_family_id);
    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_cn_myflv_kernel_ReKernelX_stopListening(
        JNIEnv *env, jclass /* clazz */) {
    if (!g_running.load())
        return;
    LOGI("stopListening: stopping...");
    cleanup_globals(env);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_cn_myflv_kernel_ReKernelX_addMonitorNet(
        JNIEnv *env, jclass /* clazz */, jint uid) {
    if (!g_running.load() || g_family_id == 0)
        return JNI_FALSE;
    return sendCommand(REKERNEL_X_C_ADD_MONITOR_NET, static_cast<uint32_t>(uid)) == 0
           ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_cn_myflv_kernel_ReKernelX_delMonitorNet(
        JNIEnv *env, jclass /* clazz */, jint uid) {
    if (!g_running.load() || g_family_id == 0)
        return JNI_FALSE;
    return sendCommand(REKERNEL_X_C_DEL_MONITOR_NET, static_cast<uint32_t>(uid)) == 0
           ? JNI_TRUE : JNI_FALSE;
}
