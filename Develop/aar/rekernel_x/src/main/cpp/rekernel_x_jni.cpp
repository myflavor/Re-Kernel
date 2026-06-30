/* ReKernelX JNI — Generic Netlink client for ReKernel-X LKM.
 *
 * Threading model: the user drives the lifecycle from Java.
 *   setCallback(cb)            — install the business-event callback
 *   connect()                  — non-blocking: build socket, resolve family,
 *                                join multicast. Returns success.
 *   pollEvent()                — BLOCKS on the calling (Java) thread, dispatching
 *                                events until the connection drops. Returning
 *                                means "disconnected".
 *   disconnect()               — call from ANOTHER thread to close the socket,
 *                                which wakes pollEvent() out of recv and makes
 *                                it return.
 *   addMonitorNet / delMonitorNet
 *
 * No native thread, no condition_variable, no eventfd. The JNIEnv used inside
 * pollEvent() is the caller's own, so no AttachCurrentThread is needed.
 *
 * Constraints (documented for users):
 *  - The callback implementation MUST NOT call connect/disconnect/pollEvent —
 *    it runs on the poll thread and would self-deadlock.
 *  - disconnect() MUST be called from a thread other than the one blocked in
 *    pollEvent() (typically the thread that called connect()).
 *  - addMonitorNet/delMonitorNet may be called from any thread while polling.
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

/* genl family metadata */
#define REKERNEL_X_GENL_FAMILY_NAME   "rekernel_x"
#define REKERNEL_X_GENL_MCGRP_NAME    "events"
#define REKERNEL_X_GENL_VERSION       1
#define REKERNEL_X_RPC_NAME_LEN       140

#include "rekernel_x_nla.h"

/* ==========================================================================
 *  Global JNI state
 * ========================================================================== */

static JavaVM           *g_jvm        = nullptr;
static jobject           g_callback   = nullptr;
static jclass            g_cbClass    = nullptr;
static jmethodID         g_mid_binder = nullptr;
static jmethodID         g_mid_signal = nullptr;
static jmethodID         g_mid_network= nullptr;

static int               g_fd          = -1;
static std::atomic<uint16_t> g_family_id{0};
static uint32_t          g_mcast_group_id = 0;
static std::atomic<uint32_t> g_seq{1};
/* Guards g_fd against concurrent close (disconnect) / sendto (monitor nets)
 * / recv (pollEvent). std::mutex is non-recursive — never hold it across a
 * Java callback (CallVoidMethod), or a callback that (incorrectly) calls back
 * into us would self-deadlock. Recv takes it only around the recvfrom() call. */
static std::mutex        g_fd_mutex;

/* ==========================================================================
 *  Netlink socket helpers
 * ========================================================================== */

static int nl_sendto_locked(const void *buf, size_t len) {
    struct sockaddr_nl dst = {};
    dst.nl_family = AF_NETLINK;
    ssize_t n = sendto(g_fd, buf, len, 0,
                       reinterpret_cast<struct sockaddr *>(&dst), sizeof(dst));
    return (n == static_cast<ssize_t>(len)) ? 0 : -1;
}

static int nl_recv_locked(void *buf, size_t bufsize) {
    struct sockaddr_nl src = {};
    socklen_t addrlen = sizeof(src);
    ssize_t n = recvfrom(g_fd, buf, bufsize, 0,
                         reinterpret_cast<struct sockaddr *>(&src), &addrlen);
    return static_cast<int>(n);
}

/* ==========================================================================
 *  genl family resolution
 * ========================================================================== */

/* Find the multicast group ID matching target_name inside CTRL_ATTR_MCAST_GROUPS. */
static uint32_t find_mcast_group_id(struct nlattr *mcast_attr,
                                    const char *target_name) {
    int pos = 0;
    int end = nla_datalen(mcast_attr);
    auto *base = static_cast<uint8_t *>(nla_data(mcast_attr));

    NLA_FOR_EACH_ATTR(pos, end, base) {
        auto *group = static_cast<uint8_t *>(nla_data(nla));
        int gpos = 0, gend = nla_datalen(nla);
        char grp_name[64] = {};
        uint32_t grp_id = 0;
        bool have_name = false, have_id = false;

        NLA_FOR_EACH_ATTR(gpos, gend, group) {
            int type = nla->nla_type & NLA_TYPE_MASK;
            if (type == CTRL_ATTR_MCAST_GRP_NAME && nla_datalen(nla) > 0) {
                int slen = nla_datalen(nla);
                if (slen > 63) slen = 63;
                memcpy(grp_name, nla_data(nla), slen);
                grp_name[slen] = '\0';
                have_name = true;
            } else if (type == CTRL_ATTR_MCAST_GRP_ID && nla_datalen(nla) >= 4) {
                grp_id = *static_cast<uint32_t *>(nla_data(nla));
                have_id = true;
            }
        }
        if (have_name && have_id && strcmp(grp_name, target_name) == 0)
            return grp_id;
    }
    return 0;
}

/* Send CTRL_CMD_GETFAMILY, parse reply into g_family_id / g_mcast_group_id.
 * Caller must hold g_fd_mutex (protects g_fd during sendto/recvfrom). */
static int resolveFamily_locked() {
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

    /* 3s recv timeout for this one-shot reply. */
    struct timeval rcvto = {3, 0};
    setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));

    if (nl_sendto_locked(buf, total) < 0) {
        LOGE("resolveFamily: sendto failed: %s", strerror(errno));
        return -1;
    }

    uint8_t reply[4096];
    int rlen = nl_recv_locked(reply, sizeof(reply));

    /* Back to blocking — steady-state wake is via close() in disconnect(). */
    struct timeval blockto = {0, 0};
    setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &blockto, sizeof(blockto));

    if (rlen < 0) {
        LOGE("resolveFamily: recv failed: %s", strerror(errno));
        return -1;
    }
    if (rlen < static_cast<int>(NLMSG_HDRLEN)) {
        LOGE("resolveFamily: reply too short (%d bytes)", rlen);
        return -1;
    }

    auto *rnlh = reinterpret_cast<struct nlmsghdr *>(reply);
    if (rnlh->nlmsg_type == NLMSG_ERROR) {
        LOGE("resolveFamily: got NLMSG_ERROR");
        return -1;
    }

    uint16_t fid = 0;
    uint32_t gid = 0;
    bool have_fid = false;

    int pos = NLMSG_HDRLEN + GENL_HDRLEN;
    /* Trust the smaller of declared length and actually-received bytes, so a
     * malformed nlmsg_len can't make us walk past the buffer. */
    int end = static_cast<int>(rnlh->nlmsg_len);
    if (end > rlen)
        end = rlen;

    NLA_FOR_EACH_ATTR(pos, end, reply) {
        int type = nla->nla_type & NLA_TYPE_MASK;

        if (type == CTRL_ATTR_FAMILY_ID && nla_datalen(nla) >= 2) {
            fid = *static_cast<uint16_t *>(nla_data(nla));
            have_fid = true;
        } else if (type == CTRL_ATTR_MCAST_GROUPS) {
            gid = find_mcast_group_id(nla, REKERNEL_X_GENL_MCGRP_NAME);
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

    g_family_id.store(fid);
    g_mcast_group_id = gid;
    LOGI("resolveFamily: family_id=%u mcast_group_id=%u", g_family_id.load(), g_mcast_group_id);
    return 0;
}

/* ==========================================================================
 *  Event dispatch
 * ========================================================================== */

static void dispatch_event(JNIEnv *env, uint8_t event_type, struct nlattr *payload_attr) {
    /* Snapshot the callback + methodIDs under g_fd_mutex so a concurrent
     * setCallback() (which DeleteGlobalRef's the old g_callback) can't free
     * the object out from under us mid-call. The local ref is private to
     * this thread, so the global ref may be released afterwards safely.
     * MethodIDs are stable for the lifetime of the class, so a plain copy
     * suffices. Lock is NOT held across CallVoidMethod — see g_fd_mutex note. */
    jobject cb;
    jmethodID mid_binder, mid_signal, mid_network;
    {
        std::lock_guard<std::mutex> lock(g_fd_mutex);
        if (!g_callback || !g_cbClass)
            return;
        cb           = env->NewLocalRef(g_callback);
        mid_binder   = g_mid_binder;
        mid_signal   = g_mid_signal;
        mid_network  = g_mid_network;
    }
    if (!cb)
        return;

    switch (event_type) {
        case REKERNEL_X_EVT_BINDER: {
            int bpos = 0, bend = nla_datalen(payload_attr);
            auto *bbase = static_cast<uint8_t *>(nla_data(payload_attr));
            int32_t  binder_type = 0, oneway = 0, from_pid = 0, target_pid = 0, code = 0;
            uint32_t from_uid = 0, target_uid = 0;
            char rpc_name[REKERNEL_X_RPC_NAME_LEN + 1] = {};

            NLA_FOR_EACH_ATTR(bpos, bend, bbase) {
                int btype = nla->nla_type & NLA_TYPE_MASK;
                switch (btype) {
                    case REKERNEL_X_A_BINDER_TYPE:     nla_get<int32_t>(nla, binder_type); break;
                    case REKERNEL_X_A_BINDER_ONEWAY:   nla_get<int32_t>(nla, oneway); break;
                    case REKERNEL_X_A_BINDER_FROM_PID: nla_get<int32_t>(nla, from_pid); break;
                    case REKERNEL_X_A_BINDER_FROM_UID: nla_get<uint32_t>(nla, from_uid); break;
                    case REKERNEL_X_A_BINDER_TARGET_PID: nla_get<int32_t>(nla, target_pid); break;
                    case REKERNEL_X_A_BINDER_TARGET_UID: nla_get<uint32_t>(nla, target_uid); break;
                    case REKERNEL_X_A_BINDER_CODE:     nla_get<int32_t>(nla, code); break;
                    case REKERNEL_X_A_BINDER_RPC_NAME: {
                        int slen = nla_datalen(nla);
                        if (slen > REKERNEL_X_RPC_NAME_LEN) slen = REKERNEL_X_RPC_NAME_LEN;
                        memcpy(rpc_name, nla_data(nla), slen);
                        rpc_name[slen] = '\0';
                        break;
                    }
                }
            }

            jstring jRpcName = env->NewStringUTF(rpc_name);
            env->CallVoidMethod(cb, mid_binder,
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

            NLA_FOR_EACH_ATTR(spos, send, sbase) {
                int stype = nla->nla_type & NLA_TYPE_MASK;
                switch (stype) {
                    case REKERNEL_X_A_SIGNAL_SIGNAL:     nla_get<int32_t>(nla, sig); break;
                    case REKERNEL_X_A_SIGNAL_KILLER_PID: nla_get<int32_t>(nla, killer_pid); break;
                    case REKERNEL_X_A_SIGNAL_KILLER_UID: nla_get<uint32_t>(nla, killer_uid); break;
                    case REKERNEL_X_A_SIGNAL_DST_PID:    nla_get<int32_t>(nla, dst_pid); break;
                    case REKERNEL_X_A_SIGNAL_DST_UID:    nla_get<uint32_t>(nla, dst_uid); break;
                }
            }

            env->CallVoidMethod(cb, mid_signal,
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

            NLA_FOR_EACH_ATTR(npos, nend, nbase) {
                int ntype = nla->nla_type & NLA_TYPE_MASK;
                switch (ntype) {
                    case REKERNEL_X_A_NETWORK_PROTO:      nla_get<int32_t>(nla, proto); break;
                    case REKERNEL_X_A_NETWORK_TARGET_UID: nla_get<uint32_t>(nla, target_uid); break;
                    case REKERNEL_X_A_NETWORK_DATA_LEN:   nla_get<int32_t>(nla, data_len); break;
                }
            }

            env->CallVoidMethod(cb, mid_network,
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

    env->DeleteLocalRef(cb);
}

/* ==========================================================================
 *  JNI lifecycle
 * ========================================================================== */

extern "C" JNIEXPORT void JNICALL
Java_cn_myflv_kernel_ReKernelX_setCallback(
        JNIEnv *env, jclass /* clazz */, jobject callback) {
    /* Prepare everything off the lock: JNI calls (FindClass/NewGlobalRef/
     * GetMethodID) can be slow and must not be held under g_fd_mutex. If
     * preparation fails, the previously installed callback is left intact. */
    jobject new_cb    = nullptr;
    jclass  new_class = nullptr;
    jmethodID new_binder = nullptr, new_signal = nullptr, new_network = nullptr;

    if (callback) {
        env->GetJavaVM(&g_jvm);

        jclass cls = env->FindClass("cn/myflv/kernel/ReKernelXCallback");
        if (!cls) {
            LOGE("setCallback: FindClass failed");
            return;
        }
        new_class = reinterpret_cast<jclass>(env->NewGlobalRef(cls));
        env->DeleteLocalRef(cls);

        new_binder  = env->GetMethodID(new_class, "binder",
            "(IIIIIILjava/lang/String;I)V");
        new_signal  = env->GetMethodID(new_class, "signal",  "(IIIII)V");
        new_network = env->GetMethodID(new_class, "network", "(III)V");

        if (!new_binder || !new_signal || !new_network) {
            LOGE("setCallback: GetMethodID failed");
            env->DeleteGlobalRef(new_class);
            return;
        }
        new_cb = env->NewGlobalRef(callback);
    }

    /* Swap under the lock: release the old refs, publish the new ones. This
     * is the only window that races with dispatch_event()'s snapshot, and the
     * critical section is just pointer assignments + DeleteGlobalRef. */
    jobject old_cb    = nullptr;
    jclass  old_class = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_fd_mutex);
        old_cb        = g_callback;
        old_class     = g_cbClass;
        g_callback    = new_cb;
        g_cbClass     = new_class;
        g_mid_binder  = new_binder;
        g_mid_signal  = new_signal;
        g_mid_network = new_network;
    }

    if (old_cb)
        env->DeleteGlobalRef(old_cb);
    if (old_class)
        env->DeleteGlobalRef(old_class);
}

/* Non-blocking: build socket, resolve family, join multicast. Returns true on
 * success. Safe to call again after disconnect(). */
extern "C" JNIEXPORT jboolean JNICALL
Java_cn_myflv_kernel_ReKernelX_connect(
        JNIEnv * /* env */, jclass /* clazz */) {

    std::lock_guard<std::mutex> lock(g_fd_mutex);

    if (g_fd >= 0) {
        LOGI("connect: already connected");
        return JNI_TRUE;
    }

    g_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
    if (g_fd < 0) {
        LOGE("connect: socket() failed: %s", strerror(errno));
        return JNI_FALSE;
    }

    int rcvbuf = 64 * 1024;
    setsockopt(g_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_nl local = {};
    local.nl_family = AF_NETLINK;
    if (bind(g_fd, reinterpret_cast<struct sockaddr *>(&local), sizeof(local)) < 0) {
        LOGE("connect: bind() failed: %s", strerror(errno));
        close(g_fd); g_fd = -1;
        return JNI_FALSE;
    }

    if (resolveFamily_locked() < 0) {
        LOGE("connect: resolveFamily failed — kernel module not loaded?");
        close(g_fd); g_fd = -1;
        return JNI_FALSE;
    }

    if (g_mcast_group_id > 0) {
        if (setsockopt(g_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                       &g_mcast_group_id, sizeof(g_mcast_group_id)) < 0) {
            LOGE("connect: NETLINK_ADD_MEMBERSHIP failed: %s", strerror(errno));
            close(g_fd); g_fd = -1;
            return JNI_FALSE;
        }
    }

    LOGI("connect: connected (family_id=%u)", g_family_id.load());
    return JNI_TRUE;
}

/* BLOCKS the calling thread. Receives and dispatches events until the socket
 * is closed (by disconnect() from another thread) or hits a recv error, then
 * returns. Returning == "disconnected". */
extern "C" JNIEXPORT void JNICALL
Java_cn_myflv_kernel_ReKernelX_pollEvent(
        JNIEnv *env, jclass /* clazz */) {

    uint8_t rbuf[8192];

    for (;;) {
        int rlen;
        {
            std::lock_guard<std::mutex> lock(g_fd_mutex);
            if (g_fd < 0)
                break;  /* torn down by disconnect() */
            rlen = nl_recv_locked(rbuf, sizeof(rbuf));
        }
        /* Lock released before dispatching — never hold g_fd_mutex across a
         * Java callback. */

        if (rlen < 0) {
            /* EINTR is transient (signal). Anything else (EBADF from close(),
             * EAGAIN, ENOBUFS) ends the loop — the caller treats return as
             * "disconnected". */
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS)
                LOGE("pollEvent: recv error: %s", strerror(errno));
            break;
        }
        if (rlen == 0)
            continue;

        for (auto *nlh = reinterpret_cast<struct nlmsghdr *>(rbuf);
             NLMSG_OK(nlh, static_cast<size_t>(rlen));
             nlh = NLMSG_NEXT(nlh, rlen)) {

            if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_DONE)
                continue;
            if (nlh->nlmsg_type != g_family_id.load())
                continue;
            if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
                continue;

            auto *ghdr = reinterpret_cast<struct genlmsghdr *>(
                reinterpret_cast<uint8_t *>(nlh) + NLMSG_HDRLEN);
            if (ghdr->cmd != REKERNEL_X_C_EVENT)
                continue;

            int pos = NLMSG_HDRLEN + GENL_HDRLEN;
            int end = static_cast<int>(nlh->nlmsg_len);

            NLA_FOR_EACH_ATTR(pos, end, reinterpret_cast<uint8_t *>(nlh)) {
                int atype = nla->nla_type & NLA_TYPE_MASK;
                if (atype != REKERNEL_X_A_EVENT || nla_datalen(nla) < NLA_HDRLEN)
                    continue;

                int epos = 0, eend = nla_datalen(nla);
                auto *ebase = static_cast<uint8_t *>(nla_data(nla));
                uint8_t event_type = 0;
                struct nlattr *payload_attr = nullptr;

                NLA_FOR_EACH_ATTR(epos, eend, ebase) {
                    int etype = nla->nla_type & NLA_TYPE_MASK;
                    if (etype == REKERNEL_X_A_EVENT_TYPE && nla_datalen(nla) >= 1) {
                        event_type = *static_cast<uint8_t *>(nla_data(nla));
                    } else if (etype == REKERNEL_X_A_BINDER ||
                               etype == REKERNEL_X_A_SIGNAL ||
                               etype == REKERNEL_X_A_NETWORK) {
                        payload_attr = nla;
                    }
                }

                if (event_type > 0 && payload_attr) {
                    dispatch_event(env, event_type, payload_attr);
                }
            }
        }
    }

    /* Tear down the fd if it's still open (recv error path). A clean
     * disconnect() already closed it. */
    {
        std::lock_guard<std::mutex> lock(g_fd_mutex);
        if (g_fd >= 0) {
            close(g_fd);
            g_fd = -1;
        }
    }

    LOGI("pollEvent: disconnected, returning");
}

/* Call from ANOTHER thread (not the one in pollEvent()) to close the socket
 * and wake pollEvent() out of its blocking recv. */
extern "C" JNIEXPORT void JNICALL
Java_cn_myflv_kernel_ReKernelX_disconnect(
        JNIEnv * /* env */, jclass /* clazz */) {
    std::lock_guard<std::mutex> lock(g_fd_mutex);
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_cn_myflv_kernel_ReKernelX_addMonitorNet(
        JNIEnv * /* env */, jclass /* clazz */, jint uid) {
    if (g_family_id.load() == 0 || g_fd < 0)
        return JNI_FALSE;
    std::lock_guard<std::mutex> lock(g_fd_mutex);
    uint8_t buf[128];
    NlaBuilder b(buf, sizeof(buf));
    b.putGenlHeader(g_family_id.load(), REKERNEL_X_C_ADD_MONITOR_NET,
                    g_seq.fetch_add(1), REKERNEL_X_GENL_VERSION);
    b.putU32(REKERNEL_X_A_UID, static_cast<uint32_t>(uid));
    return nl_sendto_locked(buf, b.finish()) == 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_cn_myflv_kernel_ReKernelX_delMonitorNet(
        JNIEnv * /* env */, jclass /* clazz */, jint uid) {
    if (g_family_id.load() == 0 || g_fd < 0)
        return JNI_FALSE;
    std::lock_guard<std::mutex> lock(g_fd_mutex);
    uint8_t buf[128];
    NlaBuilder b(buf, sizeof(buf));
    b.putGenlHeader(g_family_id.load(), REKERNEL_X_C_DEL_MONITOR_NET,
                    g_seq.fetch_add(1), REKERNEL_X_GENL_VERSION);
    b.putU32(REKERNEL_X_A_UID, static_cast<uint32_t>(uid));
    return nl_sendto_locked(buf, b.finish()) == 0 ? JNI_TRUE : JNI_FALSE;
}
