/* NLA (NetLink Attribute) helpers — mirror the kernel's nla_ok/nla_for_each
 * and nla_put_*. Header-only so they can be shared across translation units.
 * Both reading (NLA_FOR_EACH_ATTR / nla_data / nla_datalen) and writing
 * (NlaBuilder) are provided here. */
#ifndef REKERNEL_X_NLA_H
#define REKERNEL_X_NLA_H

#include <cstring>
#include <cstdint>
#include <linux/netlink.h>
#include <linux/genetlink.h>

static inline uint16_t nla_align(uint16_t len) {
    return (len + 3) & ~3;
}

/* Iterate NLA attributes in [pos, end). Whole attr (hdr+payload) must fit.
 * Usage: NLA_FOR_EACH_ATTR(pos, end, buf) { ... use `nla` ... }
 * `nla` is declared by the macro and points at the current nlattr. */
#define NLA_FOR_EACH_ATTR(pos, end, buf) \
    for (auto *nla = reinterpret_cast<struct nlattr *>(buf + (pos)); \
         (pos) + NLA_HDRLEN <= (end) && (nla)->nla_len >= NLA_HDRLEN && \
         (pos) + (nla)->nla_len <= (end); \
         (pos) += nla_align((nla)->nla_len), \
         nla = reinterpret_cast<struct nlattr *>(buf + (pos)))

static inline void *nla_data(struct nlattr *nla) {
    return reinterpret_cast<uint8_t *>(nla) + NLA_HDRLEN;
}

static inline int nla_datalen(struct nlattr *nla) {
    return nla->nla_len - NLA_HDRLEN;
}

/* Read a fixed-size scalar from an NLA attribute into `out`. Returns false
 * (leaving `out` unchanged) if the payload is too short — defensive against
 * malformed messages. Mirrors the kernel's nla_get_u32/nla_get_s32/etc. */
template<typename T>
static inline bool nla_get(struct nlattr *nla, T &out) {
    if (nla_datalen(nla) < static_cast<int>(sizeof(T)))
        return false;
    out = *static_cast<T *>(nla_data(nla));
    return true;
}

/* ---------------------------------------------------------------------------
 *  NlaBuilder — stream-style generic netlink message constructor, mirroring
 *  the kernel's nla_put_* helpers. Append as many typed attributes as needed,
 *  then finish() to publish nlmsg_len. Used for user->kernel commands.
 * --------------------------------------------------------------------------- */
class NlaBuilder {
    uint8_t *buf_;
    size_t   cap_;
    size_t   len_;   /* current used length (incl. nlmsghdr + genlmsghdr) */

    /* Append one nlattr with [data, data+datalen) payload, NLA-aligned. */
    bool put(uint16_t type, const void *data, uint16_t datalen) {
        uint16_t attr_len = NLA_HDRLEN + datalen;
        uint16_t aligned  = nla_align(attr_len);
        if (len_ + aligned > cap_)
            return false;
        auto *nla = reinterpret_cast<struct nlattr *>(buf_ + len_);
        nla->nla_len  = attr_len;
        nla->nla_type = type;
        if (datalen)
            memcpy(reinterpret_cast<uint8_t *>(nla) + NLA_HDRLEN, data, datalen);
        /* zero the alignment padding so we don't leak stack bytes */
        if (aligned > attr_len)
            memset(buf_ + len_ + attr_len, 0, aligned - attr_len);
        len_ += aligned;
        return true;
    }

public:
    NlaBuilder(uint8_t *buf, size_t cap)
        : buf_(buf), cap_(cap), len_(NLMSG_HDRLEN + GENL_HDRLEN) {
        memset(buf_, 0, NLMSG_HDRLEN + GENL_HDRLEN);
    }

    /* Lay down the nlmsghdr + genlmsghdr. Attributes are appended after. */
    void putGenlHeader(uint16_t family, uint8_t cmd, uint32_t seq,
                       uint8_t version) {
        auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf_);
        nlh->nlmsg_len   = 0;           /* finalised by finish() */
        nlh->nlmsg_type  = family;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq   = seq;
        nlh->nlmsg_pid   = 0;

        auto *ghdr = reinterpret_cast<struct genlmsghdr *>(buf_ + NLMSG_HDRLEN);
        ghdr->cmd     = cmd;
        ghdr->version  = version;
        ghdr->reserved = 0;
    }

    bool putU32(uint16_t type, uint32_t v)    { return put(type, &v, 4); }
    bool putS32(uint16_t type, int32_t  v)    { return put(type, &v, 4); }
    bool putU8 (uint16_t type, uint8_t  v)    { return put(type, &v, 1); }
    bool putString(uint16_t type, const char *s) {
        return put(type, s, static_cast<uint16_t>(strlen(s) + 1));
    }

    /* Publish nlmsg_len and return total message size. */
    size_t finish() {
        reinterpret_cast<struct nlmsghdr *>(buf_)->nlmsg_len =
            static_cast<uint32_t>(len_);
        return len_;
    }
};

#endif /* REKERNEL_X_NLA_H */
