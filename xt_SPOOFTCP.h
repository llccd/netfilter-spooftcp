#ifndef _XT_SPOOFTCP_TARGET_H
#define _XT_SPOOFTCP_TARGET_H

#include <linux/types.h>

struct xt_spooftcp_info {
    __u8 ttl;
    __u8 tcp_flags;
    __u8 delay;
    __u8 payload_len;
    __u8 corrupt_chksum:1;
    __u8 corrupt_seq:1;
    __u8 corrupt_ack:1;
    __u8 md5:1;
    __u8 ts:1;
    __u8 masq:1;
};

/* MD5 option */
#define OPT_MD5_KIND 19
#define OPT_MD5_SIZE 18

/* TS option */
#define OPT_TS_KIND 8
#define OPT_TS_SIZE 10

#endif /* _XT_SPOOFTCP_TARGET_H */
