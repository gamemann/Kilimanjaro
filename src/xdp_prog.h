#pragma once

#include <linux/types.h>

#ifndef NO_XDP
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>
#endif

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#define NO_LIBXDP

#include "utils.h"
#include "config.h"

#include "csum.h"

#define DEFAULT_A2S_CACHE_TIME 45
#define DEFAULT_A2S_CACHE_TIMEOUT 180

#define MAX_CPUS 256
#define MAX_LIST 1024

#define MAX_UDP_SIZE 1480
#define MAX_A2S_SIZE 1024

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// Stat types.
#define STATS_TYPE_BLACKLIST 0x01
#define STATS_TYPE_WHITELIST 0x02
#define STATS_TYPE_BLOCKLIST 0x03
#define STATS_TYPE_FWD 0x04
#define STATS_TYPE_PASS 0x05
#define STATS_TYPE_BAD 0x06
#define STATS_TYPE_A2S_REPLY 0x07
#define STATS_TYPE_A2S_RESPONSE 0x08
#define STATS_TYPE_DROP_OTHER 0x09
#define STATS_TYPE_DROP_CONN 0x10
#define STATS_TYPE_FWD_OUT 0x11

// Default limits.
#define PPS_DEFAULT 3000
#define BPS_DEFAULT 25000000

// Filters.
#define FILTER_TYPE_SRCDS (1 << 0)
#define FILTER_TYPE_RUST (1 << 1)
#define FILTER_TYPE_GMOD (1 << 2)

#define FILTER_SCRDS_UDP_PPS_DEFAULT 2000
#define FILTER_SRCDS_UDP_BPS_DEFAULT 0
#define FILTER_SRCDS_TCP_PPS_DEFAULT 0
#define FILTER_SRCDS_TCP_BPS_DEFAULT 0

#define FILTER_RUST_UDP_PPS_DEFAULT 5000
#define FILTER_RUST_UDP_BPS_DEFAULT 0
#define FILTER_RUST_TCP_PPS_DEFAULT 0
#define FILTER_RUST_TCP_BPS_DEFAULT 0

#define FILTER_GMOD_UDP_PPS_DEFAULT 10000
#define FILTER_GMOD_UDP_BPS_DEFAULT 0
#define FILTER_GMOD_TCP_PPS_DEFAULT 0
#define FILTER_GMOD_TCP_BPS_DEFAULT 0

// Debug
//#define A2S_DEBUG
//#define A2SCH_DEBUG
//#define ICMP_DEBUG

#ifdef htons
#undef htons
#endif

#ifdef ntohs
#undef ntohs
#endif

#ifdef htonl
#undef htonl
#endif

#ifdef ntohl
#undef ntohl
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

struct flow
{
    be32 ip;
    be16 port;
};

struct full_flow
{
    struct flow src;
    struct flow dst;
};

struct rate_limit
{
    u16 block_time;
    u64 pps;
    u64 bps;
};

struct syn_settings
{
    struct rate_limit rl;
};

struct cache_settings
{
    unsigned int A2S_INFO : 1;
    u16 A2S_INFO_time;
    unsigned int A2S_INFO_global_cache : 1;
    u16 A2S_INFO_cache_timeout;
};

struct connection_key
{
    u8 protocol;
    struct flow bind;
};

struct connection_val
{
    be32 dest_ip;
    be16 dest_port;

    u32 filters;

    struct rate_limit udp_rl;
    struct rate_limit tcp_rl;
    struct rate_limit icmp_rl;

    struct syn_settings syn_settings;
    struct cache_settings cache_settings;
};

struct port_punch_key
{
    struct flow service;
    struct flow dest;
};

struct port_punch_val
{
    be32 dest_ip;
    u64 last_seen;
    unsigned int xdp_added : 1;
    unsigned int printed : 1;
};

struct stats_val
{
    u64 bla_pckts_total;
    u64 bla_bytes_total;

    u64 whi_pckts_total;
    u64 whi_bytes_total;

    u64 blo_pckts_total;
    u64 blo_bytes_total;

    u64 fwd_pckts_total;
    u64 fwd_bytes_total;

    u64 fwd_out_pckts_total;
    u64 fwd_out_bytes_total;

    u64 pass_pckts_total;
    u64 pass_bytes_total;

    u64 bad_pckts_total;
    u64 bad_bytes_total;

    u64 a2s_reply_pckts_total;
    u64 a2s_reply_bytes_total;

    u64 a2s_response_pckts_total;
    u64 a2s_response_bytes_total;

    u64 drop_other_pckts_total;
    u64 drop_other_bytes_total;

    u64 drop_conn_pckts_total;
    u64 drop_conn_bytes_total;
};

struct connection_stats_val
{
    u64 pckts;
    u64 pckts_lu;

    u64 bytes;
    u64 bytes_lu;
};

struct a2s_info_val
{
    u16 size;
    u64 expires;
    unsigned char data[MAX_A2S_SIZE];
    unsigned char challenge[4];
    unsigned int challenge_set : 1;
};

struct outgoing_key
{
    be32 machine_ip;
    be32 connection_ip;
};

struct lpm_trie_key 
{
    __u32 prefix_len;
    __u32 data;
};

struct xdp_config_val
{
    unsigned int allow_edge : 1;
};

struct client_connection_key
{
    struct flow src;
    struct flow dst;
};

struct client_connection_val
{
    u64 pps;
    u64 bps;
    u64 last_seen;
    u64 next_update;
    u32 flags;
};

struct client_validated_val
{
    u64 last_seen;
    unsigned int xdp_added : 1;
    unsigned int printed : 1;
};