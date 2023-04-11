#pragma once

#include <stdbool.h>

#ifndef LIBXDP_DEFINED
#define LIBXDP_DEFINED

#ifndef NO_LIBXDP
#include <xdp/libxdp.h>
#endif

struct xdp_program 
{
    /* one of prog or prog_fd should be set */
    struct bpf_program *bpf_prog;
    struct bpf_object *bpf_obj;
    struct btf *btf;
    int prog_fd;
    int link_fd;
    char *prog_name;
    char *attach_name;
    __u8 prog_tag[BPF_TAG_SIZE];
    __u32 prog_id;
    __u64 load_time;
    bool from_external_obj;
    unsigned int run_prio;
    unsigned int chain_call_actions; // bitmap

    /* for building list of attached programs to multiprog */
    struct xdp_program *next;
};
#endif