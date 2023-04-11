#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/resource.h>

#include <linux/if_link.h>

#include "define_libxdp.h"

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

typedef __be64 be64;
typedef __be32 be32;
typedef __be16 be16;

int utils_raise_rlimit();
struct xdp_program *utils_xdp_prog_load(const char *bpf_prog, int if_idx, int *prog_fd);
int utils_attach_xdp(int if_idx, struct xdp_program *prog, int detach, int force_mode);
unsigned int utils_cpu_cnt();
int utils_bpf_map_get_next_key_and_delete(int fd, const void *key, void *next_key, int *delete);