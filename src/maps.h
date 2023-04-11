#pragma once

#include <linux/if_link.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <errno.h>

#include <arpa/inet.h>

#include "define_libxdp.h"

#include "utils.h"

typedef struct xdp_maps
{
    int connections;
    int connection_stats;
    int port_punch;
    int a2s_info;
    int outgoing;
    int edge_ip;
    int stats;
    int xdp_conf;
    int white_list;
    int black_list;
    int validated_clients;
    int xsks_map;
} xdp_maps_t;

#include "config.h"

//#define PORTPUNCH_DEBUG

int maps_pin(struct xdp_program *prog, const char *path);
int maps_unpin(struct xdp_program *prog, const char *path);
void maps_get(struct xdp_program *prog, xdp_maps_t *xdp_maps);
int maps_insert_edge_ip(config_t *cfg, xdp_maps_t *xdp_maps);
int maps_insert_connection(config_t *cfg, xdp_maps_t *xdp_maps, conf_connection_t *conf_connection);
int maps_insert_xdp_config(config_t *cfg, xdp_maps_t *xdp_maps);
int maps_insert_whitelist(config_t *cfg, xdp_maps_t *xdp_maps, conf_whitelist_t *wl);
int maps_insert_blacklist(config_t *cfg, xdp_maps_t *xdp_maps, conf_blacklist_t *bl);
int maps_insert_port_punch(config_t *cfg, xdp_maps_t *xdp_maps, conf_port_punch_t *pp);
int maps_insert_validated_client(config_t *cfg, xdp_maps_t *xdp_maps, conf_validated_client_t *vc);
int maps_delete_connection(config_t *cfg, xdp_maps_t *xdp_maps, conf_connection_t *conf_connection);
int maps_delete_whitelist(config_t *cfg, xdp_maps_t *xdp_maps, conf_whitelist_t *wl);
int maps_delete_blacklist(config_t *cfg, xdp_maps_t *xdp_maps, conf_blacklist_t *bl);
int maps_delete_port_punch(config_t *cfg, xdp_maps_t *xdp_maps, conf_port_punch_t *pp);
int maps_delete_validated_client(config_t *cfg, xdp_maps_t *xdp_maps, conf_validated_client_t *vc);
void maps_calc_stats(config_t *cfg, xdp_maps_t *xdp_maps);
void maps_push_port_punches(config_t *cfg, xdp_maps_t *xdp_maps);
void maps_push_validated_connections(config_t *cfg, xdp_maps_t *xdp_maps);

#define NO_XDP
#include "xdp_prog.h"