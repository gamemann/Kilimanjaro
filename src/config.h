#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json.h>

#include <ifaddrs.h>

#define MAX_CLIENT_CONNECTIONS 10000
#define MAX_CLIENTS_VALIDATED 10000
#define MAX_PORT_PUNCH MAX_CLIENT_CONNECTIONS

#define MAX_WHITELIST 2048
#define MAX_BLACKLIST 2048

#define MAX_PREFIX_LEN 32

// Common settings.
#define MAX_CONNECTIONS 2048
#define MAX_TYPE_LEN 16
#define MAX_PROTOCOL_LEN 4

struct conf_rate_limit
{
    unsigned int block_time;
    unsigned long long pps;
    unsigned long long bps;
};

struct conf_syn_settings
{
    struct conf_rate_limit rl;
};

struct conf_cache_settings
{
    unsigned int A2S_INFO;
    unsigned int A2S_INFO_time;
    unsigned int A2S_INFO_global_cache;
    unsigned int A2S_INFO_cache_timeout;
};

struct conf_filter
{
    unsigned int filters;

    struct conf_rate_limit udp_rl;
    struct conf_rate_limit tcp_rl;

    struct conf_syn_settings syn_settings;
    struct conf_cache_settings cache_settings;
};

typedef struct conf_connection
{
    int is_set;
    unsigned int is_enabled;

    char *protocol;

    char *bind_ip;
    unsigned int bind_port;

    char *dest_ip;
    unsigned int dest_port;

    unsigned int filters;

    struct conf_rate_limit udp_rl;
    struct conf_rate_limit tcp_rl;
    struct conf_rate_limit icmp_rl;

    struct conf_syn_settings syn_settings;   
    struct conf_cache_settings cache_settings; 
} conf_connection_t;


typedef struct conf_whitelist
{
    int is_set;
    char prefix[MAX_PREFIX_LEN];
} conf_whitelist_t;

typedef struct conf_blacklist
{
    int is_set;
    char prefix[MAX_PREFIX_LEN];
} conf_blacklist_t;

typedef struct conf_port_punch
{
    int is_set;

    char *ip;
    unsigned short port;

    char *service_ip;
    unsigned short service_port;

    char *dest_ip;
} conf_port_punch_t;

typedef struct conf_validated_client
{
    int is_set;

    char *src_ip;
    unsigned short src_port;

    char *dst_ip;
    unsigned short dst_port;
} conf_validated_client_t;

typedef struct config
{
    char *interface;
    char *edge_ip;
    unsigned int force_mode;
    unsigned int socket_count;
    unsigned int queue_is_static : 1;
    unsigned int queue_id;
    unsigned int zero_copy : 1;
    unsigned int need_wakeup : 1;
    unsigned int batch_size;
    unsigned int verbose : 1;
    unsigned int calc_stats : 1;
    unsigned int allow_all_edge : 1;

    conf_connection_t connections[MAX_CONNECTIONS];
    conf_whitelist_t whitelist[MAX_WHITELIST];
    conf_blacklist_t blacklist[MAX_BLACKLIST];
    conf_port_punch_t port_punch[MAX_PORT_PUNCH];
    conf_validated_client_t validated_client[MAX_CLIENTS_VALIDATED];

} config_t;

#include "maps.h"
#include "socket.h"

/* Global defines */
//#define SEC_A2S_DEBUG

int config_parse(const char *file, config_t *cfg);
int config_parse_json(const char *data, config_t *cfg, xdp_maps_t *xdp_maps);
int config_parse_json_config(config_t *cfg, xdp_maps_t *xdp_maps, struct json_object *parser);
int config_parse_json_conn(config_t *cfg, struct json_object *connection, xdp_maps_t *xdp_maps, unsigned int i);
int config_parse_json_whitelist(config_t *cfg, struct json_object *whitelist, xdp_maps_t *xdp_maps, unsigned int i);
int config_parse_json_blacklist(config_t *cfg, struct json_object *blacklist, xdp_maps_t *xdp_maps, unsigned int i);
int config_parse_json_port_punch(config_t *cfg, struct json_object *port_punch, xdp_maps_t *xdp_maps, unsigned int i);
int config_parse_and_send_port_punch(config_t *cfg, char *ip, unsigned short port, char *service_ip, unsigned short service_port, char *dest_ip);
int config_parse_and_send_validated_connection(config_t *cfg, char *src_ip, unsigned short src_port, char *dst_ip, unsigned short dst_port);
int config_parse_and_send_a2s_response(config_t *cfg, const char *ip, unsigned short port, const char *resp, u64 expires);

void config_set_defaults(config_t *cfg);
void config_set_default_edge_ip(config_t *cfg);

void config_connection_wipe(conf_connection_t *connection);
void config_connection_wipe_all(config_t *cfg);
void config_connection_set_defaults(conf_connection_t *connection);
int config_connection_find_index(config_t *cfg);
conf_connection_t *config_connection_find(config_t *cfg, const char *protocol, const char *bind_ip, unsigned short bind_port);
conf_connection_t *config_connection_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_connection_t conf_connection);
int config_connection_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_connection_t conf_connection);

void config_whitelist_wipe(conf_whitelist_t *whitelist);
void config_whitelist_wipe_all(config_t *cfg);
int config_whitelist_find_index(config_t *cfg);
conf_whitelist_t *config_whitelist_find(config_t *cfg, const char *prefix);
conf_whitelist_t *config_whitelist_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_whitelist_t conf_whitelist);
int config_whitelist_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_whitelist_t conf_whitelist);

void config_blacklist_wipe(conf_blacklist_t *blacklist);
void config_blacklist_wipe_all(config_t *cfg);
int config_blacklist_find_index(config_t *cfg);
conf_blacklist_t *config_blacklist_find(config_t *cfg, const char *prefix);
conf_blacklist_t *config_blacklist_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_blacklist_t conf_blacklist);
int config_blacklist_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_blacklist_t conf_blacklist);

void config_port_punch_wipe(conf_port_punch_t *pp);
void config_port_punch_wipe_all(config_t *cfg);
int config_port_punch_find_index(config_t *cfg);
conf_port_punch_t *config_port_punch_find(config_t *cfg, const char *ip, unsigned short port, const char *service_ip, unsigned short service_port);
conf_port_punch_t *config_port_punch_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_port_punch_t conf_port_punch);
int config_port_punch_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_port_punch_t conf_port_punch);

void config_validated_client_wipe(conf_validated_client_t *pp);
void config_validated_client_wipe_all(config_t *cfg);
int config_validated_client_find_index(config_t *cfg);
conf_validated_client_t *config_validated_client_find(config_t *cfg, const char *src_ip, unsigned short src_port, const char *dst_ip, unsigned short dst_port);
conf_validated_client_t *config_validated_client_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_validated_client_t conf_validated_client);
int config_validated_client_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_validated_client_t conf_validated_client);