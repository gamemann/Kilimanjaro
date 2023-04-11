#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <pthread.h>

#include "config.h"
#include "maps.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

//Size of each chunk of data received, try changing this
#define CHUNK_SIZE 512

#define SOCKET_PATH "/etc/kilimanjaro/server.sock"

#define MAX_BUFFER_LEN 512
#define MAX_BUFFER_MULTI 6400
#define MAX_TOTAL (MAX_BUFFER_LEN * MAX_BUFFER_MULTI)
#define MAX_SOCKETS 32

#define BIND_PORT 8002

typedef struct socket_info
{
    config_t *cfg;
    xdp_maps_t *xdp_maps;
} socket_info_t;

int socket_create();
int socket_close();
void socket_listen(config_t *cfg, xdp_maps_t *xdp_maps);
int socket_send(config_t *cfg, const char *data, size_t len);