#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>
#include <signal.h>
#include <error.h>
#include <errno.h>
#include <string.h>

#include <sys/resource.h>

#include <linux/if_link.h>
#include <net/if.h>

#include "cmd_line.h"
#include "config.h"
#include "maps.h"
#include "utils.h"
#include "socket.h"
#include "af_xdp.h"
#include "kilimanjaro.h"

#include "define_libxdp.h"

#define VERSION "1.0.0"

#define BPF_PIN_DIR "/sys/fs/bpf/kilimanjaro"

extern volatile int stop;