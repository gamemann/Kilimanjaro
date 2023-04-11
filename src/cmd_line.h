#pragma once

typedef struct cmd_line
{
    unsigned int version : 1;
    unsigned int list : 1;
    unsigned int help : 1;
} cmd_line_t;

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

void cmd_line_parse(cmd_line_t *cmd, int argc, char **argv);