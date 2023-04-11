#include "cmd_line.h"

static const struct option long_opts[] =
{
    {"version", no_argument, NULL, 'v'},
    {"list", no_argument, NULL, 'l'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

/**
 * Parses command line.
 * 
 * @param cmd Pointer to command line structure.
 * @param argc Argument count.
 * @param argv Pointer to arguments array.
 * 
 * @return Void
**/
void cmd_line_parse(cmd_line_t *cmd, int argc, char **argv)
{
    int c = -1;

    while ((c = getopt_long(argc, argv, "vlh", long_opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'v':
                cmd->version = 1;

                break;

            case 'l':
                cmd->list = 1;

                break;

            case 'h':
                cmd->help = 1;

                break;
        }
    }
}