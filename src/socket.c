#include "socket.h"

int server_sd;
struct sockaddr_un addr = {0};
socklen_t addr_len = sizeof(addr);

socket_info_t *t_info = NULL;

int client_sd;

/**
 * Creates a socket for server-side.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int socket_create()
{
    // Create the socket itself.
    server_sd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (server_sd < 0)
    {
        fprintf(stderr, "Error creating socket.\n");

        return EXIT_FAILURE;
    }

    // Unlink the current socket.
    unlink(SOCKET_PATH);

    // Prepare bind details.
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCKET_PATH);

    // Bind the socket.
    if (bind(server_sd, (struct sockaddr *)&addr, addr_len) < 0)
    {
        fprintf(stderr, "Error binding socket.\n");
        
        close(server_sd);

        return EXIT_FAILURE;
    }

    if (listen(server_sd, 64) != 0)
    {
        fprintf(stderr, "Error on socket listen.\n");

        close(server_sd);

        return EXIT_FAILURE;
    }

    // Set socket to full permissions since the socket needs that.
    chmod(SOCKET_PATH, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);

    return EXIT_SUCCESS;
}

/**
 * Closes global socket FD.
 * 
 * @return Return value of close().
**/
int socket_close()
{
    if (t_info != NULL)
    {
        free(t_info);
    }

    shutdown(server_sd, SHUT_RDWR);

    return close(server_sd);
}

int recv_timeout(int s , int timeout, char *buffer)
{
	int size_recv , total_size= 0;
	struct timeval begin , now;
	char chunk[CHUNK_SIZE];
	double timediff;
	
	//make socket non blocking
	fcntl(s, F_SETFL, O_NONBLOCK);
	
	//beginning time
	gettimeofday(&begin , NULL);
	
	while(1)
	{
		gettimeofday(&now, NULL);
		
		//time elapsed in seconds
		timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);
		
		//if you got some data, then break after timeout
		if( total_size > 0 && timediff > timeout )
		{
			break;
		}
		
		//if you got no data at all, wait a little longer, twice the timeout
		else if( timediff > timeout*2)
		{
			break;
		}
		
		memset(chunk ,0 , CHUNK_SIZE);	//clear the variable
		if((size_recv =  recv(s , chunk , CHUNK_SIZE , 0) ) < 0)
		{
			//if nothing was received then we want to wait a little before trying again, 0.1 seconds
			usleep(100000);
		}
		else
		{
			total_size += size_recv;
            
			//reset beginning time
			gettimeofday(&begin , NULL);
		}
	}
	
	return total_size;
}

/**
 * Accepts and reads new connections.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the XDP maps structure.
 * 
 * Void
**/
static void socket_accept_and_read(config_t *cfg, xdp_maps_t *xdp_maps)
{
    int new_sock_fd;

    if ((new_sock_fd = accept(server_sd, NULL, NULL)) < 0)
    {
        fprintf(stdout, "Could not accept new connection :: %s.\n", strerror(errno));

        return;
    }

    client_sd = new_sock_fd;

    u16 seg_cnt = 1;

    char buffer[MAX_BUFFER_LEN];
    char *full = (char *)malloc(MAX_BUFFER_LEN * sizeof(char));

    if (full == NULL)
    {
        fprintf(stderr, "socket_accept_and_read() :: Failed to allocate full buffer.\n");

        return;
    }

    // Variables for retrieving data.
    ssize_t len = 0;
    ssize_t tot = 0;
    ssize_t seg_len = 0;
    u32 full_idx = 0;

    while (1)
    {
        // Set buffer to 0.
        memset(buffer, 0, MAX_BUFFER_LEN);

        // Read until we have a new line.
        len = recv(client_sd, buffer, MAX_BUFFER_LEN, 0);

        tot += len;
        seg_len += len;

        // Check if we need to reallocate.
        if (seg_len >= MAX_BUFFER_LEN)
        {
            seg_cnt++;
            seg_len = 0;

            full = (char *)realloc(full, MAX_BUFFER_LEN * (seg_cnt * 2));

            if (full == NULL)
            {
                fprintf(stderr, "socket_accept_and_read() :: Error reallocating full message on full.\n");
                
                break;
            }
        }

        // Check where it ends.
        u16 copy_len = len;
        u8 ends = 0;

        void *start_loc = (void *)buffer;
        char *end_loc = NULL;

        // Check if we found end of message (new line).
        end_loc = strstr(buffer, "\n");

        // If end location is true, we send the message and reset.
        if (end_loc != NULL)
        {
            copy_len = (u16)((void *)end_loc - start_loc);
            ends = 1;
        }

        // Copy data to full allocation.
        memcpy((full + full_idx), buffer, copy_len);

        full_idx += copy_len;

        if (ends)
        {
            char *new_data = strndup(full, (tot - len) + copy_len);

            if (new_data != NULL)
            {
                // Parse message.
                config_parse_json((const char *)new_data, cfg, xdp_maps);

                // Free the new data.
                free(new_data);
            }

            // Reset everything.
            tot = 0;
            seg_cnt = 1;
            seg_len = 0;
            full_idx = 0;

            full = (char *)realloc(full, MAX_BUFFER_LEN * seg_cnt);
            memset(full, 0, MAX_BUFFER_LEN * seg_cnt);

            if (full == NULL)
            {
                fprintf(stderr, "socket_accept_and_read() :: Error reallocating full message after done.\n");

                break;
            }

            // If there's nothing else, just continue.
            if (copy_len >= (len - 1))
            {
                continue;
            }

            // If we have more data, add to full message.
            size_t len_remaining = len - copy_len;
            tot += len_remaining;
            seg_len += len_remaining;
            full_idx += len_remaining;

            memcpy(full, &buffer[copy_len + 1], len_remaining - 1);
        }

        // Make sure we don't exceed.
        if (tot > MAX_TOTAL)
        {
            tot = 0;
            seg_cnt = 1;
            seg_len = 0;
            full_idx = 0;

            full = (char *)realloc(full, MAX_BUFFER_LEN * seg_cnt);
            memset(full, 0, MAX_BUFFER_LEN * seg_cnt);

            if (full == NULL)
            {
                fprintf(stderr, "socket_accept_and_read() :: Error reallocating full message being too large.\n");

                break;
            }

            continue;
        }

        // Check for errors.
        if (len == 0)
        {
            fprintf(stdout, "Failed to read buffer...\n");

            break;
        }
        else if (len == -1)
        {
            fprintf(stderr, "Error reading data to socket.\n");

            break;
        }
    }

    // Free full message.
    free(full);

    close(client_sd);

    respin:
    socket_accept_and_read(cfg, xdp_maps);
}

/**
 * Sends messages.
 * 
 * @param cfg A pointer to the config structure.
 * @param data Data to send
 * 
 * @return Amount of bytes sent.
**/
int socket_send(config_t *cfg, const char *data, size_t len)
{
    if (client_sd < 1)
    {
        return -44;
    }

    return send(client_sd, data, len, 0);
}

/**
 * PThread handle.
 * 
 * @param data Invalid data.
 * 
 * Void
**/
void *pthread_handle(void *data)
{
    while (1)
    {
        socket_accept_and_read(t_info->cfg, t_info->xdp_maps);
    }

    pthread_exit(NULL);
}

/**
 * Creates a separate pthread and accepts incoming connections.
 * 
 * @param cfg Pointer to config structure.
 * @param xdp_maps Pointer to XDP maps structure.
 * 
 * Void
**/
void socket_listen(config_t *cfg, xdp_maps_t *xdp_maps)
{
    pthread_t pid;

    t_info = malloc(sizeof(socket_info_t));
    t_info->cfg = cfg;
    t_info->xdp_maps = xdp_maps;

    pthread_create(&pid, NULL, pthread_handle, NULL);
}