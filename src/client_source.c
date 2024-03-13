#include "client_source.h"
#include <arpa/inet.h>
#include <p101_c/p101_string.h>
#include <p101_c/p101_time.h>
#include <p101_fsm/fsm.h>
#include <p101_posix/p101_signal.h>
#include <p101_posix/p101_unistd.h>
#include <p101_posix/sys/p101_socket.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static void sigint_handler(int signum);
// static void handle_connection(const struct p101_env *env, struct p101_error *err, void *arg);
#define LEN 1024
static volatile sig_atomic_t exit_flag = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

void setup_signal_handler(const struct p101_env *env, struct p101_error *err)
{
    struct sigaction sa;

    P101_TRACE(env);
    p101_memset(env, &sa, 0, sizeof(sa));

#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    sa.sa_handler = sigint_handler;
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    p101_sigaction(env, err, SIGINT, &sa, NULL);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

// TODO: actually add this to the FSM
static void sigint_handler(const int signum)
{
    exit_flag = 1;
}

#pragma GCC diagnostic pop

int socket_create(int domain, int type, int protocol)
{
    int sockfd;

    sockfd = socket(domain, type, protocol);

    if(sockfd == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

void socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    in_port_t net_port;
    socklen_t addr_len;

    if(inet_ntop(addr->ss_family, addr->ss_family == AF_INET ? (void *)&(((struct sockaddr_in *)addr)->sin_addr) : (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr), addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Connecting to: %s:%u\n", addr_str, port);
    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        ipv4_addr->sin_port = net_port;
        addr_len            = sizeof(struct sockaddr_in);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        ipv6_addr->sin6_port = net_port;
        addr_len             = sizeof(struct sockaddr_in6);
    }
    else
    {
        fprintf(stderr, "Invalid address family: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if(connect(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        const char *msg;

        msg = strerror(errno);
        fprintf(stderr, "Error: connect (%d): %s\n", errno, msg);
        exit(EXIT_FAILURE);
    }

    printf("Connected to: %s:%u\n", addr_str, port);
}

void socket_close(int client_fd)
{
    if(close(client_fd) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}

void run_client(int sockfd)
{
    const char *temp;
    char        buffer[LEN];

    while(read(sockfd, buffer, sizeof(buffer)) > 0)
    {
        //        printf("Starting message: %s\n", buffer);
        temp = strstr(buffer, "theresstillspace");

        if(temp != NULL)
        {
            size_t msg;
            msg = (size_t)(temp - buffer);
            write(STDOUT_FILENO, buffer, msg);
            printf("\n");
            break;
        }
        write(STDOUT_FILENO, buffer, LEN);
        exit_flag = 1;
    }
    if(!exit_flag)
    {
        printf("\nEnter something:\n");
    }
    while(!exit_flag)
    {
        //        const char *temp;
        const char *word;
        //        char        buffer[LEN];
        size_t  word_len;
        ssize_t bytes_read;
        uint8_t size;
        //
        //        while(read(sockfd, buffer, sizeof(buffer)) > 0)
        //        {
        //            temp = strstr(buffer, "exittheservertheresnospace");
        //            if(temp != NULL)
        //            {
        //                size_t msg = (size_t)(temp - buffer);
        //                write(STDOUT_FILENO, buffer, msg);
        //                break;
        //            }
        //        }

        //        if(read(sockfd, &size, sizeof(uint8_t)) != 0)
        //        {
        //            read(sockfd, buffer, size);
        //            write(STDOUT_FILENO, buffer, (size_t)size);
        //        }

        // Clean everything before starting
        fflush(stdout);
        memset(buffer, '\0', LEN);

        if(fgets(buffer, sizeof(buffer), stdin) == NULL)
        {
            // Handle error or end-of-file
            if(feof(stdin))
            {
                printf("Found end of file\n");

                fflush(STDIN_FILENO);
                goto read;
            }
            break;
        }
        // Process the input
        word     = buffer;
        word_len = strlen(word);

        if(word_len > UINT8_MAX)
        {
            fprintf(stderr, "Word exceeds maximum length\n");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Write the size of the word as uint8_t

        size = (uint8_t)word_len;
        write(sockfd, &size, sizeof(uint8_t));

        // Write the word
        write(sockfd, word, word_len);
        fflush(STDIN_FILENO);
        // finished writing to server

    read:
        // READ COMPONENT
        fflush(stdout);
        memset(buffer, '\0', LEN);

        while((bytes_read = read(sockfd, buffer, sizeof(buffer))) > 0)
        {
            temp = strstr(buffer, "chloroformexitstatus");
            if(temp != NULL)
            {
                size_t msg = (size_t)(temp - buffer);
                write(STDOUT_FILENO, buffer, msg);
                break;
            }
            write(STDOUT_FILENO, buffer, (size_t)bytes_read);
        }

        memset(buffer, '\0', LEN);
    }
}
