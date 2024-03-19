#ifndef COMP4981ASSIGNMENT2V2_CLIENT_SOURCE_H
#define COMP4981ASSIGNMENT2V2_CLIENT_SOURCE_H

#include <netinet/in.h>
#include <p101_env/env.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>

struct settings
{
    struct sockaddr_storage ip_address;
    in_port_t               port;
};

void setup_signal_handler(const struct p101_env *env, struct p101_error *err);
int  socket_create(int domain, int type, int protocol);
// void socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port);
void socket_connect(int sockfd, struct settings *set);
void socket_close(int client_fd);
void run_client(int sockfd);
#endif    // COMP4981ASSIGNMENT2V2_CLIENT_SOURCE_H
