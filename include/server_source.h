#ifndef COMP4981ASSIGNMENT2V2_SERVER_SOURCE_H
#define COMP4981ASSIGNMENT2V2_SERVER_SOURCE_H

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

void run_server(const struct p101_env *env, struct p101_error *err, struct settings *sets);

#endif    // COMP4981ASSIGNMENT2V2_SERVER_SOURCE_H
