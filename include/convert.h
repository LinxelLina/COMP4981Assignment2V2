//
// Created by linayang on 2/22/24.
//

#ifndef COMP4981ASSIGNMENT2V2_CONVERT_H
#define COMP4981ASSIGNMENT2V2_CONVERT_H

#include <netinet/in.h>
#include <p101_env/env.h>
#include <sys/socket.h>
#include <time.h>

in_port_t parse_in_port_t(const struct p101_env *env, struct p101_error *error, const char *str);
void      convert_address(const struct p101_env *env, struct p101_error *error, const char *address, struct sockaddr_storage *addr);

#endif    // COMP4981ASSIGNMENT2V2_CONVERT_H
