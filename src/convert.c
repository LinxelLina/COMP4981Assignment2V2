#include "convert.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <p101_c/p101_string.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#define BASE_TEN 10

in_port_t parse_in_port_t(const struct p101_env *env, struct p101_error *error, const char *str)
{
    char     *endptr;
    uintmax_t parsed_value;

    P101_TRACE(env);
    errno        = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        P101_ERROR_RAISE_USER(error, "Error parsing in_port_t", 1);
        parsed_value = 0;
        goto done;
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        P101_ERROR_RAISE_USER(error, "Invalid characters in input.", 2);
        parsed_value = 0;
        goto done;
    }
    else
    {
        // Check if the parsed value is within the valid range for in_port_t
        if(parsed_value > UINT16_MAX)
        {
            P101_ERROR_RAISE_USER(error, "in_port_t value out of range.", 3);
            parsed_value = 0;
            goto done;
        }
    }

done:
    return (in_port_t)parsed_value;
}

void convert_address(const struct p101_env *env, struct p101_error *error, const char *address, struct sockaddr_storage *addr)
{
    P101_TRACE(env);
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        addr->ss_family = AF_INET;
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        addr->ss_family = AF_INET6;
    }
    else
    {
        P101_ERROR_RAISE_USER(error, "is not an IPv4 or an IPv6 address", 1);
    }
}
