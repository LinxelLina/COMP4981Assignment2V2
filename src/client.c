#include "client_source.h"
#include "convert.h"
#include <p101_c/p101_string.h>
#include <p101_posix/p101_unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct arguments
{
    char *ip_address;
    char *port;
};

static void           parse_arguments(const struct p101_env *env, int argc, char *argv[], struct arguments *args);
static void           check_arguments(const struct p101_env *env, const char *binary_name, const struct arguments *args);
static void           convert_arguments(const struct p101_env *env, struct p101_error *err, const struct arguments *args, struct settings *sets);
_Noreturn static void usage(const struct p101_env *env, const char *program_name, int exit_code, const char *message);

#define UNKNOWN_OPTION_MESSAGE_LEN 24

int main(int argc, char *argv[])
{
    struct p101_error *err;
    struct p101_env   *env;
    int                sockfd;
    struct arguments   args = {0};
    struct settings    sets = {0};
    int                exit_code;

    err = p101_error_create(true);
    env = p101_env_create(err, true, NULL);

    setup_signal_handler(env, err);
    parse_arguments(env, argc, argv, &args);
    check_arguments(env, argv[0], &args);
    convert_arguments(env, err, &args, &sets);
    sockfd = socket_create(sets.ip_address.ss_family, SOCK_STREAM, 0);
    if(p101_error_has_error(err))
    {
        goto error;
    }

    //    socket_connect(sockfd, &sets.ip_address, sets.port);
    socket_connect(sockfd, &sets);
    run_client(sockfd);

    exit_code = EXIT_SUCCESS;
    goto done;

error:
    fprintf(stderr, "Error: %s\n", p101_error_get_message(err));
    exit_code = EXIT_FAILURE;

done:
    p101_error_reset(err);
    free(env);
    free(err);
    socket_close(sockfd);
    return exit_code;
}

static void parse_arguments(const struct p101_env *env, int argc, char *argv[], struct arguments *args)
{
    int opt;

    P101_TRACE(env);

    opterr = 0;

    while((opt = p101_getopt(env, argc, argv, "h")) != -1)
    {
        switch(opt)
        {
            case 'h':
            {
                usage(env, argv[0], EXIT_SUCCESS, NULL);
            }
            case '?':
            {
                char message[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                usage(env, argv[0], EXIT_FAILURE, message);
            }
            default:
            {
                usage(env, argv[0], EXIT_FAILURE, NULL);
            }
        }
    }
    if(optind >= argc)
    {
        usage(env, argv[0], EXIT_FAILURE, "The ip address and port are required");
    }

    if(optind + 1 >= argc)
    {
        usage(env, argv[0], EXIT_FAILURE, "The port is required");
    }

    if(optind < argc - 2)
    {
        usage(env, argv[0], EXIT_FAILURE, "Error: Too many arguments.");
    }

    args->ip_address = argv[optind];
    args->port       = argv[optind + 1];
}

static void check_arguments(const struct p101_env *env, const char *binary_name, const struct arguments *args)
{
    P101_TRACE(env);
    if(args->ip_address == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The ip address is required.");
    }

    if(args->port == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The port is required.");
    }
}

static void convert_arguments(const struct p101_env *env, struct p101_error *error, const struct arguments *args, struct settings *sets)
{
    P101_TRACE(env);

    if(p101_error_has_error(error))
    {
        goto done;
    }

    convert_address(env, error, args->ip_address, &sets->ip_address);

    if(p101_error_has_error(error))
    {
        goto done;
    }

    sets->port = parse_in_port_t(env, error, args->port);

    if(p101_error_has_error(error))
    {
        goto done;
    }

done:
    return;
}

_Noreturn static void usage(const struct p101_env *env, const char *program_name, int exit_code, const char *message)
{
    P101_TRACE(env);

    if(message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] <ip address> <port> \n", program_name);
    fputs("Options:\n", stderr);
    fputs("  -h Display this help message\n", stderr);
    fputs(" <ip address> the ip address\n", stderr);
    fputs(" <port> the port number\n", stderr);

    exit(exit_code);
}
