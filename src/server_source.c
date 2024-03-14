#include "server_source.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <p101_c/p101_string.h>
#include <p101_c/p101_time.h>
#include <p101_posix/p101_signal.h>
#include <p101_posix/p101_unistd.h>
#include <p101_posix/sys/p101_socket.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>

static void  setup_signal_handler(const struct p101_env *env, struct p101_error *err);
static void  sigint_handler(int signum);
static void  socket_create(const struct p101_env *env, struct p101_error *err, void *arg);
static void  socket_bind(const struct p101_env *env, struct p101_error *err, void *arg);
static void  socket_listen(const struct p101_env *env, struct p101_error *err, void *arg);
static int   socket_accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len);
static void  socket_close(int sockfd);
static void  handle_connection(const struct p101_env *env, struct p101_error *err, void *arg, int sockfd);
static void  cleanup(const struct p101_env *env, struct p101_error *err, void *arg);
static void *run_thread(void *arg);
int          runCommand(const char *path, char *const *argument);
char        *doesExist(const char *command);
int          executeCommand(char *arg);

#define LEN 2048
#define MAX_CLIENT 3
#define NO_CONNECTION (-1)
#define CONNECTED 1
#define DONE (-1)
#define GET_ENV_TYPE "PATH"
#define FAIL_VALUE (-1)

static volatile sig_atomic_t exit_flag = 0;                // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int                   thread_status[MAX_CLIENT];    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

struct server_data
{
    struct settings *sets;
    int              server_socket;
};

struct client_data
{
    const struct p101_env *env;
    struct p101_error     *err;
    //    struct settings *sets;
    struct server_data data;
    int                client_sockfd;
    size_t             status_location;
};

void run_server(const struct p101_env *env, struct p101_error *err, struct settings *sets)
{
    struct server_data data;
    int                enable;
    struct client_data client_information[MAX_CLIENT];
    pthread_t          client_connections[MAX_CLIENT];
    int                status_connections[MAX_CLIENT];
    int                client_sockets[MAX_CLIENT];
    P101_TRACE(env);

    data.sets = sets;
    enable    = 1;
    socket_create(env, err, &data);

    // set all to not connected
    for(int i = 0; i < MAX_CLIENT; i++)
    {
        client_connections[i] = 0;
        status_connections[i] = NO_CONNECTION;
        thread_status[i]      = 0;
        client_sockets[i]     = -1;
    }

    p101_setsockopt(env, err, data.server_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    if(p101_error_has_error(err))
    {
        goto close;
    }

    socket_bind(env, err, &data);

    setup_signal_handler(env, err);

    if(p101_error_has_error(err))
    {
        goto close;
    }

    socket_listen(env, err, &data);

    while(!exit_flag)
    {
        int                     client_sockfd;
        struct client_data      clientData;
        struct sockaddr_storage client_addr;
        socklen_t               client_addr_len;
        size_t                  size;
        // when accept client, make new thread
        const char *message          = "Cannot take any more connections";
        const char *continue_message = "theresstillspace";

        client_addr_len = sizeof(client_addr);
        client_sockfd   = socket_accept_connection(data.server_socket, &client_addr, &client_addr_len);
        printf("...Client %d Connecting...", client_sockfd);
        if(client_sockfd <= 0)
        {
            perror("Failed connection with Client");
        }
        else
        {
            clientData.client_sockfd = client_sockfd;
            clientData.env           = env;
            clientData.err           = err;
            clientData.data          = data;

            for(size_t i = 0; i < MAX_CLIENT; i++)
            {
                if(status_connections[i] != CONNECTED)
                {
                    goto process;
                }
            }
            printf("Server is full, disconnecting client socket %d\n", client_sockfd);
            size = (uint8_t)strlen(message);
            write(client_sockfd, &size, sizeof(uint8_t));
            write(client_sockfd, message, strlen(message));
            socket_close(client_sockfd);
            goto restart_acceptance;

        process:
            for(size_t i = 0; i < MAX_CLIENT; i++)
            {
                if(status_connections[i] == NO_CONNECTION)
                {
                    int thread_creation;
                    printf("Creating thread, Position %zu\n", i);
                    clientData.status_location = i;
                    client_information[i]      = clientData;
                    thread_creation            = pthread_create(&client_connections[i], NULL, run_thread, (void *)&client_information[i]);
                    if(thread_creation < 0)
                    {
                        perror("Thread creation error has occurred.\n");
                        goto restart_acceptance;
                    }
                    client_sockets[i]     = client_sockfd;
                    status_connections[i] = CONNECTED;

                    break;
                }
            }
        }

    restart_acceptance:
        write(client_sockfd, continue_message, strlen(continue_message));

        for(size_t i = 0; i < MAX_CLIENT; i++)
        {
            // CHECK global variable to see if thread is done.
            if(thread_status[i] == DONE)
            {
                if(pthread_join(client_connections[i], NULL) == 0)
                {
                    status_connections[i] = NO_CONNECTION;
                    thread_status[i]      = 0;
                    if(client_sockets[i] > 0)
                    {
                        printf("Client thread exiting %d\n", client_sockets[i]);
                        socket_close(client_sockets[i]);
                        client_sockets[i] = -1;
                    }
                }
            }
        }
    }

close:
    for(size_t i = 0; i < MAX_CLIENT; i++)
    {
        if(client_sockets[i] != -1)
        {
            write(client_sockets[i], "chloroformexitstatus", sizeof("chloroformexitstatus"));
        }
        // CHECK global variable to see if thread is done.
        if(thread_status[i] == DONE)
        {
            if(pthread_cancel(client_connections[i]) == 0)
            {
                if(client_sockets[i] > 0)
                {
                    printf("Client thread rejoined %d\n", client_sockets[i]);
                    socket_close(client_sockets[i]);
                    client_sockets[i] = -1;
                }
            }
        }
    }
}

static void setup_signal_handler(const struct p101_env *env, struct p101_error *err)
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

static void sigint_handler(const int signum)
{
    printf("\nClosing the server...\n");
    exit_flag = 1;
}

#pragma GCC diagnostic pop

static void socket_create(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;

    P101_TRACE(env);
    data                = (struct server_data *)arg;
    data->server_socket = p101_socket(env, err, data->sets->ip_address.ss_family, SOCK_STREAM, 0);

    if(p101_error_has_error(err))
    {
        perror("Socket creation error");
        cleanup(env, err, arg);
    }
}

static void socket_bind(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;
    socklen_t           addr_len;
    in_port_t           net_port;

    P101_TRACE(env);
    data     = (struct server_data *)arg;
    net_port = htons(data->sets->port);

    if(data->sets->ip_address.ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)&data->sets->ip_address;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
    }
    else if(data->sets->ip_address.ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)&data->sets->ip_address;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
    }
    else
    {
        P101_ERROR_RAISE_USER(err, "Internal error: addr->ss_family must be AF_INET or AF_INET6", 1);
        goto error;
    }

    p101_setsockopt(env, err, data->server_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if(p101_error_has_error(err))
    {
        goto error;
    }

    p101_bind(env, err, data->server_socket, (struct sockaddr *)&data->sets->ip_address, addr_len);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    goto done;

error:
    cleanup(env, err, arg);

done:
    return;
}

static void socket_listen(const struct p101_env *env, struct p101_error *err, void *arg)
{
    const struct server_data *data;

    P101_TRACE(env);
    data = (struct server_data *)arg;
    p101_listen(env, err, data->server_socket, SOMAXCONN);
    printf("Server is listening....\n");
    if(p101_error_has_error(err))
    {
        cleanup(env, err, arg);
    }
}

static int socket_accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len)
{
    int  client_fd;
    char client_host[NI_MAXHOST];
    char client_service[NI_MAXSERV];

    errno     = 0;
    client_fd = accept(server_fd, (struct sockaddr *)client_addr, client_addr_len);

    if(client_fd == -1)
    {
        if(errno != EINTR)
        {
            perror("accept failed");
        }

        return -1;
    }

    if(getnameinfo((struct sockaddr *)client_addr, *client_addr_len, client_host, NI_MAXHOST, client_service, NI_MAXSERV, 0) == 0)
    {
        printf("Accepted a new connection from %s:%s\n", client_host, client_service);
    }
    else
    {
        printf("Unable to get client information\n");
    }

    return client_fd;
}

static void socket_close(int sockfd)
{
    if(close(sockfd) == -1)
    {
        perror("Error closing socket\n");
    }
}

static void handle_connection(const struct p101_env *env, struct p101_error *err, void *arg, int sockfd)
{
    int original_stdout;
    int original_stderr;

    P101_TRACE(env);
    printf("Handing connection\n");

    printf("Connected %d\n", sockfd);

    while(!exit_flag)
    {
        char    destroy[LEN];
        char   *word;
        char    buffer[LEN];
        size_t  word_len;
        uint8_t size    = 0;
        original_stdout = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0);
        original_stderr = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 0);

        fflush(stdout);
        memset(buffer, '\0', LEN);

        if(read(sockfd, &size, sizeof(uint8_t)) == 0)
        {
            printf("Received exit\n");
            goto done;
        }

        if(read(sockfd, buffer, (size_t)(size - 1)) == 0)
        {
            printf("received exit 2.0\n");
            goto done;
        }
        read(sockfd, destroy, 1);
        memset(destroy, '\0', LEN);
        word = buffer;

        word_len = strlen(word);

        if(word_len > UINT8_MAX)
        {
            fprintf(stderr, "Word exceeds maximum length\n");
            goto error;
        }

        if(p101_dup2(env, err, sockfd, STDOUT_FILENO) == -1)
        {
            perror("Error redirecting stdout");
        }
        if(p101_error_has_error(err))
        {
            goto error;
        }
        if(p101_dup2(env, err, sockfd, STDERR_FILENO) == -1)
        {
            perror("Error redirecting stdout");
        }
        if(p101_error_has_error(err))
        {
            goto error;
        }
        executeCommand(word);

        if(p101_dup2(env, err, original_stdout, STDOUT_FILENO) == -1)
        {
            perror("Error redirecting stdout");
        }
        if(p101_error_has_error(err))
        {
            goto error;
        }
        if(p101_dup2(env, err, original_stderr, STDERR_FILENO) == -1)
        {
            perror("Error redirecting stdout");
        }
        if(p101_error_has_error(err))
        {
            goto error;
        }
        write(sockfd, "chloroformexitstatus", 20);    // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    goto done;

error:
    cleanup(env, err, arg);

done:
    printf("Connection ended.\n");
}

static void cleanup(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;

    P101_TRACE(env);
    data = (struct server_data *)arg;

    // TODO close client socket too
    if(data->server_socket != -1)
    {
        printf("closing %d\n", data->server_socket);
        p101_close(env, err, data->server_socket);
        data->server_socket = -1;
    }
}

static void *run_thread(void *arg)
{
    struct client_data *clientData = (struct client_data *)arg;
    handle_connection(clientData->env, clientData->err, (void *)&clientData->data, clientData->client_sockfd);
    thread_status[clientData->status_location] = DONE;
    printf("Connection ended with %d\n", clientData->client_sockfd);
    return NULL;
}

/**
 * runCommand
 * @param path string/char pointer
 * @param argument string/char pointer
 * @return 0 or -1
 */
int runCommand(const char *path, char *const *argument)
{
    int   status;
    pid_t pid;
    pid = fork();

    if(path == NULL)
    {    // check if path is NULL aka no command
        return FAIL_VALUE;
    }

    if(pid == FAIL_VALUE)
    {
        perror("Error creating child process");
        return FAIL_VALUE;
    }

    if(pid == 0)
    {
        if(access(path, X_OK) == 0)
        {
            printf("Path is ok");
            if(execv(path, argument) == -1)
            {
                perror("Failed to execute");
                fprintf(stderr, "Error message: %s\n", strerror(errno));
                return FAIL_VALUE;
            }
        }
        else
        {
            printf("path is not okay");
        }
    }

    if(waitpid(pid, &status, 0) == FAIL_VALUE)
    {
        perror("Error waiting for child process\n");
        return FAIL_VALUE;
    }

    if(pid != 0)
    {
        return 0;
    }
    printf("Error running parent process\n");
    return FAIL_VALUE;
}

char *doesExist(const char *command)
{
    const char *path = getenv(GET_ENV_TYPE);
    char        pathA[LEN];
    const char *pathToken;
    char       *pathptr;

    if(path == NULL)
    {
        perror("Path is null, cannot use getenv");
        exit(EXIT_FAILURE);
    }
    strncpy(pathA, path, sizeof(pathA));
    pathToken = strtok_r(pathA, ":", &pathptr);

    for(; pathToken != NULL;)
    {
        char pathArray[LEN];
        //        memset(pathArray, '\0', LEN);
        snprintf(pathArray, LEN, "%s/%s", pathToken, command);
        if(access(pathArray, X_OK) == 0)
        {
            return strdup(pathArray);
        }
        pathToken = strtok_r(NULL, ":", &pathptr);
    }
    printf("%s command is not found in path\n", command);
    return NULL;
}

int executeCommand(char *arg)
{
    char       *cmdPtr;
    const char *delimiter = " ";
    const char *command;
    char       *path;
    char       *argument[LEN];
    int         success;
    size_t      i;

    command = strtok_r(arg, delimiter, &cmdPtr);    // tokenize argument

    if(command == NULL)
    {    // checks if command has any values
        printf("Command and arguments cannot be empty\n");
        return FAIL_VALUE;
    }

    path = doesExist(command);    // grabs path if command is found

    if(path == NULL)
    {    // check if path is NULL aka no command
        free(path);
        return FAIL_VALUE;
    }

    // create array of commands for execv
    for(i = 0; command != NULL && i < LEN; i++)
    {
        // Allocate memory for each argument and copy its value
        argument[i] = strdup(command);
        if(argument[i] == NULL)
        {
            // Handle memory allocation error
            for(i = 0; argument[i] != NULL; i++)
            {
                free(argument[i]);
            }
            free(path);
            perror("Memory allocation failed");
            return FAIL_VALUE;
        }
        command = strtok_r(NULL, " ", &cmdPtr);
    }

    // Set the last element of the array to NULL for execv
    if(i >= LEN)
    {
        argument[LEN - 1] = NULL;
    }
    else
    {
        argument[i] = NULL;
    }

    success = runCommand(path, (char *const *)argument);
    if(success == FAIL_VALUE)
    {
        for(i = 0; argument[i] != NULL; i++)
        {
            free(argument[i]);
        }
        free(path);
        return FAIL_VALUE;
    }
    for(i = 0; argument[i] != NULL; i++)
    {
        free(argument[i]);
    }
    free(path);
    return 0;
}
