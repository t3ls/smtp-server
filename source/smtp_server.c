//
// Project name: smtp-server
// Describe: t3ls's smtp server, originally created for the Computer Network
// Project address: https://github.com/t3ls/smtp-server
//
// Created at: 2018/12
// author: tsls
//
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include "./smtp_server.h"


// Global variables
SSL_CTX *ctx;
struct sockaddr_in my_addr;
struct sockaddr_in remote_addr;
const char *kCommandInfo[] = {
    "220 SMTP Is Ready\r\n",
    "250-mail \r\n250-PIPELINING \r\n250-SIZE 52428800\r\n250-AUTH LOGIN PLAIN \r\n250-AUTH=LOGIN \r\n250 8BITMIME\r\n",
    "250 Mail OK\r\n",
    "354 Start mail input;end with <CR><LF>.<CR><LF>\r\n",
    "221 Bye\r\n",
    "550 Invalid User\r\n",
    "334 user-base64\r\n",
    "334 pwd-base64\r\n",
    "235 Authentication Successful\r\n",
    "502 Error: command not implemented\r\n",
    "500 Error: bad syntax\r\n",
    "503 Error: send HELO/EHLO first\r\n",
    "530 Authentication required\r\n",
    "535 Error: authentication failed\r\n"
    };


//
// Main Function: Entrance of program
//
int main() {
    int server_sockfd = 0;
    if ((server_sockfd = init()) < 0) {
        perror("Init failed");
    }
    run(server_sockfd);
    return 0;
}


//
// Core Function: Initialize
//
int init() {
    int server_sockfd = 0;

    // Set buffer length
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    // Initialize SSL
    if (USE_SSL) {
        if (!init_ssl()) {
            return -1;
        }
    }

    // Initialize socket
    if (!(server_sockfd = init_socket())) {
        return -1;
    }
    return server_sockfd;
}


//
// Core Function: Initialize SSL
//
SSL_CTX * init_ssl() {
    // Initialize SSL library
    SSL_library_init();
    // Load all algorithms from SSL
    OpenSSL_add_all_algorithms();
    // Load all error messege
    SSL_load_error_strings();
    // Generate a SSL_CTX(SSL Content Text) by SSL V2 and V3
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    // Load server public cert
    if (!SSL_CTX_use_certificate_file(ctx, SSL_CERT, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    // Load private key
    if (!SSL_CTX_use_PrivateKey_file(ctx, SSL_KEY, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    // Check private key
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    return ctx;
}


//
// Core Function: Initialize socket
//
int init_socket() {
    int server_sockfd = 0;

    bzero(&my_addr, sizeof(my_addr));
    bzero(&remote_addr, sizeof(remote_addr));

    my_addr.sin_family = PF_INET;
    my_addr.sin_addr.s_addr = INADDR_ANY;
    my_addr.sin_port = htons(SMTP_PORT);

    // Create socket fd
    if ((server_sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket create failed");
        return -1;
    }

    // Set socket reuse address:on
    int on = 1;
    if ((setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
        perror("Socket set failed");
        return -1;
    }

    // Bind address info to socket
    if ((bind(server_sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr))) < 0) {
        perror("Socket bind failed");
        return -1;
    }

    // Listening socket
    if (listen(server_sockfd, LISTEN_QUENE_LENGTH) < 0) {
        perror("Socket listen failed");
        return -1;
    }

    if (DEBUG) {
        printf("IP: %s, PORT: %d\n\n", inet_ntoa(my_addr.sin_addr), ntohs(my_addr.sin_port));
    }
    return server_sockfd;
}


//
// Core Function: do most things:
// connect with client and forward mails
//
int run(int server_sockfd) {
    int sin_size = sizeof(struct sockaddr);
    int client_sockfd = 0;
    pthread_t tid[LISTEN_THREADS_NUM];
    void *args = &server_sockfd;

    if (DEBUG) printf("Waiting for connecting...\n");

    if (USE_MULTITHREADING) {
        // Multithreading listening client connect
        // to make sure multi clients could connect together
        while (TRUE) {
            for (int i = 0; i < LISTEN_THREADS_NUM; i++) {
                pthread_create(&tid[i], NULL, thread_func, args);
            }
            for (int i = 0; i < LISTEN_THREADS_NUM; i++) {
                pthread_join(tid[i], NULL);
            }
        }
    }
    else {
        // Single thread
        while (TRUE) {
            if ((client_sockfd = accept(server_sockfd, (struct sockaddr*)&remote_addr, &sin_size)) < 0) {
                perror("Socket accept failed");
                return -1;
            }
            if (DEBUG) printf("Remote address: %s", inet_ntoa(remote_addr.sin_addr));
            if (USE_SSL) {
                ssl_daemon(client_sockfd);
            }
            else {
                normal_daemon(client_sockfd);
            }
        }
    }
    return 0;
}


//
// Core Function: thread function,
// accept client socket and connect
// with starting normal/SSL daemon function
//
void * thread_func(void *args) {
    int server_sockfd = *(int*)args;
    int sin_size = sizeof(struct sockaddr);
    int client_sockfd = 0;

    pthread_detach(pthread_self());

    // Accept client's requests
    if ((client_sockfd = accept(server_sockfd, (struct sockaddr*)&remote_addr, &sin_size)) < 0) {
        perror("Socket accept failed");
        return NULL;
    }

    // Have accept socket,
    // select normal/SSL mode to start daemon
    if (DEBUG) printf("Remote address: %s, Port: %d\n\n", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port));
    if (USE_SSL) {
        ssl_daemon(client_sockfd);
    }
    else {
        normal_daemon(client_sockfd);
    }
}


//
// Core Function: SSL mode daemon,
// connect with client using SSL,
// accept smtp commands and mail,
// if have received data then start forward function
//
int ssl_daemon(int client_sockfd) {
    time_t timestamp_tmp;
    struct tm *timestamp = NULL;
    BOOL auth_plain = FALSE;
    char log_path[260];
    char recv_buf[BUFFER_MAX_LENGTH], tmp_buf[BUFFER_MAX_LENGTH];
    char tmp[BUFFER_MAX_LENGTH];
    struct mail_info {
        char rcpt_to[MAX_RCPT_TO][BUFFER_MAX_LENGTH];
        char ehlo[BUFFER_MAX_LENGTH];
        char auth[BUFFER_MAX_LENGTH];
        char mail_from[BUFFER_MAX_LENGTH];
        char data[BUFFER_MAX_LENGTH];
        char user[BUFFER_MAX_LENGTH];
        char pwd[BUFFER_MAX_LENGTH];
    } mail_info;
    pthread_t forward_tid[LISTEN_THREADS_NUM];
    int forward_num = 0;

    // Initialize ctx and accept client ssl
    SSL *client_ssl = SSL_new(ctx);
    SSL_set_fd(client_ssl, client_sockfd);
    if (!SSL_accept(client_ssl)) {
        perror("SSL accept failed");
        close(client_sockfd);
        return -1;
    }
    printf("SSL algorithm: %s\n", SSL_get_cipher(client_ssl));

    bzero(log_path, sizeof(log_path));
    bzero(mail_info.rcpt_to, sizeof(mail_info.rcpt_to));
    bzero(mail_info.ehlo, sizeof(mail_info.ehlo));
    bzero(mail_info.auth, sizeof(mail_info.auth));
    bzero(mail_info.mail_from, sizeof(mail_info.mail_from));
    bzero(mail_info.data, sizeof(mail_info.data));
    bzero(mail_info.user, sizeof(mail_info.user));
    bzero(mail_info.pwd, sizeof(mail_info.pwd));

    // Open log file
    strcat(log_path, "log/log-");
    time(&timestamp_tmp);
    timestamp = localtime(&timestamp_tmp);
    sprintf(tmp, "%d", 1900 + timestamp->tm_year);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", 1 + timestamp->tm_mon);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", timestamp->tm_mday);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", timestamp->tm_hour);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", timestamp->tm_min);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", timestamp->tm_sec);
    strcat(log_path, tmp);
    strcat(log_path, ".txt");
    FILE *fp = fopen(log_path, "w+");

    // Send 220
    SSL_write(client_ssl, kCommandInfo[0], strlen(kCommandInfo[0]));

    // Waiting to receive EHLO/HELO
    while (TRUE) {
        SSL_read(client_ssl, recv_buf, BUFFER_MAX_LENGTH);
        strncpy(tmp_buf, recv_buf, strlen("quit"));
        if (!strcasecmp(tmp_buf, "quit")) {
            ssl_quit(fp, client_ssl, client_sockfd);
            return 0;
        }
        strncpy(tmp_buf, recv_buf, strlen("ehlo"));
        if (strcasecmp(tmp_buf, "ehlo") && strcasecmp(tmp_buf, "helo")) {
            memset(tmp_buf, 0, sizeof(tmp_buf));
            strncpy(tmp_buf, recv_buf, strlen("auth"));
            if (strcasecmp(tmp_buf, "auth")) {
                memset(recv_buf, 0, sizeof(recv_buf));
                memset(tmp_buf, 0, sizeof(tmp_buf));
                SSL_write(client_ssl, kCommandInfo[11], strlen(kCommandInfo[11]));  // send: 503 Error
                continue;
            }
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            SSL_write(client_ssl, kCommandInfo[9], strlen(kCommandInfo[9]));  // send: 502 Error
            continue;
        }
        if (strlen(recv_buf) == 6) {
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            SSL_write(client_ssl, kCommandInfo[10], strlen(kCommandInfo[10]));  // send: 500 Error
            continue;
        }
        if (!strcasecmp(tmp_buf, "ehlo"))
            SSL_write(client_ssl, kCommandInfo[1], strlen(kCommandInfo[1]));  // send: ehlo
        else if (!strcasecmp(tmp_buf, "helo"))
            SSL_write(client_ssl, kCommandInfo[2], strlen(kCommandInfo[2]));  // send: 250 OK
        bzero(mail_info.ehlo, sizeof(mail_info.ehlo));
        memcpy(mail_info.ehlo, recv_buf, sizeof(recv_buf));
        fprintf(fp, "%s", recv_buf);
        memset(recv_buf, 0, sizeof(recv_buf));
        memset(tmp_buf, 0, sizeof(tmp_buf));
        break;
    }


    // Waiting to receive AUTH LOGIN or AUTH PLAIN
    // then open a socket with mail server to authenticate
    while (TRUE) {
        bzero(mail_info.auth, sizeof(mail_info.auth));
        // Receiving AUTH command
        while (TRUE) {
            SSL_read(client_ssl, recv_buf, BUFFER_MAX_LENGTH);
            strncpy(tmp_buf, recv_buf, strlen("quit"));
            if (!strcasecmp(tmp_buf, "quit")) {
                ssl_quit(fp, client_ssl, client_sockfd);
                return 0;
            }
            if (!strcasecmp(tmp_buf, "ehlo")) {
                SSL_write(client_ssl, kCommandInfo[1], strlen(kCommandInfo[1]));  // send: ehlo
                continue;
            }
            else if (!strcasecmp(tmp_buf, "helo")) {
                SSL_write(client_ssl, kCommandInfo[2], strlen(kCommandInfo[2]));  // send: 250 OK
                continue;
            }
            strncpy(tmp_buf, recv_buf, strlen("auth login"));
            if (strcasecmp(tmp_buf, "auth login")) {
                memset(tmp_buf, 0, sizeof(tmp_buf));
                strncpy(tmp_buf, recv_buf, strlen("auth plain"));
                if (strcasecmp(tmp_buf, "auth plain")) {
                    memset(recv_buf, 0, sizeof(recv_buf));
                    memset(tmp_buf, 0, sizeof(tmp_buf));
                    SSL_write(client_ssl, kCommandInfo[12], strlen(kCommandInfo[12]));  // send: 530 Auth required
                    continue;
                }
                auth_plain = TRUE;
            }
            memcpy(mail_info.auth, recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            break;
        }

        // If AUTH LOGIN,
        // receive username and password
        bzero(mail_info.user, sizeof(mail_info.user));
        bzero(mail_info.pwd, sizeof(mail_info.pwd));
        if (!auth_plain) {
            // Username-base64
            SSL_write(client_ssl, kCommandInfo[6], strlen(kCommandInfo[6]));
            SSL_read(client_ssl, recv_buf, BUFFER_MAX_LENGTH);
            memcpy(mail_info.user, recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            // Password-base64
            SSL_write(client_ssl, kCommandInfo[7], strlen(kCommandInfo[7]));
            SSL_read(client_ssl, recv_buf, BUFFER_MAX_LENGTH);
            memcpy(mail_info.pwd, recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
        }

        // Start authenticate function
        // if Success, step to next stage,
        // else repeat receiving AUTH command
        if (!auth_test(mail_info.auth, mail_info.user, mail_info.pwd)) {
            SSL_write(client_ssl, kCommandInfo[13], strlen(kCommandInfo[13]));  // send: 535 authentication failed
            continue;
        }
        SSL_write(client_ssl, kCommandInfo[8], strlen(kCommandInfo[8]));  // send: 235 Authentication Successful
        break;
    }


    // Receiving sender, receivers and message
    while (TRUE) {
        while (TRUE) {
            // Receiving sender address
            SSL_read(client_ssl, recv_buf, BUFFER_MAX_LENGTH);
            strncpy(tmp_buf, recv_buf, strlen("quit"));
            if (!strcasecmp(tmp_buf, "quit")) {
                ssl_quit(fp, client_ssl, client_sockfd);
                return 0;
            }
            strncpy(tmp_buf, recv_buf, strlen("mail from:"));
            if (strcasecmp(tmp_buf, "mail from:")) {
                memset(recv_buf, 0, sizeof(recv_buf));
                memset(tmp_buf, 0, sizeof(tmp_buf));
                SSL_write(client_ssl, kCommandInfo[9], strlen(kCommandInfo[9]));  // send: 502 Error
                continue;
            }
            bzero(mail_info.mail_from, sizeof(mail_info.mail_from));
            memcpy(mail_info.mail_from, recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            // Verify the mail address syntax
            if (!valid_mailaddr(mail_info.mail_from)) {
                memset(recv_buf, 0, sizeof(recv_buf));
                memset(tmp_buf, 0, sizeof(tmp_buf));
                SSL_write(client_ssl, kCommandInfo[5], strlen(kCommandInfo[5]));  // send: 550 Invalid User
                continue;
            }
            SSL_write(client_ssl, kCommandInfo[2], strlen(kCommandInfo[2]));  // send: 250 OK
            break;
        }

        // Receiving receivers address
        // support max receivers: MAX_RCPT_TO in "smtp_server.h"
        int i = 0;
        bzero(mail_info.rcpt_to, sizeof(mail_info.rcpt_to));
        while (TRUE) {
            SSL_read(client_ssl, recv_buf, BUFFER_MAX_LENGTH);
            strncpy(tmp_buf, recv_buf, strlen("quit"));
            if (!strcasecmp(tmp_buf, "quit")) {
                ssl_quit(fp, client_ssl, client_sockfd);
                return 0;
            }
            strncpy(tmp_buf, recv_buf, strlen("rcpt to:"));
            if (strcasecmp(tmp_buf, "rcpt to:")) {
                if (i == 0) {
                    memset(recv_buf, 0, sizeof(recv_buf));
                    memset(tmp_buf, 0, sizeof(tmp_buf));
                    SSL_write(client_ssl, kCommandInfo[9], strlen(kCommandInfo[9]));  // send: 502 Error
                    continue;
                }
                else {
                    memset(tmp_buf, 0, sizeof(tmp_buf));
                    break;
                }
            }
            // Verify the mail address syntax
            if (!valid_mailaddr(recv_buf)) {
                memset(recv_buf, 0, sizeof(recv_buf));
                memset(tmp_buf, 0, sizeof(tmp_buf));
                SSL_write(client_ssl, kCommandInfo[5], strlen(kCommandInfo[5]));  // send: 550 Invalid User
                continue;
            }
            memcpy(mail_info.rcpt_to[i], recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            SSL_write(client_ssl, kCommandInfo[2], strlen(kCommandInfo[2]));  // send: 250 OK
            i++;
        }

        // Receiving start transport data command
        for (int i = 0;; i++) {
            if (i) {
                SSL_read(client_ssl, recv_buf, BUFFER_MAX_LENGTH);
            }
            strncpy(tmp_buf, recv_buf, strlen("quit"));
            if (!strcasecmp(tmp_buf, "quit")) {
                ssl_quit(fp, client_ssl, client_sockfd);
                return 0;
            }
            strncpy(tmp_buf, recv_buf, strlen("data"));
            if (strcasecmp(tmp_buf, "data")) {
                memset(tmp_buf, 0, sizeof(tmp_buf));
                memset(recv_buf, 0, sizeof(recv_buf));
                continue;
            }
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            SSL_write(client_ssl, kCommandInfo[3], strlen(kCommandInfo[3]));  // send: 354 Start mail input
            break;
        }


        // Receiving data
        char *pos = NULL;
        while (TRUE) {
            SSL_read(client_ssl, recv_buf, BUFFER_MAX_LENGTH);
            fprintf(fp, "%s", recv_buf);
            strcat(mail_info.data, recv_buf);
            if (pos = strstr(recv_buf, ".\r")) {
                SSL_write(client_ssl, kCommandInfo[2], strlen(kCommandInfo[2]));  // send: 250 OK
                *(pos + 3) = '\x00';
                break;
            }
            bzero(recv_buf, sizeof(recv_buf));
        }
        memset(recv_buf, 0, sizeof(recv_buf));

        // Create a forward mail thread
        // which can receive another mail at the same time
        // max threads forward together: LISTEN_THREADS_NUM in "smtp_server.h"
        pthread_create(&forward_tid[forward_num], NULL, ssl_forward, (void*)&mail_info);
        forward_num++;
    }
}



//
// Core Function: normal mode daemon,
// connect with client using no encrypt way,
// accept smtp commands and mail,
// if have received data then start forward function
//
int normal_daemon(int client_sockfd) {
    time_t timestamp_tmp;
    struct tm *timestamp = NULL;
    BOOL auth_plain = FALSE;
    char log_path[260];
    char recv_buf[BUFFER_MAX_LENGTH], tmp_buf[BUFFER_MAX_LENGTH];
    char tmp[BUFFER_MAX_LENGTH];
    struct mail_info {
        char rcpt_to[MAX_RCPT_TO][BUFFER_MAX_LENGTH];
        char ehlo[BUFFER_MAX_LENGTH];
        char auth[BUFFER_MAX_LENGTH];
        char mail_from[BUFFER_MAX_LENGTH];
        char data[BUFFER_MAX_LENGTH];
        char user[BUFFER_MAX_LENGTH];
        char pwd[BUFFER_MAX_LENGTH];
    } mail_info;
    pthread_t forward_tid[LISTEN_THREADS_NUM];
    int forward_num = 0;


    bzero(log_path, sizeof(log_path));
    bzero(mail_info.rcpt_to, sizeof(mail_info.rcpt_to));
    bzero(mail_info.ehlo, sizeof(mail_info.ehlo));
    bzero(mail_info.auth, sizeof(mail_info.auth));
    bzero(mail_info.mail_from, sizeof(mail_info.mail_from));
    bzero(mail_info.data, sizeof(mail_info.data));
    bzero(mail_info.user, sizeof(mail_info.user));
    bzero(mail_info.pwd, sizeof(mail_info.pwd));

    // Open log file
    strcat(log_path, "log/log-");
    time(&timestamp_tmp);
    timestamp = localtime(&timestamp_tmp);
    sprintf(tmp, "%d", 1900 + timestamp->tm_year);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", 1 + timestamp->tm_mon);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", timestamp->tm_mday);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", timestamp->tm_hour);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", timestamp->tm_min);
    strcat(log_path, tmp);
    sprintf(tmp, "%d", timestamp->tm_sec);
    strcat(log_path, tmp);
    strcat(log_path, ".txt");
    FILE *fp = fopen(log_path, "w+");

    // Send 220
    send(client_sockfd, kCommandInfo[0], strlen(kCommandInfo[0]), 0);

    // Waiting to receive EHLO/HELO
    while (TRUE) {
        recv(client_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
        strncpy(tmp_buf, recv_buf, strlen("quit"));
        if (!strcasecmp(tmp_buf, "quit")) {
            normal_quit(fp, client_sockfd);
            return 0;
        }
        strncpy(tmp_buf, recv_buf, strlen("ehlo"));
        if (strcasecmp(tmp_buf, "ehlo") && strcasecmp(tmp_buf, "helo")) {
            memset(tmp_buf, 0, sizeof(tmp_buf));
            strncpy(tmp_buf, recv_buf, strlen("auth"));
            if (strcasecmp(tmp_buf, "auth")) {
                memset(recv_buf, 0, sizeof(recv_buf));
                memset(tmp_buf, 0, sizeof(tmp_buf));
                send(client_sockfd, kCommandInfo[11], strlen(kCommandInfo[11]), 0);  // send: 503 Error
                continue;
            }
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            send(client_sockfd, kCommandInfo[9], strlen(kCommandInfo[9]), 0);  // send: 502 Error
            continue;
        }
        if (strlen(recv_buf) == 6) {
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            send(client_sockfd, kCommandInfo[10], strlen(kCommandInfo[10]), 0);  // send: 500 Error
            continue;
        }
        if (!strcasecmp(tmp_buf, "ehlo"))
            send(client_sockfd, kCommandInfo[1], strlen(kCommandInfo[1]), 0);  // send: ehlo
        else if (!strcasecmp(tmp_buf, "helo"))
            send(client_sockfd, kCommandInfo[2], strlen(kCommandInfo[2]), 0);  // send: 250 OK
        bzero(mail_info.ehlo, sizeof(mail_info.ehlo));
        memcpy(mail_info.ehlo, recv_buf, sizeof(recv_buf));
        fprintf(fp, "%s", recv_buf);
        memset(recv_buf, 0, sizeof(recv_buf));
        memset(tmp_buf, 0, sizeof(tmp_buf));
        break;
    }


    // Waiting to receive AUTH LOGIN or AUTH PLAIN
    // then open a socket with mail server to authenticate
    while (TRUE) {
        bzero(mail_info.auth, sizeof(mail_info.auth));
        // Receiving AUTH command
        while (TRUE) {
            recv(client_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
            strncpy(tmp_buf, recv_buf, strlen("quit"));
            if (!strcasecmp(tmp_buf, "quit")) {
                normal_quit(fp, client_sockfd);
                return 0;
            }
            if (!strcasecmp(tmp_buf, "ehlo")) {
                send(client_sockfd, kCommandInfo[1], strlen(kCommandInfo[1]), 0);  // send: ehlo
                continue;
            }
            else if (!strcasecmp(tmp_buf, "helo")) {
                send(client_sockfd, kCommandInfo[2], strlen(kCommandInfo[2]), 0);  // send: 250 OK
                continue;
            }
            strncpy(tmp_buf, recv_buf, strlen("auth login"));
            if (strcasecmp(tmp_buf, "auth login")) {
                memset(tmp_buf, 0, sizeof(tmp_buf));
                strncpy(tmp_buf, recv_buf, strlen("auth plain"));
                if (strcasecmp(tmp_buf, "auth plain")) {
                    memset(recv_buf, 0, sizeof(recv_buf));
                    memset(tmp_buf, 0, sizeof(tmp_buf));
                    send(client_sockfd, kCommandInfo[12], strlen(kCommandInfo[12]), 0);  // send: 530 Auth required
                    continue;
                }
                auth_plain = TRUE;
            }
            memcpy(mail_info.auth, recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            break;
        }


        // If AUTH LOGIN,
        // receive username and password
        bzero(mail_info.user, sizeof(mail_info.user));
        bzero(mail_info.pwd, sizeof(mail_info.pwd));
        if (!auth_plain) {
            // Username-base64
            send(client_sockfd, kCommandInfo[6], strlen(kCommandInfo[6]), 0);
            recv(client_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
            memcpy(mail_info.user, recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            // Password-base64
            send(client_sockfd, kCommandInfo[7], strlen(kCommandInfo[7]), 0);
            recv(client_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
            memcpy(mail_info.pwd, recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
        }

        // Start authenticate function
        // if Success, step to next stage,
        // else repeat receiving AUTH command
        if (!auth_test(mail_info.auth, mail_info.user, mail_info.pwd)) {
            send(client_sockfd, kCommandInfo[13], strlen(kCommandInfo[13]), 0);  // send: 535 authentication failed
            continue;
        }
        send(client_sockfd, kCommandInfo[8], strlen(kCommandInfo[8]), 0);  // send: 235 Authentication Successful
        break;
    }


    // Receiving sender, receivers and message
    while (TRUE) {
        while (TRUE) {
            // Receiving sender address
            recv(client_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
            strncpy(tmp_buf, recv_buf, strlen("quit"));
            if (!strcasecmp(tmp_buf, "quit")) {
                normal_quit(fp, client_sockfd);
                return 0;
            }
            strncpy(tmp_buf, recv_buf, strlen("mail from:"));
            if (strcasecmp(tmp_buf, "mail from:")) {
                memset(recv_buf, 0, sizeof(recv_buf));
                memset(tmp_buf, 0, sizeof(tmp_buf));
                send(client_sockfd, kCommandInfo[9], strlen(kCommandInfo[9]), 0);  // send: 502 Error
                continue;
            }
            bzero(mail_info.mail_from, sizeof(mail_info.mail_from));
            memcpy(mail_info.mail_from, recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            // Verify the mail address syntax
            if (!valid_mailaddr(mail_info.mail_from)) {
                memset(recv_buf, 0, sizeof(recv_buf));
                memset(tmp_buf, 0, sizeof(tmp_buf));
                send(client_sockfd, kCommandInfo[5], strlen(kCommandInfo[5]), 0);  // send: 550 Invalid User
                continue;
            }
            send(client_sockfd, kCommandInfo[2], strlen(kCommandInfo[2]), 0);  // send: 250 OK
            break;
        }

        // Receiving receivers address
        // support max receivers: MAX_RCPT_TO in "smtp_server.h"
        int i = 0;
        bzero(mail_info.rcpt_to, sizeof(mail_info.rcpt_to));
        while (TRUE) {
            recv(client_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
            strncpy(tmp_buf, recv_buf, strlen("quit"));
            if (!strcasecmp(tmp_buf, "quit")) {
                normal_quit(fp, client_sockfd);
                return 0;
            }
            if (i >= MAX_RCPT_TO) {
                memset(tmp_buf, 0, sizeof(tmp_buf));
                break;
            }
            strncpy(tmp_buf, recv_buf, strlen("rcpt to:"));
            if (strcasecmp(tmp_buf, "rcpt to:")) {
                if (i == 0) {
                    memset(recv_buf, 0, sizeof(recv_buf));
                    memset(tmp_buf, 0, sizeof(tmp_buf));
                    send(client_sockfd, kCommandInfo[9], strlen(kCommandInfo[9]), 0);  // send: 502 Error
                    continue;
                }
                else {
                    memset(tmp_buf, 0, sizeof(tmp_buf));
                    break;
                }
            }
            // Verify the mail address syntax
            if (!valid_mailaddr(recv_buf)) {
                memset(recv_buf, 0, sizeof(recv_buf));
                memset(tmp_buf, 0, sizeof(tmp_buf));
                send(client_sockfd, kCommandInfo[5], strlen(kCommandInfo[5]), 0);  // send: 550 Invalid User
                continue;
            }
            memcpy(mail_info.rcpt_to[i], recv_buf, sizeof(recv_buf));
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            send(client_sockfd, kCommandInfo[2], strlen(kCommandInfo[2]), 0);  // send: 250 OK
            i++;
        }

        // Receiving start transport data command
        for (int i = 0;; i++) {
            if (i) {
                recv(client_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
            }
            strncpy(tmp_buf, recv_buf, strlen("quit"));
            if (!strcasecmp(tmp_buf, "quit")) {
                normal_quit(fp, client_sockfd);
                return 0;
            }
            strncpy(tmp_buf, recv_buf, strlen("data"));
            if (strcasecmp(tmp_buf, "data")) {
                memset(tmp_buf, 0, sizeof(tmp_buf));
                memset(recv_buf, 0, sizeof(recv_buf));
                continue;
            }
            fprintf(fp, "%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
            memset(tmp_buf, 0, sizeof(tmp_buf));
            send(client_sockfd, kCommandInfo[3], strlen(kCommandInfo[3]), 0);  // send: 354 Start mail input
            break;
        }


        // Receiving data
        char *pos = NULL;
        while (TRUE) {
            recv(client_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
            fprintf(fp, "%s", recv_buf);
            strcat(mail_info.data, recv_buf);
            if (pos = strstr(recv_buf, ".\r")) {
                send(client_sockfd, kCommandInfo[2], strlen(kCommandInfo[2]), 0);  // send: 250 OK
                *(pos + 3) = '\x00';
                break;
            }
            bzero(recv_buf, sizeof(recv_buf));
        }
        memset(recv_buf, 0, sizeof(recv_buf));

        // Create a forward mail thread
        // which can receive another mail at the same time
        // max threads forward together: LISTEN_THREADS_NUM in "smtp_server.h"
        pthread_create(&forward_tid[forward_num], NULL, normal_forward, (void*)&mail_info);
        forward_num++;
    }

}


//
// Core Function: forward mail with no encrypt
//
void * normal_forward(void *args) {
    int mailserver_sockfd;
    char tmp_buf[BUFFER_MAX_LENGTH];
    char recv_buf[BUFFER_MAX_LENGTH];
    char serv_hostname[BUFFER_MAX_LENGTH];
    struct sockaddr_in servaddr;
    struct mail_info {
        char rcpt_to[MAX_RCPT_TO][BUFFER_MAX_LENGTH];
        char ehlo[BUFFER_MAX_LENGTH];
        char auth[BUFFER_MAX_LENGTH];
        char mail_from[BUFFER_MAX_LENGTH];
        char data[BUFFER_MAX_LENGTH];
        char user[BUFFER_MAX_LENGTH];
        char pwd[BUFFER_MAX_LENGTH];
        char data_header[BUFFER_MAX_LENGTH];
    } mail_info, *mail_info_ptr, *tmp;
    struct hostent *serv_host;

    pthread_detach(pthread_self());
    tmp = (struct mail_info*)args;
    mail_info_ptr = &mail_info;
    // TODO: not thread safe
    memcpy(mail_info_ptr->rcpt_to, tmp->rcpt_to, sizeof(mail_info_ptr->rcpt_to));
    memcpy(mail_info_ptr->ehlo, tmp->ehlo, sizeof(mail_info_ptr->ehlo));
    memcpy(mail_info_ptr->auth, tmp->auth, sizeof(mail_info_ptr->auth));
    memcpy(mail_info_ptr->mail_from, tmp->mail_from, sizeof(mail_info_ptr->mail_from));
    memcpy(mail_info_ptr->data, tmp->data, sizeof(mail_info_ptr->data));
    memcpy(mail_info_ptr->user, tmp->user, sizeof(mail_info_ptr->user));
    memcpy(mail_info_ptr->pwd, tmp->pwd, sizeof(mail_info_ptr->pwd));


    // Create socket
    if ((mailserver_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Forward socket create failed");
        return NULL;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);

    // Solve smtp server host by sender address
    bzero(serv_hostname, sizeof(serv_hostname));
    bzero(tmp_buf, sizeof(tmp_buf));
    strcpy(tmp_buf, strchr(mail_info_ptr->mail_from, '@') + 1);
    *strchr(tmp_buf, '>') = '\x00';
    strcat(serv_hostname, "smtp.");
    strcat(serv_hostname, tmp_buf);
    printf("serv_hostname: %s\n", serv_hostname);
    if (!(serv_host = gethostbyname(serv_hostname))) {
        perror("Unknown host");
        return NULL;
    }
    memcpy(&servaddr.sin_addr, serv_host->h_addr, serv_host->h_length);
    printf("Server host: %s, IP: %s, PORT: %d\n", serv_hostname, inet_ntoa(servaddr.sin_addr), SERV_PORT);

    // Connect mail server with own socket
    if (connect(mailserver_sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("Forward socket connect failed");
        return NULL;
    }

    // Receiving 220
    printf("Connecting mail server...\n");
    bzero(recv_buf, sizeof(recv_buf));
    recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "220")) {
        perror("Forward recv 220 failed");
        return NULL;
    }


    // Send EHLO/HELO
    bzero(recv_buf, sizeof(recv_buf));
    send(mailserver_sockfd, mail_info_ptr->ehlo, strlen(mail_info_ptr->ehlo), 0);  // send: ehlo
    recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "250")) {
        perror("Forward EHLO/HELO failed");
        return NULL;
    }


    // Send AUTH LOGIN/PLAIN
    bzero(recv_buf, sizeof(recv_buf));
    send(mailserver_sockfd, mail_info_ptr->auth, strlen(mail_info_ptr->auth), 0);
    if (*mail_info_ptr->user) {
        // AUTH LOGIN
        recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
        if (!strstr(recv_buf, "334")) {
            perror("Forward AUTH LOGIN failed");
            return NULL;
        }
        send(mailserver_sockfd, mail_info_ptr->user, strlen(mail_info_ptr->user), 0);
        bzero(recv_buf, sizeof(recv_buf));
        recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
        if (!strstr(recv_buf, "334")) {
            perror("Forward AUTH LOGIN failed");
            return NULL;
        }
        send(mailserver_sockfd, mail_info_ptr->pwd, strlen(mail_info_ptr->pwd), 0);
    }
    bzero(recv_buf, sizeof(recv_buf));
    recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "235")) {
        perror("Forward AUTH failed");
        return NULL;
    }

    // Send sender information
    send(mailserver_sockfd, mail_info_ptr->mail_from, strlen(mail_info_ptr->mail_from), 0);
    bzero(recv_buf, sizeof(recv_buf));
    recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "250")) {
        perror("Forward MAIL FROM failed");
        return NULL;
    }

    // Send receivers information
    for (int i = 0; i < MAX_RCPT_TO; i++) {
        if (*mail_info_ptr->rcpt_to[i]) {
            send(mailserver_sockfd, mail_info_ptr->rcpt_to[i], strlen(mail_info_ptr->rcpt_to[i]), 0);
            bzero(recv_buf, sizeof(recv_buf));
            recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
            if (!strstr(recv_buf, "250")) {
                perror("Forward RCPT TO failed");
                return NULL;
            }
        }
        else break;
    }

    // Send "data" command to start transport data
    send(mailserver_sockfd, "data\r\n", strlen("data\r\n"), 0);
    bzero(recv_buf, sizeof(recv_buf));
    recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "354")) {
        perror("Forward DATA failed");
        return NULL;
    }
    // TODO:Anti DT:SPM
    bzero(mail_info_ptr->data_header, sizeof(mail_info_ptr->data_header));
    send(mailserver_sockfd, mail_info_ptr->data_header, strlen(mail_info_ptr->data_header), 0);

    // Send data
    send(mailserver_sockfd, mail_info_ptr->data, strlen(mail_info_ptr->data), 0);
    bzero(recv_buf, sizeof(recv_buf));
    recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "250")) {
        perror("Forward send DATA failed");
        return NULL;
    }


    // Quit
    send(mailserver_sockfd, "QUIT\r\n", strlen("QUIT\r\n"), 0);
    bzero(recv_buf, sizeof(recv_buf));
    recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "221")) {
        perror("Forward QUIT failed");
        return NULL;
    }

    printf("Forward Success\n");
}


//
// Core Function: forward mail with SSL
//
void * ssl_forward(void *args) {
    int mailserver_sockfd;
    char tmp_buf[BUFFER_MAX_LENGTH];
    char recv_buf[BUFFER_MAX_LENGTH];
    char serv_hostname[BUFFER_MAX_LENGTH];
    struct sockaddr_in servaddr;
    struct mail_info {
        char rcpt_to[MAX_RCPT_TO][BUFFER_MAX_LENGTH];
        char ehlo[BUFFER_MAX_LENGTH];
        char auth[BUFFER_MAX_LENGTH];
        char mail_from[BUFFER_MAX_LENGTH];
        char data[BUFFER_MAX_LENGTH];
        char user[BUFFER_MAX_LENGTH];
        char pwd[BUFFER_MAX_LENGTH];
        char data_header[BUFFER_MAX_LENGTH];
    } mail_info, *mail_info_ptr, *tmp;
    struct hostent *serv_host;

    pthread_detach(pthread_self());
    tmp = (struct mail_info*)args;
    mail_info_ptr = &mail_info;
    // TODO: not thread safe
    memcpy(mail_info_ptr->rcpt_to, tmp->rcpt_to, sizeof(mail_info_ptr->rcpt_to));
    memcpy(mail_info_ptr->ehlo, tmp->ehlo, sizeof(mail_info_ptr->ehlo));
    memcpy(mail_info_ptr->auth, tmp->auth, sizeof(mail_info_ptr->auth));
    memcpy(mail_info_ptr->mail_from, tmp->mail_from, sizeof(mail_info_ptr->mail_from));
    memcpy(mail_info_ptr->data, tmp->data, sizeof(mail_info_ptr->data));
    memcpy(mail_info_ptr->user, tmp->user, sizeof(mail_info_ptr->user));
    memcpy(mail_info_ptr->pwd, tmp->pwd, sizeof(mail_info_ptr->pwd));


    // Create socket
    if ((mailserver_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Forward socket create failed");
        return NULL;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    // If use STARTTLS way to connect,
    // use SERV_PORT, else use SERV_SSL_PORT
    if (STARTTLS_FORWARD)
        servaddr.sin_port = htons(SERV_PORT);
    else servaddr.sin_port = htons(SERV_SSL_PORT);

    // Solve smtp server host by sender address
    bzero(serv_hostname, sizeof(serv_hostname));
    bzero(tmp_buf, sizeof(tmp_buf));
    strcpy(tmp_buf, strchr(mail_info_ptr->mail_from, '@') + 1);
    *strchr(tmp_buf, '>') = '\x00';
    strcat(serv_hostname, "smtp.");
    strcat(serv_hostname, tmp_buf);
    printf("serv_hostname: %s\n", serv_hostname);
    if (!(serv_host = gethostbyname(serv_hostname))) {
        perror("Unknown host");
        return NULL;
    }
    memcpy(&servaddr.sin_addr, serv_host->h_addr, serv_host->h_length);
    if (STARTTLS_FORWARD)
        printf("Server host: %s, IP: %s, PORT: %d\n", serv_hostname, inet_ntoa(servaddr.sin_addr), SERV_PORT);
    else printf("Server host: %s, IP: %s, PORT: %d\n", serv_hostname, inet_ntoa(servaddr.sin_addr), SERV_SSL_PORT);


    // Connect mail server with own socket
    if (connect(mailserver_sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("Forward socket connect failed");
        return NULL;
    }


    // If use STARTTLS mode
    // Connect socket and send EHLO/HELO first
    // then send "STARTTLS" to start a SSL/TLS Connect
    if (STARTTLS_FORWARD) {
        // Receiving 220
        bzero(recv_buf, sizeof(recv_buf));
        recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
        if (!strstr(recv_buf, "220")) {
            perror("Forward recv 220 failed");
            return NULL;
        }
        // Send EHLO/HELO
        bzero(recv_buf, sizeof(recv_buf));
        send(mailserver_sockfd, mail_info_ptr->ehlo, strlen(mail_info_ptr->ehlo), 0);
        recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
        if (!strstr(recv_buf, "250")) {
            perror("Forward EHLO/HELO failed");
            return NULL;
        }
        // STARTTLS
        bzero(recv_buf, sizeof(recv_buf));
        send(mailserver_sockfd, "STARTTLS\r\n", strlen("STARTTLS\r\n"), 0);
        recv(mailserver_sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
        if (!strstr(recv_buf, "220")) {
            perror("Forward STARTTLS failed");
            return NULL;
        }
    }


    // Create a client SSL ctx then bind socket to SSL
    SSL_CTX *serv_ctx = SSL_CTX_new(SSLv23_client_method());
    SSL *serv_ssl = SSL_new(serv_ctx);
    SSL_set_fd(serv_ssl, mailserver_sockfd);
    if (!SSL_connect(serv_ssl)) {
        perror("Forward SSL connect failed");
        close(mailserver_sockfd);
        return NULL;
    }
    printf("Forward SSL algorithm: %s\n", SSL_get_cipher(serv_ssl));


    // When SSL/TLS directly
    // Receiving 220 here
    if (!STARTTLS_FORWARD) {
        printf("Connecting mail server...\n");
        bzero(recv_buf, sizeof(recv_buf));
        SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
        if (!strstr(recv_buf, "220")) {
            perror("Forward recv 220 failed");
            return NULL;
        }
    }


    // Send EHLO/HELO
    bzero(recv_buf, sizeof(recv_buf));
    SSL_write(serv_ssl, mail_info_ptr->ehlo, strlen(mail_info_ptr->ehlo));  // send: ehlo
    SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
    if (!strstr(recv_buf, "250")) {
        perror("Forward SSL EHLO/HELO failed");
        return NULL;
    }


    // Send AUTH LOGIN/PLAIN
    bzero(recv_buf, sizeof(recv_buf));
    SSL_write(serv_ssl, mail_info_ptr->auth, strlen(mail_info_ptr->auth));
    if (*mail_info_ptr->user) {
        // AUTH LOGIN
        SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
        if (!strstr(recv_buf, "334")) {
            perror("Forward AUTH LOGIN failed");
            return NULL;
        }
        SSL_write(serv_ssl, mail_info_ptr->user, strlen(mail_info_ptr->user));
        bzero(recv_buf, sizeof(recv_buf));
        SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
        if (!strstr(recv_buf, "334")) {
            perror("Forward AUTH LOGIN failed");
            return NULL;
        }
        SSL_write(serv_ssl, mail_info_ptr->pwd, strlen(mail_info_ptr->pwd));
    }
    bzero(recv_buf, sizeof(recv_buf));
    SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
    if (!strstr(recv_buf, "235")) {
        perror("Forward AUTH failed");
        return NULL;
    }

    // Send sender information
    SSL_write(serv_ssl, mail_info_ptr->mail_from, strlen(mail_info_ptr->mail_from));
    bzero(recv_buf, sizeof(recv_buf));
    SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
    if (!strstr(recv_buf, "250")) {
        perror("Forward MAIL FROM failed");
        return NULL;
    }

    // Send receivers information
    for (int i = 0; i < MAX_RCPT_TO; i++) {
        if (*mail_info_ptr->rcpt_to[i]) {
            SSL_write(serv_ssl, mail_info_ptr->rcpt_to[i], strlen(mail_info_ptr->rcpt_to[i]));
            bzero(recv_buf, sizeof(recv_buf));
            SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
            if (!strstr(recv_buf, "250")) {
                perror("Forward RCPT TO failed");
                return NULL;
            }
        }
        else break;
    }

    // Send "data" command to start transport data
    SSL_write(serv_ssl, "data\r\n", strlen("data\r\n"));
    bzero(recv_buf, sizeof(recv_buf));
    SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
    if (!strstr(recv_buf, "354")) {
        perror("Forward DATA failed");
        return NULL;
    }
    // TODO:Anti DT:SPM
    bzero(mail_info_ptr->data_header, sizeof(mail_info_ptr->data_header));
    SSL_write(serv_ssl, mail_info_ptr->data_header, strlen(mail_info_ptr->data_header));

    // Send data
    SSL_write(serv_ssl, mail_info_ptr->data, strlen(mail_info_ptr->data));
    bzero(recv_buf, sizeof(recv_buf));
    SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
    if (!strstr(recv_buf, "250")) {
        perror("Forward send DATA failed");
        return NULL;
    }

    // Quit
    SSL_write(serv_ssl, "QUIT\r\n", strlen("QUIT\r\n"));
    bzero(recv_buf, sizeof(recv_buf));
    SSL_read(serv_ssl, recv_buf, BUFFER_MAX_LENGTH);
    if (!strstr(recv_buf, "221")) {
        perror("Forward QUIT failed");
        return NULL;
    }

    printf("Forward Success\n");

}


//
// Module Function: authenticate when receiving client's AUTH request,
// create a socket with mail server then try to authenticate,
// return TRUE or FALSE to show authenticate Success or Fail
//
BOOL auth_test(char *auth, char *user, char *pwd) {
    char serv_hostname[BUFFER_MAX_LENGTH];
    char recv_buf[BUFFER_MAX_LENGTH];
    char *pos = NULL;
    struct hostent *serv_host;
    struct sockaddr_in servaddr;
    int sockfd = 0;

    bzero(serv_hostname, sizeof(serv_hostname));
    bzero(&servaddr, sizeof(servaddr));
    // Determine mail host name by decode the AUTH info
    if (*user) {
        // AUTH LOGIN
        pos = base64_decode(user);
    }
    else {
        // AUTH PLAIN
        pos = strcasestr(auth, "plain ") + strlen("plain ");
        pos = base64_decode(pos);
    }
    if (pos = strchr(pos, '@')) {
        strcat(serv_hostname, "smtp.");
        strcat(serv_hostname, ++pos);
    }
    else {
        perror("Auth Test: Host b64decode failed");
        return FALSE;
    }
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Auth Test: Socket create failed");
        return FALSE;
    }
    // Solve host by name
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);
    if (!(serv_host = gethostbyname(serv_hostname))) {
        perror("Auth Test: Unknown host");
        return FALSE;
    }
    memcpy(&servaddr.sin_addr, serv_host->h_addr, serv_host->h_length);
    printf("Auth Test: Host: %s, IP: %s, PORT:%d\n", serv_hostname, inet_ntoa(servaddr.sin_addr), SERV_PORT);
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("Auth Test: Socket connect failed");
        return FALSE;
    }

    // Receive 220 from mail server
    printf("Auth Test: Connecting mail server...\n");
    bzero(recv_buf, sizeof(recv_buf));
    recv(sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "220")) {
        perror("Auth Test: recv 220 failed");
        return FALSE;
    }

    // Send EHLO/HELO
    bzero(recv_buf, sizeof(recv_buf));
    send(sockfd, "EHLO authtest\r\n", strlen("EHLO authtest\r\n"), 0);  // send: ehlo
    recv(sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "250")) {
        perror("Auth Test: EHLO/HELO failed");
        return FALSE;
    }

    // Try to authenticate with the key
    // provided by client
    bzero(recv_buf, sizeof(recv_buf));
    send(sockfd, auth, strlen(auth), 0);
    if (*user) {
        // AUTH LOGIN
        recv(sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
        if (!strstr(recv_buf, "334")) {
            perror("Auth Test: AUTH LOGIN failed");
            return FALSE;
        }
        send(sockfd, user, strlen(user), 0);
        bzero(recv_buf, sizeof(recv_buf));
        recv(sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
        if (!strstr(recv_buf, "334")) {
            perror("Auth Test: AUTH LOGIN failed");
            return FALSE;
        }
        send(sockfd, pwd, strlen(pwd), 0);
    }
    bzero(recv_buf, sizeof(recv_buf));
    recv(sockfd, recv_buf, BUFFER_MAX_LENGTH, 0);
    if (!strstr(recv_buf, "235")) {
        perror("Auth Test: AUTH failed");
        return FALSE;
    }
    printf("Auth Test Success\n");
    return TRUE;
}


//
// Module Function: Verify the mail address syntax received
// by locate '@' and '.' positions
//
BOOL valid_mailaddr(char *mailaddr) {
    char *pos1 = strchr(mailaddr, '<');
    char *pos2 = strchr(mailaddr, '>');

    if (!pos1 || !pos2) {
        return FALSE;
    }
    char *pos3 = strchr(pos1, '@');
    char *pos4 = strchr(pos1, '.');
    if (!pos3 || !pos4) {
        return FALSE;
    }
    if ((strchr(pos4, '.') - pos4) || pos4 <= pos3+1 || (strchr(pos3, '@') - pos3) || pos2 == pos4+1 || pos1 == pos3-1) {
        return FALSE;
    }
    return TRUE;
}


//
// Core Function: when receive quit request,
// close the connect by SSL way
//
int ssl_quit(FILE *fp, SSL *client_ssl, int client_sockfd) {
    SSL_write(client_ssl, kCommandInfo[4], strlen(kCommandInfo[4]));
    fclose(fp);
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_sockfd);
    return 0;
}


//
// Core Function: when receive quit request,
// close the connect by normal way
//
int normal_quit(FILE *fp, int client_sockfd) {
    send(client_sockfd, kCommandInfo[4], strlen(kCommandInfo[4]), 0);
    fclose(fp);
    close(client_sockfd);
    return 0;
}


//
// Module Function: base64 decode
//
unsigned char *base64_decode(unsigned char *code) {
    int table[] = {
        0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,62,0,0,0,
        63,52,53,54,55,56,57,58,
        59,60,61,0,0,0,0,0,0,0,0,
        1,2,3,4,5,6,7,8,9,10,11,12,
        13,14,15,16,17,18,19,20,21,
        22,23,24,25,0,0,0,0,0,0,26,
        27,28,29,30,31,32,33,34,35,
        36,37,38,39,40,41,42,43,44,
        45,46,47,48,49,50,51
        };
    int str_len = 0;
    unsigned char *res;

    int len = strlen(code);
    if (strstr(code, "=="))
        str_len = len / 4*3 - 2;
    else if (strstr(code, "="))
        str_len = len / 4*3 - 1;
    else
        str_len = len / 4*3;

    res = (char*)malloc(sizeof(unsigned char) * str_len + 1);
    res[str_len] = '\x00';

    for (int i = 0, j = 0; i < len - 2; j += 3, i += 4) {
        res[j] = ((unsigned char)table[code[i]]) << 2 | (((unsigned char)table[code[i + 1]]) >> 4);
        res[j + 1] = (((unsigned char)table[code[i + 1]]) << 4) | (((unsigned char)table[code[i + 2]]) >> 2);
        res[j + 2] = (((unsigned char)table[code[i + 2]]) << 6) | ((unsigned char)table[code[i + 3]]);
    }
    if (!res[0]) res++;
    return res;
}

