#pragma once
#ifndef __SMTP_SERVER_H__
#define __SMTP_SERVER_H__
#define _GNU_SOURCE
#define TRUE                1
#define FALSE               0
#define BOOL                int

// Global switchers
#define USE_SSL             1
#define DEBUG               1
#define STARTTLS_FORWARD    0
#define USE_MULTITHREADING  1

// Basic setting
#define BUFFER_MAX_LENGTH   4096
#define MAX_RCPT_TO         5  // max receivers
#define LISTEN_THREADS_NUM  50

// SSL setting
#define SSL_CERT            "../ssl/server/public/server.pem"
#define SSL_KEY             "../ssl/server/private/server.key"

// Socket setting
#define SMTP_PORT           25
#define SERV_PORT           25
#define SERV_SSL_PORT       465
#define LISTEN_QUENE_LENGTH 5

// Core functions
int init();
SSL_CTX * init_ssl();
int init_socket();
int run(int);
int ssl_daemon(int);
int normal_daemon(int);
int ssl_quit(FILE*, SSL*, int);
int normal_quit(FILE*, int);
void * ssl_forward();
void * normal_forward(void*);
void * thread_func(void*);

// Module functions
BOOL valid_mailaddr(char*);
BOOL auth_test(char*, char*, char*);
unsigned char *base64_decode(unsigned char*);
extern char *strcasestr(const char*, const char*);
#endif
