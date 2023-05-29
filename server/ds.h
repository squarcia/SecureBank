#ifndef DS_H_
#define DS_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

struct transaction_info {

    char* recipient;
    char* amount;
    char* timestamp;

    struct transaction_info* next;
};

struct user_info {

    char* username;
    double balance;

    struct transaction_info* transaction_list;
};

#endif
