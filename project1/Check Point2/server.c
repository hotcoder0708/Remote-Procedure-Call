/*
 * server.c
 * Author: jiaxingh
 * Project:1
 * CheckPoint: 2
 */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <stdarg.h>

#define MAXMSGLEN 5000

#define OPEN 1
#define CLOSE 2
#define READ 3
#define WRITE 4
#define LSEEK 5
#define _XSTAT 6
#define UNLINK 7
#define GETDE 8
#define GETDT 9
#define FREEDT 10

// The request struct declaration
#pragma pack(0)

typedef struct {
    int opcode;
    int total_len;
    unsigned char data[0];
} request_header_t;

typedef struct {
    int flag;
    mode_t mode;
    int filename_len;
    unsigned char data[0];
} open_request_header_t;

typedef struct {
    int pfd;
} close_request_header_t;

typedef struct {
    int handle;
    size_t nbyte;
    unsigned char data[0];
} write_request_header_t;

typedef struct {
    int response;
    int err;
} return_type;

// The main function
int main(int argc, char**argv) {
    char *msg="Hello from server";
    char buf[MAXMSGLEN+1];
    char *serverport;
    unsigned short port;
    int sockfd, sessfd, rv;
    struct sockaddr_in srv, cli;
    socklen_t sa_size;
    return_type return_info = {0, 0};
    return_type *return_info_p = &return_info;
    
    
    
    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (serverport) port = (unsigned short)atoi(serverport);
    else port=15440;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd<0) err(1, 0);
    
    // setup address structure to indicate server port
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = htonl(INADDR_ANY);
    srv.sin_port = htons(port);
    
    // bind to our port
    rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) err(1,0);
    
    // start listening for connections
    rv = listen(sockfd, 5);
    if (rv<0) err(1,0);
    
    //server says hello to you!
    fprintf(stderr, "%s\n", msg);
    
    // main server loop
    while (1) {
        
        // wait for next client, get session socket
        sa_size = sizeof(struct sockaddr_in);
        sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
        if (sessfd<0) err(1,0);
        
        // client connected, receive the request header
        rv = recv(sessfd, buf, sizeof(request_header_t), 0);
        fprintf(stderr, "recieved data1 is %d\n", rv);
        
        // pos record the current pos in data flow
        int pos = rv;
        
        // get all the info in request header
        request_header_t *header = (request_header_t *)buf;
        int opcode = (int)header->opcode;
        int total_len = (int)header->total_len - sizeof(request_header_t);
        fprintf(stderr, "opcode is %d, total len is %d\n", opcode, total_len);
        
        // receive the specific header data
        while ((rv=recv(sessfd, buf + pos, total_len, 0)) > 0) {
            pos += rv;
            total_len -= rv;
            if (total_len == 0) {
                break;
            }
        }
        
        // execute according to different operation
        switch (opcode) {
            case OPEN:
            {
                // get all the info in specific header
                open_request_header_t *open_header = (open_request_header_t *)header->data;
                int flag = (int)open_header->flag;
                mode_t mode = (mode_t)open_header->mode;
                char *filename = (char *)open_header->data;
                fprintf(stderr, "flag is %d, mode is %d, filename is %s\n", flag, (int)mode, filename);
                
                // set the return info
                return_info_p->response = (int)open(filename, flag, mode);
                return_info_p->err = errno;
                
                break;
            }
            case CLOSE:
            {
                // get all the info in specific header
                close_request_header_t *close_header = (close_request_header_t *)header->data;
                int pfd = (int)close_header->pfd;
                
                // set the return info
                return_info_p->response = close(pfd);
                return_info_p->err = errno;
                
                break;
            }
            case WRITE:
            {
                // get all the info in specific header
                write_request_header_t *write_header = (write_request_header_t *)header->data;
                int handle = (int)write_header->handle;
                size_t nbyte = (size_t)write_header->nbyte;
                char *buf1 = (char *)write_header->data;
                
                // add EOF in the end
                buf1[nbyte] = '\0';
                fprintf(stderr, "handle is %d, buf is %s, nbyte is %d\n",
                        (int)write_header->handle, buf1, (int)write_header->nbyte);
                
                // set the return info
                return_info_p->response = (int)write(handle, buf1, nbyte);
                return_info_p->err = errno;
                
                break;
            }
        }
        
        // send reply to client
        send(sessfd, return_info_p, sizeof(return_type), 0);
        
        // either client closed connection, or error
        if (rv<0) err(1,0);
        close(sessfd);
    }
    
    // close socket
    fprintf(stderr, "server shutting down cleanly\n");
    close(sockfd);
    
    return 0;
}

