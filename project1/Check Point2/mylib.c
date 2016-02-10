/*
 * mylib.c
 * Author: jiaxingh
 * Project:1
 * CheckPoint: 2
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <err.h>
#include <errno.h>

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

// The following line declares a function pointer with the same prototype as the open function.  
int (*orig_open)(const char *pathname, int flags, ...);
int (*orig_close)(int pfd);
ssize_t (*orig_read)(int fildes, void *buf1, size_t nbyte);
ssize_t (*orig_write)(int handle, const void *buf1, size_t nbyte);
__off_t (*orig_lseek)(int fildes, __off_t offset, int whence);
int (*orig___xstat)(int ver, const char *filename, struct stat *stat_buf);
int (*orig_unlink)(const char *path);
ssize_t (*orig_getdirentries)(int fd, char *buf, ssize_t nbyte, long *basep);
struct dirtreenode* (*orig_getdirtree)(const char *pathname);
void (*orig_freedirtree)(struct dirtreenode* dt);

// This is the function that all other function will call
int callServer(void *message, int total_len){
    char *serverip;
    char *serverport;
    unsigned short port;
    void *msg = message;
    char buf[MAXMSGLEN + 1];
    int sockfd, rv;
    struct sockaddr_in srv;
    
    // Get environment variable indicating the ip address of the server
    serverip = getenv("server15440");
    if (serverip) {
        fprintf(stderr, "Got environment variable server15440: %s\n", serverip);
    } else {
        fprintf(stderr, "Environment variable server15440 not found.  Using 127.0.0.1\n");
        serverip = "127.0.0.1";
    }
    
    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (serverport){
        fprintf(stderr, "Got environment variable serverport15440: %s\n", serverport);
    } else {
        fprintf(stderr, "Environment variable serverport15440 not found.  Using 15440\n");
        serverport = "15440";
    }
    port = (unsigned short)atoi(serverport);
    
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        err(1, 0);
    }
    
    // setup address structure to point to server
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = inet_addr(serverip);
    srv.sin_port = htons(port);
    
    // actually connect to the server
    rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) {
        err(1,0);
    }
    
    // send message to server
    send(sockfd, msg, total_len, 0);
    
    // get message back
    rv = recv(sockfd, buf, sizeof(return_type), 0);
    if (rv<0) {
        err(1,0);
    }
    
    // get the info in returned message
    return_type *return_info_p = (return_type *)buf;
    fprintf(stderr, "client got messge: response is %d, err is %d\n",
            return_info_p->response, return_info_p->err);
    errno = return_info_p->err;
    
    // close socket
    orig_close(sockfd);
    return return_info_p->response;
}
// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
    
    mode_t m=0;
    int len = strlen(pathname);
    int total_len = sizeof(request_header_t) +
                    sizeof(open_request_header_t) +
                    (len + 1) * sizeof(char);
    //print all the arguments
    fprintf(stderr, "flag is %d, the total_len is %d\n", flags, total_len);
    
    // set the mode
    if (flags & O_CREAT) {
        va_list a;
        va_start(a, flags);
        m = va_arg(a, mode_t);
        va_end(a);
    }
    
    // malloc the buf to save the info
    void *buf = malloc(total_len);
    
    // assign space to save the info
    request_header_t *header = (request_header_t *)buf;
    open_request_header_t *open_header = (open_request_header_t *)(header->data);
    char *open_filename = (char *)open_header->data;
    header->opcode = OPEN;
    header->total_len = total_len;
    open_header->flag = flags;
    open_header->mode = m;
    open_header->filename_len = len;
    strcpy(open_filename, pathname);
    *((char *)buf + total_len - 1) = 0;
    
    // check basic info
    fprintf(stderr, "filename is %s\n", open_filename);
    fprintf(stderr, "open from remote\n");
    
    // call the server
    int answer = callServer(buf, total_len);
    free(buf);
    
    return answer;
}

// This is our replacement for the close function from libc
int close(int pfd) {
    // get the len
    int total_len = sizeof(request_header_t) + sizeof(close_request_header_t);
    
    //malloc the space
    void *buf = malloc(total_len);
    
    //assign the space
    request_header_t *header = (request_header_t *)buf;
    close_request_header_t *close_header = (close_request_header_t *)(header->data);
    header->opcode = CLOSE;
    header->total_len = total_len;
    close_header->pfd = pfd;
    
    // for checking
    fprintf(stderr, "close from remote\n");
    
    // call the server
    int answer = callServer(buf, total_len);
    free(buf);
    
    return answer;
}

// This is our replacement for the read function from libc
ssize_t read(int fildes, void *buf1, size_t nbyte) {
    callServer("read", 0);
    
    return orig_read(fildes, buf1, nbyte);
}

// This is our replacement for the write function from libc
ssize_t write(int handle, const void *buf1, size_t nbyte) {
    // get the len
    int total_len = sizeof(request_header_t) + sizeof(write_request_header_t)
                    + nbyte * sizeof(char);
    
    // malloc the space
    void *buf = malloc(total_len);
    
    // assign the space
    request_header_t *header = (request_header_t *)buf;
    write_request_header_t *write_header = (write_request_header_t *)(header->data);
    char *write_buf = (char *)write_header->data;
    header->opcode = WRITE;
    header->total_len = total_len;
    write_header->handle = handle;
    write_header->nbyte = nbyte;
    memcpy(write_buf, buf1, nbyte);
    
    // checking
    fprintf(stderr, "write from remote\n");
    
    // call the server
    ssize_t answer = (ssize_t)callServer(buf, total_len);
    free(buf);
    
    return answer;
}

// This is our replacement for the lseek function from libc
__off_t lseek(int fildes, __off_t offset, int whence) {
    callServer("lseek", 0);
    
    return orig_lseek(fildes, offset, whence);
}

// This is our replacement for the stat function from libc
int __xstat(int ver, const char *filename, struct stat *stat_buf) {
    callServer("__xstat", 0);
    
    return orig___xstat(ver, filename, stat_buf);
}

// This is our replacement for the unlink function from libc
int unlink(const char *path) {
    callServer("unlink", 0);
    
    return orig_unlink(path);
}

// This is our replacement for the getdirentries function from libc
ssize_t getdirentries(int fd, char *buf, size_t nbyte, long *basep) {
    callServer("getdirentries", 0);
    
    return orig_getdirentries(fd, buf, nbyte, basep);
}

struct dirtreenode* getdirtree(const char *pathname) {
    // Send message from client to server
    callServer("getdirtree\n", 0);
    
    // Return the original function
    return orig_getdirtree(pathname);
}

void freedirtree(struct dirtreenode* dt) {
    // Send message from client to server
    callServer("freedirtree\n", 0);
    
    // Call the original function
    orig_freedirtree(dt);
}

// This function is automatically called when program is started
void _init(void) {
	// set function pointer orig_open to point to the original open function
    orig_open = dlsym(RTLD_NEXT, "open");
    orig_close = dlsym(RTLD_NEXT, "close");
    orig_read = dlsym(RTLD_NEXT, "read");
    orig_write = dlsym(RTLD_NEXT, "write");
    orig_lseek = dlsym(RTLD_NEXT, "lseek");
    orig___xstat = dlsym(RTLD_NEXT, "__xstat");
    orig_unlink = dlsym(RTLD_NEXT, "unlink");
    orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
    orig_getdirtree = dlsym(RTLD_NEXT, "getdirtree");
    orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");
    
	fprintf(stderr, "Init mylib\n");
}


