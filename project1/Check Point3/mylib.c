/*
 * mylib.c
 * Author: jiaxingh
 * Project:1
 * CheckPoint: 3
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
#include "../include/dirtree.h"


// Save the length of integer as the max length
#define MAXMSGLEN sizeof(int)

// Define the operator number
#define OPEN 1
#define CLOSE 2
#define READ 3
#define WRITE 4
#define LSEEK 5
#define __XSTAT 6
#define UNLINK 7
#define GETDE 8
#define GETDT 9
#define FREEDT 10

/************************************/
// The request struct declaration
#pragma pack(1)

typedef struct {
    int total_len;
    int opcode;
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
    int fildes;
    void *buf1;
    size_t nbyte;
} read_request_header_t;

typedef struct {
    int handle;
    size_t nbyte;
    unsigned char data[0];
} write_request_header_t;

typedef struct {
    int fildes;
    __off_t offset;
    int whence;
} lseek_request_header_t;

typedef struct {
    int ver;
    int filename_len;
    struct stat *stat_buf;
    unsigned char data[0];
} __xstat_request_header_t;

typedef struct {
    int filename_len;
    unsigned char data[0];
} unlink_request_header_t;

typedef struct {
    int fd;
    char *buf1;
    ssize_t nbyte;
    __off_t *basep;
    __off_t base;
} getde_request_header_t;

typedef struct {
    int pathname_len;
    unsigned char data[0];
} getdt_request_header_t;

typedef struct {
    int total_len;
    int response;
    int err;
    unsigned char data[0];
} return_type;

typedef struct {
    int name_len;
    int num_subdirs;
    unsigned char data[0];
} return_node_type;

/************************************/

// The following lines are declearation of functions
/************************************/
int (*orig_open)(const char *pathname, int flags, ...);
int (*orig_close)(int pfd);
ssize_t (*orig_read)(int fildes, void *buf1, size_t nbyte);
ssize_t (*orig_write)(int handle, const void *buf1, size_t nbyte);
__off_t (*orig_lseek)(int fildes, __off_t offset, int whence);
int (*orig___xstat)(int ver, const char *filename, struct stat *stat_buf);
int (*orig_unlink)(const char *path);
ssize_t (*orig_getdirentries)(int fd, char *buf1, ssize_t nbyte, __off_t *basep);
struct dirtreenode* (*orig_getdirtree)(const char *pathname);
void (*orig_freedirtree)(struct dirtreenode* dt);
void construct(struct dirtreenode **sub);
/************************************/

// These are some global variables
int sockfd;
char *data_start;

/*
 * This function is used to call server and transfer
 * data from local to server by TCP
 * Also, it can receive the response data
 */
double callServer(void *message){
    
    void *msg = message;
    char buf_len[MAXMSGLEN];
    
    // Get the header info in message
    request_header_t *header = (request_header_t *)msg;
    int opcode = (int)header->opcode;
    int total_len = (int)header->total_len;
    int rv = 0;
    
    // Send message to server
    send(sockfd, msg, total_len, 0);
    
    // Get response header back
    rv = recv(sockfd, buf_len, MAXMSGLEN, 0);
    if (rv<0) {
        err(1,0);
    }
    int total_len_r = *((int *)buf_len);
    char *buf = malloc(total_len_r);
    total_len_r -= sizeof(int);
    int pos = sizeof(int);
    int rest = total_len_r;
    
    // Use loop to receive the
    while ((rv = recv(sockfd, buf + pos, rest, 0)) > 0) {
        pos += rv;
        rest -=rv;
        if (rest == 0) {
            break;
        }
    }
    
    // Get the info in returned message
    return_type *return_info_p = (return_type *)buf;
    return_info_p->total_len = total_len_r + sizeof(int);
    
    // Handle the info in the response
    int response = return_info_p->response;
    errno = return_info_p->err;
    
    // If the opcode is read, buf would return a string in the end
    if (opcode == READ) {
        read_request_header_t *read_header =
            (read_request_header_t *)header->data;
        memcpy(read_header->buf1, return_info_p->data,
               read_header->nbyte);
    }
    
    // If the opcode is __xstat, buf would return a struct in the end
    if (opcode == __XSTAT) {
        __xstat_request_header_t *__xstat_header =
            (__xstat_request_header_t *)header->data;
        memcpy(__xstat_header->stat_buf, return_info_p->data,
               sizeof(struct stat));
    }
    
    // If the opcode is getde, buf would return a ssize_t and a string
    if (opcode == GETDE) {
        getde_request_header_t *getde_header =
            (getde_request_header_t *)header->data;
        *(getde_header->basep) = (__off_t)return_info_p->data;
        memcpy(getde_header->buf1, return_info_p->data
               + sizeof(__off_t), getde_header->nbyte);
    }
    
    free(buf);
    return (double)response;
}

// This is the function for tree to send data
struct dirtreenode * callTreeServer(void *message){
    
    
    void *msg = message;
    char buf_len[MAXMSGLEN];
    
    // Get the message in header
    request_header_t *header = (request_header_t *)msg;
    int opcode = (int)header->opcode;
    int total_len = (int)header->total_len;
    int rv = 0;
    
    // Send message to server
    send(sockfd, msg, total_len, 0);
    
    // Get response header back
    rv = recv(sockfd, buf_len, MAXMSGLEN, 0);
    if (rv<0) {
        err(1,0);
    }
    int total_len_r = *((int *)buf_len);
    char *buf = malloc(total_len_r);
    total_len_r -= sizeof(int);
    rv = recv(sockfd, buf + sizeof(int), total_len_r, 0);
    
    // Get the info in returned message
    return_type *return_info_p = (return_type *)buf;
    return_info_p->total_len = total_len_r + sizeof(int);
    errno = return_info_p->err;
    
    // Ff the opcode is getdt, buf would return a long data or null
    if (opcode == GETDT) {
        if (return_info_p->response == 0) {
            free(buf);
            return NULL;
        }
        // Build the tree
        struct dirtreenode *root =
            (struct dirtreenode *)malloc(sizeof(struct dirtreenode));
        return_node_type *node_header =
            (return_node_type *)return_info_p->data;
        int len = node_header->name_len;
        int num_subdirs = node_header->num_subdirs;
        int my_size = len * sizeof(char) + sizeof(return_type);
        data_start = (char *)return_info_p->data + my_size;
        
        // Recursively build the sub trees
        root->num_subdirs = num_subdirs;
        memcpy(root->name, node_header->data, len);
        root->subdirs = (struct dirtreenode **)
            malloc(num_subdirs * sizeof(struct dirtreenode *));
        int i = 0;
        for (i = 0; i < root->num_subdirs; i ++) {
            construct(root->subdirs + i);
        }
        free(buf);
        return root;
    }
    
    return NULL;
}

// This function is used to build the tree
void construct(struct dirtreenode **sub) {
    
    struct dirtreenode *node = (struct dirtreenode *)
        malloc(sizeof(struct dirtreenode));
    
    return_node_type *node_header = (return_node_type *)data_start;
    int len = node_header->name_len;
    int num_subdirs = node_header->num_subdirs;
    int my_size = len * sizeof(char) + sizeof(return_type);
    data_start = data_start + my_size;
    
    node->num_subdirs = num_subdirs;
    memcpy(node->name, node_header->data, len);
    node->subdirs = (struct dirtreenode **)
        malloc(num_subdirs * sizeof(struct dirtreenode *));
    int i = 0;
    for (i = 0; i < num_subdirs; i ++) {
        construct(node->subdirs + i);
    }
    
    *sub = node;
}

// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
    
    mode_t m=0;
    int len = strlen(pathname);
    int total_len = sizeof(request_header_t) +
                    sizeof(open_request_header_t) +
                    (len + 1) * sizeof(char);
    
    // Set the mode
    if (flags & O_CREAT) {
        va_list a;
        va_start(a, flags);
        m = va_arg(a, mode_t);
        va_end(a);
    }
    
    // Malloc the buf to save the info
    void *buf = malloc(total_len);
    
    // Assign space to save the info
    request_header_t *header = (request_header_t *)buf;
    open_request_header_t *open_header =
        (open_request_header_t *)(header->data);
    char *open_filename = (char *)open_header->data;
    header->opcode = OPEN;
    header->total_len = total_len;
    open_header->flag = flags;
    open_header->mode = m;
    open_header->filename_len = len;
    strcpy(open_filename, pathname);
    *((char *)buf + total_len - 1) = 0;
    
    // Call the server
    int answer = (int)callServer(buf);
    free(buf);
    
    return answer;
}

// This is our replacement for the close function from libc
int close(int pfd) {
    
    // Get the total len
    int total_len = sizeof(request_header_t) + sizeof(close_request_header_t);
    
    // Malloc the space
    void *buf = malloc(total_len);
    
    // Assign the space
    request_header_t *header = (request_header_t *)buf;
    close_request_header_t *close_header =
        (close_request_header_t *)(header->data);
    header->opcode = CLOSE;
    header->total_len = total_len;
    close_header->pfd = pfd;
    
    // Call the server
    int answer = (int)callServer(buf);
    free(buf);
    
    return answer;
}

// This is our replacement for the read function from libc
ssize_t read(int fildes, void *buf1, size_t nbyte) {
    
    // Get the len
    int total_len = sizeof(request_header_t) + sizeof(read_request_header_t);
    
    // Malloc the space
    void *buf = malloc(total_len);
    
    // Assign the space
    request_header_t *header = (request_header_t *)buf;
    read_request_header_t *read_header = (read_request_header_t *)header->data;
    header->opcode = READ;
    header->total_len = total_len;
    read_header->fildes = fildes;
    read_header->buf1 = buf1;
    read_header->nbyte = nbyte;
    
    // Call the server
    int answer = (size_t)callServer(buf);
    free(buf);
    
    return answer;
}

// This is our replacement for the write function from libc
ssize_t write(int handle, const void *buf1, size_t nbyte) {
    // Get the len
    int total_len = sizeof(request_header_t)
        + sizeof(write_request_header_t) + nbyte * sizeof(char);
    
    // Malloc the space
    void *buf = malloc(total_len);
    
    // Assign the space
    request_header_t *header = (request_header_t *)buf;
    write_request_header_t *write_header =
        (write_request_header_t *)(header->data);
    char *write_buf = (char *)write_header->data;
    header->opcode = WRITE;
    header->total_len = total_len;
    write_header->handle = handle;
    write_header->nbyte = nbyte;
    memcpy(write_buf, buf1, nbyte);
    
    // Call the server
    ssize_t answer = (ssize_t)callServer(buf);
    free(buf);
    
    return answer;
}

// This is our replacement for the lseek function from libc
__off_t lseek(int fildes, __off_t offset, int whence) {
    
    // Get the len
    int total_len = sizeof(request_header_t)
        + sizeof(lseek_request_header_t);
    
    // Malloc the space
    void *buf = malloc(total_len);
    
    // Assign the space
    request_header_t *header = (request_header_t *)buf;
    lseek_request_header_t * lseek_header =
        (lseek_request_header_t *)header->data;
    header->opcode = LSEEK;
    header->total_len = total_len;
    lseek_header->fildes = fildes;
    lseek_header->offset = offset;
    lseek_header->whence = whence;
    
    // Call the server
    __off_t answer = (__off_t)callServer(buf);
    free(buf);
    
    return answer;;
}

// This is our replacement for the stat function from libc
int __xstat(int ver, const char *filename, struct stat *stat_buf) {
    
    // Get the len
    int len = strlen(filename) + 1;
    int total_len = sizeof(request_header_t)
        + sizeof(__xstat_request_header_t) + len * sizeof(char);
    
    // Malloc the space
    void *buf = malloc(total_len);
    
    // Assign the space
    request_header_t *header = (request_header_t *)buf;
    __xstat_request_header_t *__xstat_header =
        (__xstat_request_header_t *)header->data;
    header->opcode = __XSTAT;
    header->total_len = total_len;
    __xstat_header->ver = ver;
    __xstat_header->filename_len = len;
    __xstat_header->stat_buf = stat_buf;
    memcpy(__xstat_header->data, filename, len);
    
    // Call the server
    int answer = (int)callServer(buf);
    free(buf);
    
    return answer;
}

// This is our replacement for the unlink function from libc
int unlink(const char *path) {
    
    // Get the len
    int len = strlen(path) + 1;
    int total_len = sizeof(request_header_t)
        + sizeof(unlink_request_header_t) + len * sizeof(char);
    
    // Malloc the space
    void *buf = malloc(total_len);
    
    // Assign the space
    request_header_t *header = (request_header_t *)buf;
    unlink_request_header_t *unlink_header =
        (unlink_request_header_t *)header->data;
    header->opcode = UNLINK;
    header->total_len = total_len;
    unlink_header->filename_len = len;
    memcpy(unlink_header->data, path, len);
    
    // Call the server
    int answer = (int)callServer(buf);
    free(buf);
    
    return answer;
}

// This is our replacement for the getdirentries function from libc
ssize_t getdirentries(int fd, char *buf1, size_t nbyte, __off_t *basep) {
    
    // Get the len
    int total_len = sizeof(request_header_t)
        + sizeof(getde_request_header_t);
    
    // Malloc the space
    void *buf = malloc(total_len);
    
    // Assign the space
    request_header_t *header = (request_header_t *)buf;
    getde_request_header_t *getde_header =
        (getde_request_header_t *)header->data;
    header->opcode = GETDE;
    header->total_len = total_len;
    getde_header->fd = fd;
    getde_header->buf1 = buf1;
    getde_header->nbyte = nbyte;
    getde_header->basep = basep;
    getde_header->base = *basep;
    
    // Call the server
    ssize_t answer = (ssize_t)callServer(buf);
    free(buf);
    
    return answer;
}

// This is our replacement for getdirtree from libc
struct dirtreenode* getdirtree(const char *pathname) {
    
    // Get the len
    int len = strlen(pathname);
    int total_len = sizeof(request_header_t)
        + sizeof(getdt_request_header_t) + (len + 1) * sizeof(char);
    
    // Malloc the space
    char *buf = malloc(total_len);
    
    // Assign the space
    request_header_t *header = (request_header_t *)buf;
    getdt_request_header_t *getdt_header =
        (getdt_request_header_t *)header->data;
    header->opcode = GETDT;
    header->total_len = total_len;
    getdt_header->pathname_len = len;
    memcpy(getdt_header->data, pathname, len);
    
    // send the data
    struct dirtreenode *answer = callTreeServer(buf);
    
    // Return the original function
    return answer;
}

// no need to use rpc
void freedirtree(struct dirtreenode* dt) {
    
    //checking
    fprintf(stderr, "freedirtree from local\n");
    
    // Call the original function
    orig_freedirtree(dt);
}

// This function is automatically called when program is started
void _init(void) {
    
	// Set function pointer orig_open to point to the original open function
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
    
    // Define some variables
    char *serverip;
    char *serverport;
    unsigned short port;
    int rv;
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
    
    // Setup address structure to point to server
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = inet_addr(serverip);
    srv.sin_port = htons(port);
    
    // Actually connect to the server
    rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) {
        err(1,0);
    }
    
}

// will be called in the end
void _fini() {
    
    // close socket
    orig_close(sockfd);
}


