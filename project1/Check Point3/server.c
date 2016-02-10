/*
 * server.c
 * Author: jiaxingh
 * Project:1
 * CheckPoint: 3
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
#include "../include/dirtree.h"

// Max length to save the data get from client
#define MAXMSGLEN sizeof(request_header_t)

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


// The request struct declaration
#pragma pack(1)
/*********************************/
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
/*********************************/

// Below are declaration of functions
ssize_t getdirentries(int fd, char *buf1, ssize_t nbyte, __off_t *basep);
void constructTree(struct dirtreenode *root, char **tree_buf);
int getTreeSize(struct dirtreenode *root);

// The main function
int main(int argc, char**argv) {
    
    char buf_len[MAXMSGLEN];
    char *serverport;
    unsigned short port;
    int sockfd, sessfd, rv;
    struct sockaddr_in srv, cli;
    socklen_t sa_size;
    return_type *return_info_p;
    int return_len = 0;

    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (serverport) port = (unsigned short)atoi(serverport);
    else port=15440;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd<0) err(1, 0);
    
    // Setup address structure to indicate server port
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = htonl(INADDR_ANY);
    srv.sin_port = htons(port);
    
    // Bind to our port
    rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) err(1,0);
    
    // Start listening for connections
    rv = listen(sockfd, 5);
    if (rv<0) err(1,0);
    
    // Main server loop
    while (1) {
        
        // wait for next client, get session socket
        sa_size = sizeof(struct sockaddr_in);
        sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
        if (sessfd<0) err(1,0);
        
        // use fork to handle concurrency
        int pid;
        if ((pid = fork()) == 0) {
            close(sockfd);
            
            while (1) {
                // client connected, receive the request header
                rv = recv(sessfd, buf_len, MAXMSGLEN, 0);
                if (rv<0) {
                    err(1,0);
                }
                
                //judge whether the client ends the connection
                if (rv == 0) {
                    // either client closed connection, or error
                    close(sessfd);
                    exit(0);
                    break;
                }
                
                // pos record the current pos in data flow
                int pos = rv;
                
                // get all the info in request header
                request_header_t *header = (request_header_t *)buf_len;
                int opcode = (int)header->opcode;
                int total_len = (int)header->total_len;
                int rest =  total_len - sizeof(request_header_t);
                
                char *buf = malloc(total_len);
                header = (request_header_t *)buf;
                
                // receive the specific header data
                while ((rv=recv(sessfd, buf + pos, rest, 0)) > 0) {
                    pos += rv;
                    rest -= rv;
                    if (rest == 0) {
                        break;
                    }
                }
                
                // execute according to different operation
                switch (opcode) {
                    case OPEN:
                    {
                        // get all the info in specific header
                        open_request_header_t *open_header =
                            (open_request_header_t *)header->data;
                        int flag = (int)open_header->flag;
                        mode_t mode = (mode_t)open_header->mode;
                        char *filename = (char *)open_header->data;
                        
                        // set the return info
                        return_len = sizeof(return_type);
                        return_info_p = (return_type *)malloc(return_len);
                        return_info_p->response = (int)open(filename, flag, mode);
                        return_info_p->err = errno;
                        return_info_p->total_len = return_len;
                        
                        break;
                    }
                    case CLOSE:
                    {
                        // get all the info in specific header
                        close_request_header_t *close_header =
                            (close_request_header_t *)header->data;
                        int pfd = (int)close_header->pfd;
                        
                        // set the return info
                        return_len = sizeof(return_type);
                        return_info_p = (return_type *)malloc(return_len);
                        return_info_p->response = close(pfd);
                        return_info_p->err = errno;
                        return_info_p->total_len = return_len;
                        
                        break;
                    }
                    case READ:
                    {
                        //get all the info in specific header
                        read_request_header_t *read_header =
                            (read_request_header_t *)header->data;
                        int fildes = read_header->fildes;
                        size_t nbyte = read_header->nbyte;
                        
                        //set the return info
                        return_len = sizeof(return_type) + nbyte;
                        return_info_p = (return_type *)malloc(return_len);
                        unsigned char *return_buf = malloc(nbyte);
                        return_info_p->response = read(fildes, return_buf, nbyte);
                        return_info_p->err = errno;
                        memcpy(return_info_p->data, return_buf, nbyte);
                        return_info_p->total_len = return_len;
                        free(return_buf);
                        
                        break;
                    }
                    case WRITE:
                    {
                        // get all the info in specific header
                        write_request_header_t *write_header =
                            (write_request_header_t *)header->data;
                        int handle = (int)write_header->handle;
                        size_t nbyte = (size_t)write_header->nbyte;
                        char *buf1 = (char *)write_header->data;
                        
                        // add EOF in the end
                        buf1[nbyte] = '\0';
                        fprintf(stderr, "handle is %d, buf is %s, nbyte is %d\n",
                                (int)write_header->handle, buf1, (int)write_header->nbyte);
                        
                        // set the return info
                        return_len = sizeof(return_type);
                        return_info_p = (return_type *)malloc(return_len);
                        return_info_p->response = (int)write(handle, buf1, nbyte);
                        return_info_p->err = errno;
                        return_info_p->total_len = return_len;
                        
                        break;
                    }
                    case LSEEK:
                    {
                        // get all the info in specific header
                        lseek_request_header_t *lseek_header =
                            (lseek_request_header_t *)header->data;
                        int fildes = lseek_header->fildes;
                        __off_t offset = lseek_header->offset;
                        int whence = lseek_header->whence;
                        
                        // set the return info
                        return_len = sizeof(return_type);
                        return_info_p = (return_type *)malloc(return_len);
                        return_info_p->response = (int)lseek(fildes, offset, whence);
                        return_info_p->err = errno;
                        return_info_p->total_len = return_len;
                        
                        break;
                    }
                    case UNLINK:
                    {
                        // get all the info in specific header
                        unlink_request_header_t *unlink_header =
                            (unlink_request_header_t *)header->data;
                        int filename_len = unlink_header->filename_len;
                        char *filename = malloc(filename_len);
                        memcpy(filename, unlink_header->data, filename_len);
                        
                        // set the return info
                        return_len = sizeof(return_type);
                        return_info_p = (return_type *)malloc(return_len);
                        return_info_p->response = (int)unlink(filename);
                        return_info_p->err = errno;
                        return_info_p->total_len = return_len;
                        
                        free(filename);
                        
                        break;
                    }
                    case __XSTAT:
                    {
                        // get all the info in specific header
                        __xstat_request_header_t * __xstat_header =
                            (__xstat_request_header_t *)header->data;
                        int ver = __xstat_header->ver;
                        int filename_len = __xstat_header->filename_len;
                        char *filename = malloc(filename_len);
                        memcpy(filename, __xstat_header->data, filename_len);
                        struct stat *stat_buf = malloc(sizeof(struct stat));
                        
                        // set the return info
                        return_len = sizeof(return_type) + sizeof(struct stat);
                        return_info_p = (return_type *)malloc(return_len);
                        return_info_p->response = __xstat(ver, filename, stat_buf);
                        return_info_p->err = errno;
                        memcpy(return_info_p->data, stat_buf, sizeof(struct stat));
                        return_info_p->total_len = return_len;
                        
                        free(filename);
                        free(stat_buf);
                        
                        break;
                    }
                    case GETDE:
                    {
                        // get all the info in specific header
                        getde_request_header_t *getde_header =
                            (getde_request_header_t *)header->data;
                        int fd = getde_header->fd;
                        ssize_t nbyte = getde_header->nbyte;
                        char *buf1 = malloc(nbyte);
                        __off_t base = getde_header->base;
                        
                        // set the return info
                        return_len = sizeof(return_type) + sizeof(ssize_t) + nbyte;
                        return_info_p = (return_type *)malloc(return_len);
                        return_info_p->response = (int)getdirentries(fd, buf1, nbyte, &base);
                        return_info_p->err = errno;
                        ssize_t *base_p = (ssize_t *)return_info_p->data;
                        *base_p = base;
                        memcpy(return_info_p->data + sizeof(ssize_t), buf1, nbyte);
                        return_info_p->total_len = return_len;
                        
                        free(buf1);
                        
                        break;
                        
                    }
                    case GETDT:
                    {
                        // get all the info in specific header
                        getdt_request_header_t *getdt_header =
                            (getdt_request_header_t *)header->data;
                        int len = getdt_header->pathname_len;
                        char *pathname = (char *)malloc(len);
                        memcpy(pathname, getdt_header->data, len);
                        
                        // set return info
                        struct dirtreenode *root = getdirtree(pathname);
                        if (root == NULL) {
                            return_len = sizeof(return_type);
                            return_info_p = (return_type *)malloc(return_len);
                            return_info_p->response = 0;
                            return_info_p->err = errno;
                            return_info_p->total_len = return_len;
                        } else {
                            int tree_size = getTreeSize(root);
                            char *tree_buf = (char *)malloc(tree_size);
                            constructTree(root, &tree_buf);
                            
                            // set return info
                            return_len = sizeof(return_type) + tree_size;
                            return_info_p = (return_type *)malloc(return_len);
                            return_info_p->response = tree_size;
                            return_info_p->err = errno;
                            memcpy(return_info_p->data, tree_buf, tree_size);
                            return_info_p->total_len = return_len;
                            
                            free(tree_buf);
                        }
                        
                        free(pathname);
                        break;
                    }
                }
                
                // send reply to client
                send(sessfd, return_info_p, return_len, 0);
                free(return_info_p);
                free(buf);
            }
        }
        // for parent
        close(sessfd);
    }
    
    // close socket
    close(sockfd);
    
    return 0;
}

int getTreeSize(struct dirtreenode *root) {
    int my_size = (strlen(root->name) + 1) * sizeof(char) + sizeof(return_node_type);
    int i = 0;
    for (i = 0; i < root->num_subdirs; i ++) {
        my_size = my_size + getTreeSize(root->subdirs[i]);
    }
    return my_size;
}

void constructTree(struct dirtreenode *root, char **tree_buf) {
    
    int len = strlen(root->name) + 1;
    int my_size = len * sizeof(char) + sizeof(return_node_type);
    return_node_type *node_header = (return_node_type *)*tree_buf;
    node_header->name_len = len;
    node_header->num_subdirs = root->num_subdirs;
    memcpy(node_header->data, root->name, len);
    
    int i = 0;
    for (i = 0; i < root->num_subdirs; i ++) {
        *tree_buf = *tree_buf + my_size;
        constructTree(root->subdirs[i], tree_buf);
    }
    return ;
}
