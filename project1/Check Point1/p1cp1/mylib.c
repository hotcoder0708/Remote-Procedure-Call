/*
 * Author: jiaxingh
 * Project1
 * check point1
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

#define MAXMSGLEN 100

// The following line declares a function pointer with the same prototype as the open function.  
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_close)(int pfd);
ssize_t (*orig_read)(int fildes, void *buf, size_t nbyte);
ssize_t (*orig_write)(int handle, const void *buf, size_t nbyte);
__off_t (*orig_lseek)(int fildes, __off_t offset, int whence);
int (*orig___xstat)(int ver, const char *filename, struct stat *stat_buf);
int (*orig_unlink)(const char *path);
ssize_t (*orig_getdirentries)(int fd, char *buf, ssize_t nbyte, long *basep);
struct dirtreenode* (*orig_getdirtree)(const char *pathname);
void (*orig_freedirtree)(struct dirtreenode* dt);

int callServer(char *functionName){
    char *serverip;
    char *serverport;
    unsigned short port;
    char *msg = functionName;
    char buf[MAXMSGLEN+1];
    int sockfd, rv;
    struct sockaddr_in srv;
    
    // Get environment variable indicating the ip address of the server
    serverip = getenv("server15440");
    if (serverip) printf("Got environment variable server15440: %s\n", serverip);
    else {
        printf("Environment variable server15440 not found.  Using 127.0.0.1\n");
        serverip = "127.0.0.1";
    }
    
    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (serverport) fprintf(stderr, "Got environment variable serverport15440: %s\n", serverport);
    else {
        fprintf(stderr, "Environment variable serverport15440 not found.  Using 15440\n");
        serverport = "15440";
    }
    port = (unsigned short)atoi(serverport);
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
    if (sockfd<0) err(1, 0);			// in case of error
    
    // setup address structure to point to server
    memset(&srv, 0, sizeof(srv));			// clear it first
    srv.sin_family = AF_INET;			// IP family
    srv.sin_addr.s_addr = inet_addr(serverip);	// IP address of server
    srv.sin_port = htons(port);			// server port
    
    // actually connect to the server
    rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) err(1,0);
    
    // send message to server
    printf("%s", msg);
    send(sockfd, msg, strlen(msg), 0);	// send message; should check return value
    
    // get message back
    rv = recv(sockfd, buf, MAXMSGLEN, 0);	// get message
    if (rv<0) err(1,0);			// in case something went wrong
    buf[rv]=0;				// null terminate string to print
    printf("client got messge: %s\n", buf);
    
    // close socket
    orig_close(sockfd);
    return 0;
}
// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
    callServer("open");
    
    mode_t m=0;
    if (flags & O_CREAT) {
        va_list a;
        va_start(a, flags);
        m = va_arg(a, mode_t);
        va_end(a);
    }
    // we just print a message, then call through to the original open function (from libc)
    
    return orig_open(pathname, flags, m);
}

// This is our replacement for the close function from libc
int close(int pfd) {
    callServer("close");
    
    return orig_close(pfd);
}

// This is our replacement for the read function from libc
ssize_t read(int fildes, void *buf, size_t nbyte) {
    callServer("read");
    
    return orig_read(fildes, buf, nbyte);
}

// This is our replacement for the write function from libc
ssize_t write(int handle, const void *buf, size_t nbyte) {
    callServer("write");
    
    return orig_write(handle, buf, nbyte);
}

// This is our replacement for the lseek function from libc
__off_t lseek(int fildes, __off_t offset, int whence) {
    callServer("lseek");
    
    return orig_lseek(fildes, offset, whence);
}

// This is our replacement for the stat function from libc
int __xstat(int ver, const char *filename, struct stat *stat_buf) {
    callServer("__xstat");
    
    return orig___xstat(ver, filename, stat_buf);
}

// This is our replacement for the unlink function from libc
int unlink(const char *path) {
    callServer("unlink");
    
    return orig_unlink(path);
}

// This is our replacement for the getdirentries function from libc
ssize_t getdirentries(int fd, char *buf, size_t nbyte, long *basep) {
    callServer("getdirentries");
    
    return orig_getdirentries(fd, buf, nbyte, basep);
}

struct dirtreenode* getdirtree(const char *pathname) {
    // Send message from client to server
    callServer("getdirtree\n");
    
    // Return the original function
    return orig_getdirtree(pathname);
}

void freedirtree(struct dirtreenode* dt) {
    // Send message from client to server
    callServer("freedirtree\n");
    
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


