#define _GNU_SOURCE
// #define _POSIX_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
// #define _FCNTL_H
// #define _SYS_TYPES_H
// #define _SYS_STAT_H

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <ctype.h>

using namespace std;

// chmod chown close creat* fclose fopen* fread fwrite open* read remove rename
// tmpfile* write

static char buffer[1005];
static char write_buffer[2000];

// === prepare ===

static int (*old_chown)(const char*, uid_t, gid_t) = NULL;
static int (*old_chmod)(const char*, mode_t) = NULL;
static int (*old_close)(int) = NULL;
static int (*old_creat)(const char*, mode_t) = NULL;
static int (*old_creat64)(const char*, mode_t) = NULL;
static int (*old_fclose)(FILE*) = NULL;
static FILE* (*old_fopen)(const char*, const char*) = NULL;
static FILE* (*old_fopen64)(const char*, const char*) = NULL;
static size_t (*old_fread)(void*, size_t, size_t, FILE*) = NULL;
static size_t (*old_fwrite)(const void*, size_t, size_t, FILE*) = NULL;
static int (*old_open)(const char*, int, ...) = NULL;
static int (*old_open64)(const char*, int, ...) = NULL;
static ssize_t (*old_read)(int, void*, size_t) = NULL;
static int (*old_remove)(const char*) = NULL;
static int (*old_rename)(const char*, const char*) = NULL;
static FILE* (*old_tmpfile)(void) = NULL;
static FILE* (*old_tmpfile64)(void) = NULL;
static ssize_t (*old_write)(int, const void*, size_t) = NULL;

static bool prepare_done = false;
static int stderr_fd = 2;
void prepare() {
    if (prepare_done) return;
    old_chown = (int (*)(const char*, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");
    old_chmod = (int (*)(const char*, mode_t))dlsym(RTLD_NEXT, "chmod");
    old_close = (int (*)(int))dlsym(RTLD_NEXT, "close");
    old_creat = (int (*)(const char*, mode_t))dlsym(RTLD_NEXT, "creat");
    old_creat64 = (int (*)(const char*, mode_t))dlsym(RTLD_NEXT, "creat");
    old_fclose = (int (*)(FILE*))dlsym(RTLD_NEXT, "fclose");
    old_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen");
    old_fopen64 = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen64");
    old_fread = (size_t (*)(void*, size_t, size_t, FILE*))dlsym(RTLD_NEXT, "fread");
    old_fwrite = (size_t (*)(const void*, size_t, size_t, FILE*))dlsym(RTLD_NEXT, "fwrite");
    old_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
    old_open64 = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open64");
    old_read = (ssize_t (*)(int fd, void *buf, size_t count))dlsym(RTLD_NEXT, "read");
    old_remove = (int (*)(const char*))dlsym(RTLD_NEXT, "remove");
    old_rename = (int (*)(const char*, const char*))dlsym(RTLD_NEXT, "rename");
    old_tmpfile = (FILE* (*)(void))dlsym(RTLD_NEXT, "tmpfile");
    old_tmpfile64 = (FILE* (*)(void))dlsym(RTLD_NEXT, "tmpfile64");
    old_write = (ssize_t (*)(int, const void*, size_t))dlsym(RTLD_NEXT, "write");
    if (strncmp(getenv("OUTPUT_PATH"), "STDERR", 6) != 0) {
        stderr_fd = old_open(getenv("OUTPUT_PATH"), O_RDWR | O_CREAT | O_APPEND, 420);
    }
    prepare_done = true;
}

// === print ===

void printstr(const char *str) {
    // old_write(stderr_fd, str, strlen(str));
    strcat(write_buffer, str);
}

char int_buf[100];
char ptr_buf[100];
char char_buf[100];

void printint(int x) {
    int int_buf_ptr = sprintf(int_buf, "%d", x);
    // old_write(stderr_fd, int_buf, int_buf_ptr);
    strcat(write_buffer, int_buf);
}

void printint_oct(int x) {
    int int_buf_ptr = sprintf(int_buf, "%o", x);
    // old_write(stderr_fd, int_buf, int_buf_ptr);
    strcat(write_buffer, int_buf);
}

void printptr(void *x) {
    int ptr_buf_ptr = sprintf(ptr_buf, "%p", x);
    // old_write(stderr_fd, ptr_buf, ptr_buf_ptr);
    strcat(write_buffer, ptr_buf);
}

void printcharbuf(const void *x, size_t n) {
    int size = 32;
    if (n < size)
        size = n;
    memcpy(char_buf, x, size);
    for (int i = 0; i < size; i++) {
        if (!isprint(char_buf[i]))
            char_buf[i] = '.';
    }
    char_buf[size] = '\0';
    printstr(char_buf);
}

void flushprint() {
    old_write(stderr_fd, write_buffer, strlen(write_buffer));
    write_buffer[0] = '\0';
}

// === get filename ===

char path[1024];

void get_fd(int fd, char *buf) {
    char proclnk[200];
    sprintf(proclnk, "/proc/self/fd/%d", fd);
    int r = readlink(proclnk, path, 1000);
    if (r < 0) {
        buf[0] = '\0';
        return;
    }
    path[r] = '\0';
    realpath(path, buf);
}

void get_FILE(FILE *fp, char *buf) {
    int fno = fileno(fp);
    if (fno < 0) {
        buf[0] = '\0';
        return;
    }
    char proclnk[200];
    sprintf(proclnk, "/proc/self/fd/%d", fno);
    int r = readlink(proclnk, path, 1000);
    if (r < 0) {
        buf[0] = '\0';
        return;
    }
    path[r] = '\0';
    realpath(path, buf);
}

// === injected functions start ===

int chown(const char *pathname, uid_t owner, gid_t group) {
    prepare();
    int ret = old_chown(pathname, owner, group);
    printstr("[logger] chown(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\", ");
    printint(owner);
    printstr(", ");
    printint(group);
    printstr(") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int chmod(const char *pathname, mode_t mode) {
    prepare();
    int ret = old_chmod(pathname, mode);
    printstr("[logger] chmod(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\", ");
    printint_oct(mode);
    printstr(") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int close(int fd) {
    prepare();
    if (fd == stderr_fd) {
        stderr_fd = dup(stderr_fd);
    }
    get_fd(fd, buffer);
    int ret = old_close(fd);
    printstr("[logger] close(\"");
    printstr(buffer);
    printstr("\") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int creat(const char *pathname, mode_t mode) {
    prepare();
    int ret = old_creat(pathname, mode);
    printstr("[logger] creat(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\", ");
    printint_oct(mode);
    printstr(") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int creat64(const char *pathname, mode_t mode) {
    prepare();
    int ret = old_creat64(pathname, mode);
    printstr("[logger] creat64(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\", ");
    printint_oct(mode);
    printstr(") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int fclose(FILE *stream) {
    if (fileno(stream) == stderr_fd) {
        stderr_fd = dup(stderr_fd);
    }
    prepare();
    get_FILE(stream, buffer);
    int ret = old_fclose(stream);
    printstr("[logger] fclose(\"");
    printstr(buffer);
    printstr("\") = ");
    printint(ret);
    printstr("\n");
    flushprint();

    return ret;
}

FILE *fopen(const char *pathname, const char *mode) {
    prepare();
    FILE *ret = old_fopen(pathname, mode);
    printstr("[logger] fopen(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\", \"");
    printstr(mode);
    printstr("\") = ");
    printptr(ret);
    printstr("\n");
    flushprint();
    return ret;
}

// fopen64
FILE *fopen64(const char *pathname, const char *mode) {
    prepare();
    FILE *ret = old_fopen64(pathname, mode);
    printstr("[logger] fopen64(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\", \"");
    printstr(mode);
    printstr("\") = ");
    printptr(ret);
    printstr("\n");
    flushprint();
    return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    prepare();
    size_t ret = old_fread(ptr, size, nmemb, stream);
    printstr("[logger] fread(\"");
    printcharbuf(ptr, ret * size);
    printstr("\", ");
    printint(size);
    printstr(", ");
    printint(nmemb);
    printstr(", \"");
    get_FILE(stream, buffer);
    printstr(buffer);
    printstr("\") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    prepare();
    size_t ret = old_fwrite(ptr, size, nmemb, stream);
    printstr("[logger] fwrite(\"");
    printcharbuf(ptr, ret * size);
    printstr("\", ");
    printint(size);
    printstr(", ");
    printint(nmemb);
    printstr(", \"");
    get_FILE(stream, buffer);
    printstr(buffer);
    printstr("\") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int open(const char *pathname, int flags, ...) {
    prepare();
    mode_t mode = 0;
    int ret;
    if (__OPEN_NEEDS_MODE(flags)) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        ret = old_open(pathname, flags, mode);
    } else {
        ret = old_open(pathname, flags, 0);
    }
    printstr("[logger] open(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\", ");
    printint_oct(flags);
    printstr(", ");
    printint_oct(mode);
    printstr(") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int open64(const char *pathname, int flags, ...) {
    prepare();
    mode_t mode = 0;
    int ret;
    if (__OPEN_NEEDS_MODE(flags)) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        ret = old_open64(pathname, flags, mode);
    } else {
        ret = old_open64(pathname, flags, 0);
    }
    printstr("[logger] open64(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\", ");
    printint_oct(flags);
    printstr(", ");
    printint_oct(mode);
    printstr(") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}


ssize_t read(int fd, void *buf, size_t count) {
    prepare();
    ssize_t ret = old_read(fd, buf, count);
    printstr("[logger] read(\"");
    get_fd(fd, buffer);
    printstr(buffer);
    printstr("\", \"");
    printcharbuf(buf, ret);
    printstr("\", ");
    printint(count);
    printstr(") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int remove(const char *pathname) {
    prepare();
    int ret = old_remove(pathname);
    printstr("[logger] remove(\"");
    realpath(pathname, buffer);
    printstr(buffer);
    printstr("\") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

int rename(const char *oldpath, const char *newpath) {
    prepare();
    int ret = old_rename(oldpath, newpath);
    printstr("[logger] rename(\"");
    realpath(oldpath, buffer);
    printstr(buffer);
    printstr("\", \"");
    realpath(newpath, buffer);
    printstr(buffer);
    printstr("\") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}

FILE* tmpfile(void) {
    FILE *ret = old_tmpfile();
    printstr("[logger] tmpfile() = ");
    printptr(ret);
    printstr("\n");
    flushprint();
    return ret;
}

FILE* tmpfile64(void) {
    FILE *ret = old_tmpfile64();
    printstr("[logger] tmpfile64() = ");
    printptr(ret);
    printstr("\n");
    flushprint();
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
    prepare();
    ssize_t ret = old_write(fd, buf, count);
    printstr("[logger] write(\"");
    get_fd(fd, buffer);
    printstr(buffer);
    printstr("\", \"");
    printcharbuf(buf, ret);
    printstr("\", ");
    printint(count);
    printstr(") = ");
    printint(ret);
    printstr("\n");
    flushprint();
    return ret;
}
