#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "libcifs/cifs.h"
#include "macros.h"
#include "uri.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef struct cifs_cookie_s {
    cifs_uri_p uri;
    cifs_connect_p conn;
    int fid;
    off_t off, size;
} cifs_cookie_t;

static ssize_t reader (void *cookie, char *buffer, size_t size) {
    cifs_cookie_t *c = cookie;
    size_t res;
    res = cifs_read(c->conn, c->fid, buffer, size, c->off);
    if (res > 0) {
        c->off += res;
    }
    return res;
}

static ssize_t writer (void *cookie, const char *buffer, size_t size) {
    cifs_cookie_t *c = cookie;
    size_t res;
    res = cifs_write(c->conn, c->fid, buffer, size, c->off);
    if (res > 0) {
        c->off += res;
    }
    return res;
}

static int seeker (void *cookie, off64_t *position, int whence) {
    cifs_cookie_t *c = cookie;
    if (whence == SEEK_SET) {
        c->off = *position;
    } else if (whence == SEEK_CUR) {
        c->off += *position;
    } else if (whence == SEEK_END) {
        c->off = c->size + *position;
    }
    *position = c->off;
    return 0;
}

static int closer (void *cookie) {
    cifs_cookie_t *c = cookie;
    cifs_connect_close(c->conn);
    cifs_uri_free(c->uri);
    free(c);
    return 0;
}

cookie_io_functions_t cifs_io = {
    .read = reader,
    .write = writer,
    .seek = seeker,
    .close = closer,
};

FILE *fopen_cifs(const char *uri, const char *mode) {
    cifs_cookie_t *c;
    NEW_STRUCT(c);
    int omode = 0, oflags = 0;
    c->uri = cifs_uri_parse(uri);
    if (c->uri == NULL) goto err;
    c->conn = cifs_connect(c->uri->addr, c->uri->port, c->uri->host, c->uri->tree);
    if (c->conn == NULL) goto err;
    const char *p = mode;
    while (1) {
        switch (*p++) {
            case '\0':
                break;
            case 'r':
                omode = O_RDONLY;
                continue;
            case 'w':
                omode = O_WRONLY;
                oflags = O_CREAT | O_TRUNC;
                continue;
            case 'a':
                omode = O_WRONLY;
                oflags = O_CREAT | O_APPEND;
                continue;
            case '+':
                omode = O_RDWR;
                continue;
            case 'x':
                oflags |= O_EXCL;
                continue;
        }
        break;
    }
    cifs_stat_t st;
    c->fid = cifs_open(c->conn, c->uri->path, omode | oflags, &st);
    if (c->fid < 0) goto err;
    c->size = st.file_size;
    if (oflags & O_APPEND) {
        c->off = st.file_size;
    }
    return fopencookie(c, mode, cifs_io);
err:
    cifs_uri_free(c->uri);
    cifs_connect_close(c->conn);
    free(c);
    return NULL;
}

int main (int argc, char **argv) {
    FILE *f;
    char buf[1024*4];
    int res;
    for (int i = 1 ; i < argc ; i++) {
        f = fopen_cifs(argv[i], "r");
        if (f == NULL) {
            perror(argv[i]);
            continue;
        }
        do {
            res = fread(buf, 1, sizeof(buf), f);
            fwrite(buf, 1, res, stdout);
        } while (res);
    }
}
