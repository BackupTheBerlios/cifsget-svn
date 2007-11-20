#include "includes.h"

cifs_buf_p cifs_buf_new(int size) {
    cifs_buf_p buf = (cifs_buf_p)malloc(sizeof(cifs_buf_t) + size);
    if (size) {
        buf->b = buf->buf;
        buf->l = buf->b + size;
        buf->p = buf->b;
        buf->s = size;
    } else {
        ZERO_STRUCTP(buf);
    }
    return buf;
}

void cifs_buf_free(cifs_buf_p buf) {
    free(buf);
}

void cifs_buf_setup(cifs_buf_p buf, char *begin, int size) {
    buf->b = begin;
    buf->l = buf->b + size;
    buf->p = buf->b;
    buf->s = size;
}

int cifs_buf_limit(cifs_buf_p buf, int size) {
    if (size < 0) size = buf->s;
    if (size > buf->s) return -1;
    buf->l = buf->b + size;
    return 0;
}

int cifs_write_oem(cifs_buf_p dst, const char *src) {
    int res;
    res = cifs_cp_block(cifs_cp_sys_to_oem, cifs_buf_cur(dst), cifs_buf_left(dst), src, strlen(src));
    if (res < 0) {
        cifs_log_error("iconv error\n");
        return 0;
    }
    dst-> p += res;
    return res;
}

int cifs_write_ucs(cifs_buf_p dst, const char *src) {
    int res;
    res = cifs_cp_block(cifs_cp_sys_to_ucs, cifs_buf_cur(dst), cifs_buf_left(dst), src, strlen(src));
    if (res < 0) {
        cifs_log_error("iconv error\n");
        return 0;
    }
    dst-> p += res;
    return res/2;
}


int cifs_write_path_oem (cifs_buf_p buf, const char *path) {
    int len;
    char *p = cifs_buf_cur(buf);
    len = cifs_write_oem(buf, path);
    for (int i = 0 ; i <= len ; i++) {
        if (p[i] == '/') {
            p[i] = '\\';
        }
    }
    return len;
}

int cifs_write_path_ucs (cifs_buf_p buf, const char *path) {
    int len;
    uint16_t *p = (uint16_t *)cifs_buf_cur(buf);
    len = cifs_write_ucs(buf, path);
    for (int i = 0 ; i <= len ; i++) {
        if (p[i] == '/') {
            p[i] = '\\';
        }
    }
    return len;
}

