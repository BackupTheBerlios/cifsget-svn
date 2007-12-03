#ifndef BUFFER_H
#define BUFFER_H

#define	ZERO_STRUCT(x)	memset((char *)&(x), 0, sizeof(x))
#define	ZERO_STRUCTP(x)	do { if ((x) != NULL) memset((char*)(x), 0, sizeof(*(x))); } while(0)

#define NEW_STRUCT(x) x = calloc(1, sizeof(*(x)))
#define FREE_STRUCT(x) do { free(x); x = NULL; } while(0)
#define ALLOC_STRUCT(t) (t*)calloc(1, sizeof(t))

/*
 * |<----------size---------->|
 * |<----len--->|<----left--->|
 * +----------------------------------------+
 * |XXXXXXXXXXXX|YYYYYYYYYYYYY|ZZZZZZZZZZZZZ|
 * +----------------------------------------+
 * ^            ^             ^             ^
 * b - begin    p - point     e - end       x - limit
 *              cifs_read_*   cifs_append_*
 *              cifs_write_*
 */

typedef struct cifs_buf_s {
    void *b, *p, *e, *x;
    char buf[0];
} cifs_buf_t;
typedef cifs_buf_t *cifs_buf_p;

cifs_buf_p cifs_buf_new(int size);
void cifs_buf_free(cifs_buf_p buf);
void cifs_buf_setup(cifs_buf_p buf, char *begin, int size);

int cifs_buf_resize(cifs_buf_p buf, int size);
#define cifs_buf_size(buf) ((buf)->e - (buf)->b)

#define cifs_buf_range(buf, off, len) (((buf)->b + (off) < (buf)->b) || ((buf)->b + (off) + (len) > (buf)->e))
#define cifs_buf_rangep(buf, ptr, len) (((void*)(ptr) < (buf)->b) || (((void*)(ptr) + (len)) > (buf)->e))

// length
#define cifs_buf_len(buf) ((buf)->p - (buf)->b)
#define cifs_buf_left(buf) ((buf)->e - (buf)->p)

// pointer
#define cifs_buf_ptr(buf, off) ((buf)->b + (off))
#define cifs_buf_off(buf, ptr) ((void*)(ptr) - (buf)->b)
#define cifs_buf_cur(buf) ((buf)->p)
#define cifs_buf_set(buf, i) ((buf)->p = (buf)->b + (i))
#define cifs_buf_inc(buf, i) ((buf)->p += (i))

#define cifs_write_type(buf, type, value) do { *((type*)(buf)->p) = value; cifs_buf_inc(buf, sizeof(type)); } while (0)

#define cifs_write_byte(buf, value) cifs_write_type(buf, uint8_t, value)
#define cifs_write_word(buf, value) cifs_write_type(buf, uint16_t, value)
#define cifs_write_long(buf, value) cifs_write_type(buf, uint32_t, value)
#define cifs_write_quad(buf, value) cifs_write_type(buf, uint64_t, value)

#define cifs_write_str(buf, str) do { strcpy(buf->p, str) ; cifs_buf_inc(buf, strlen(str)); } while (0)

#define cifs_write_strz(buf, str) do { cifs_write_str(buf, str); cifs_write_byte(buf, 0); } while(0)

#define cifs_write_buf(buf, ptr, cnt) do { memcpy(cifs_buf_cur(buf), ptr, cnt); cifs_buf_inc(buf, cnt); } while (0)

int cifs_write_oem(cifs_buf_p dst, const char *src);
int cifs_write_ucs(cifs_buf_p dst, const char *src);
#define cifs_write_oemz(buf, str) do { cifs_write_oem(buf, str); cifs_write_byte(buf, 0); } while(0)
#define cifs_write_ucsz(buf, str) do { cifs_write_ucs(buf, str); cifs_write_word(buf, 0); } while(0)

int cifs_write_path_oem (cifs_buf_p buf, const char *path);
int cifs_write_path_ucs (cifs_buf_p buf, const char *path);
#define cifs_write_path_oemz(buf, path) do { cifs_write_path_oem(buf, path); cifs_write_byte(buf, 0); } while(0)
#define cifs_write_path_ucsz(buf, path) do { cifs_write_path_ucs(buf, path); cifs_write_word(buf, 0); } while(0)

#define cifs_read_typep(buf, type)  ((type*)(buf)->p, cifs_buf_inc(buf, sizeof(type)))
#define cifs_read_type(buf, type)  (*cifs_read_typep(buf, type))

#define cifs_read_byte(buf) cifs_read_type(buf, uint8_t)
#define cifs_read_word(buf) cifs_read_type(buf, uint16_t)
#define cifs_read_long(buf) cifs_read_type(buf, uint32_t)
#define cifs_read_quad(buf) cifs_read_type(buf, uint64_t)



#endif
