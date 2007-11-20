#ifndef BUFFER_H
#define BUFFER_H

#define	ZERO_STRUCT(x)	memset((char *)&(x), 0, sizeof(x))
#define	ZERO_STRUCTP(x)	do { if ((x) != NULL) memset((char*)(x), 0, sizeof(*(x))); } while(0)

#define NEW_STRUCT(x) x = calloc(1, sizeof(*(x)))
#define FREE_STRUCT(x) do { free(x); x = NULL; } while(0)
#define ALLOC_STRUCT(t) (t*)calloc(1, sizeof(t))

typedef struct cifs_buf_s {
    char *b, *p, *l;
    int s;
    char buf[0];
} cifs_buf_t;
typedef cifs_buf_t *cifs_buf_p;

cifs_buf_p cifs_buf_new(int size);
void cifs_buf_free(cifs_buf_p buf);
void cifs_buf_setup(cifs_buf_p buf, char *begin, int size);

// limit
int cifs_buf_limit(cifs_buf_p buf, int size);
#define cifs_buf_size(buf) ((buf)->l - (buf)->b)

// test
#define cifs_buf_end(buf) ((buf)->l == (buf)->p)
#define cifs_buf_range(buf, off, len) (((buf)->b + (off) < (buf)->b) || ((buf)->b + (off) + (len) > (buf)->l))
#define cifs_buf_rangep(buf, ptr, len) (((ptr) < (buf)->b) || (((ptr) + (len)) > (buf)->l))

// length
#define cifs_buf_len(buf) ((buf)->p - (buf)->b)
#define cifs_buf_left(buf) ((buf)->l - (buf)->p)

#define cifs_buf_ptr(buf, off) ((buf)->b + (off))
#define cifs_buf_off(buf, ptr) ((ptr) - (buf)->b)


// pointer
#define cifs_buf_cur(buf) ((buf)->p)
#define cifs_buf_reset(buf) ((buf)->p = (buf)->b)
#define cifs_buf_inc(buf, i) ((buf)->p+=(i))
#define cifs_buf_set(buf, i) ((buf)->p = (buf)->b + (i))


#define cifs_write_byte(b, v)   (*((b)->p)++ = v)
#define cifs_write_word(b, v)   (*((uint16_t*)((b)->p)) = v, (b)->p+=2)
#define cifs_write_long(b, v)   (*((uint32_t*)((b)->p)) = v, (b)->p+=4)

static inline void cifs_write_str(cifs_buf_p buf, const char *s) {
	while (*s) {
		*(buf->p)++ = *s++;
	}
}
#define cifs_write_strz(buf, str) do { cifs_write_str(buf, str); cifs_write_byte(buf, 0); } while(0)

#define cifs_write_buf(buf, ptr, cnt) do { \
    memcpy(buf->p, ptr, cnt); \
    buf->p += cnt; \
} while (0); \

int cifs_write_oem(cifs_buf_p dst, const char *src);
int cifs_write_ucs(cifs_buf_p dst, const char *src);
#define cifs_write_oemz(buf, str) do { cifs_write_oem(buf, str); cifs_write_byte(buf, 0); } while(0)
#define cifs_write_ucsz(buf, str) do { cifs_write_ucs(buf, str); cifs_write_word(buf, 0); } while(0)

int cifs_write_path_oem (cifs_buf_p buf, const char *path);
int cifs_write_path_ucs (cifs_buf_p buf, const char *path);
#define cifs_write_path_oemz(buf, path) do { cifs_write_path_oem(buf, path); cifs_write_byte(buf, 0); } while(0)
#define cifs_write_path_ucsz(buf, path) do { cifs_write_path_ucs(buf, path); cifs_write_word(buf, 0); } while(0)

#define CIFS_BUF_STRUCT_PTR(buf, type, name) struct type *name = (struct type *) (buf)->p;

#define CIFS_BUF_STRUCT(buf, type, name)  \
    struct type *name = (struct type *) (buf)->p; \
    (buf)->p += sizeof(struct type);

#endif
