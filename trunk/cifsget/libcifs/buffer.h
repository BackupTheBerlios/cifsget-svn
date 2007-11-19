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

#define cifs_read_byte(b)   (CVAL(b->p, 0),b->p+=1)
#define cifs_read_word(b)   (SVAL(b->p, 0),b->p+=2)
#define cifs_read_long(b)   (IVAL(b->p, 0),b->p+=4)
#define cifs_read_quad(b)   (BVAL(b->p, 0),b->p+=8)
#define cifs_read_signed_word(b)   (SVALS(b->p, 0),b->p+=2)
#define cifs_read_signed_long(b)   (IVALS(b->p, 0),b->p+=4)
#define cifs_read_signed_quad(b)   (BVALS(b->p, 0),b->p+=8)
#define cifs_read_be_word(b)   (RSVAL(b->p, 0),b->p+=2)
#define cifs_read_be_long(b)   (RIVAL(b->p, 0),b->p+=4)
#define cifs_read_be_signed_word(b)   (RSVALS(b->p, 0),b->p+=2)
#define cifs_read_be_signed_long(b)   (RIVALS(b->p, 0),b->p+=4)

#define cifs_write_byte(b, v)   (SCVAL((b)->p, 0, (v)),(b)->p+=1)
#define cifs_write_word(b, v)   (SSVAL(b->p, 0, v),b->p+=2)
#define cifs_write_long(b, v)   (SIVAL(b->p, 0, v),b->p+=4)
#define cifs_write_quad(b, v)   (SBVAL(b->p, 0, v),b->p+=8)
#define cifs_signed_write_word(b, v)   (SSVALS(b->p, 0, v),b->p+=2)
#define cifs_signed_write_long(b, v)   (SIVALS(b->p, 0, v),b->p+=4)
#define cifs_signed_write_quad(b, v)   (SBVALS(b->p, 0, v),b->p+=8)
#define cifs_write_be_word(b, v)   (RSSVAL(b->p, 0, v),b->p+=2)
#define cifs_write_be_long(b, v)   (RSIVAL(b->p, 0, v),b->p+=4)
#define cifs_write_be_signed_word(b, v)   (RSSVALS(b->p, 0, v),b->p+=2)
#define cifs_write_be_signed_long(b, v)   (RSIVALS(b->p, 0, v),b->p+=4)

#define cifs_write_align(buf, a)    while (((buf)->p - (buf)->b) % (a)) { cifs_write_byte((buf), 0); }


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

#define CIFS_BUF_STRUCT_PTR(buf, type, name) struct type *name = (struct type *) (buf)->p;

#define CIFS_BUF_STRUCT(buf, type, name)  \
    struct type *name = (struct type *) (buf)->p; \
    (buf)->p += sizeof(struct type);

#endif
