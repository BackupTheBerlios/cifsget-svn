#ifndef ATOM_H
#define ATOM_H

typedef unsigned int uint_t;
#define	ZERO_STRUCT(x)	memset((char *)&(x), 0, sizeof(x))
#define	ZERO_STRUCTP(x)	do { if ((x) != NULL) memset((char*)(x), 0, sizeof(*(x))); } while(0)

#define NEW_STRUCT(x) x = calloc(1, sizeof(*(x)))
#define FREE_STRUCT(x) do { free(x); x = NULL; } while(0)
#define ALLOC_STRUCT(t) (t*)calloc(1, sizeof(t))

static inline void cifs_write_buf(char **p, const char *s) {
	while (*s) {
		*(*p)++ = *s++;
	}
}

static inline void cifs_write_string(char **p, const char *s) {
	do {
		*(*p)++ = *s;
	} while (*s++);
}

#define WRITE_BUF(p, s) cifs_write_buf(&p, s)
#define WRITE_STRING(p, s) cifs_write_string(&p, s)
#define WRITE_FORMAT(p, s, ...) (p+=sprintf(p, s, __VA_ARGS__)+1)


static inline char *cifs_read_string(char **p) {
	int len = strlen(*p);
	char *t = malloc(len+1);
	strcpy(t, *p);
	*p += len + 1;
	return t;
}

#define READ_STRING(p)	(cifs_read_string(&p))

#define READ_BYTE(p)	(CVAL(p, 0),p+=1)
#define READ_WORD(p)	(SVAL(p, 0),p+=2)
#define READ_LONG(p)	(IVAL(p, 0),p+=4)
#define READ_QUAD(p)	(BVAL(p, 0),p+=8)
#define READ_BE_WORD(p)	(RSVAL(p, 0),p+=2)
#define READ_BE_LONG(p)	(RIVAL(p, 0),p+=4)
#define READ_SIGNED_WORD(p)	(SVALS(p, 0),p+=2)
#define READ_SIGNED_LONG(p)	(IVALS(p, 0),p+=4)
#define READ_SIGNED_QUAD(p)	(BVALS(p, 0),p+=8)
#define READ_BE_SIGNED_WORD(p)	(RSVALS(p, 0),p+=2)
#define READ_BE_SIGNED_LONG(p)	(RIVALS(p, 0),p+=4)


#define WRITE_BYTE(p, v) (SCVAL(p, 0, v),p+=1)
#define WRITE_WORD(p, v) (SSVAL(p, 0, v),p+=2)
#define WRITE_LONG(p, v) (SIVAL(p, 0, v),p+=4)
#define WRITE_QUAD(p, v) (SBVAL(p, 0, v),p+=8)
#define WRITE_BE_WORD(p, v) (RSSVAL(p, 0, v),p+=2)
#define WRITE_BE_LONG(p, v) (RSIVAL(p, 0, v),p+=4)
#define WRITE_SIGNED_WORD(p, v) (SSVALS(p, 0, v),p+=2)
#define WRITE_SIGNED_LONG(p, v) (SIVALS(p, 0, v),p+=4)
#define WRITE_SIGNED_QUAD(p, v) (SBVALS(p, 0, v),p+=8)
#define WRITE_BE_SIGNED_WORD(p, v) (RSSVALS(p, 0, v),p+=2)
#define WRITE_BE_SIGNED_LONG(p, v) (RSIVALS(p, 0, v),p+=4)

#define WRITE_ALIGN(p, b, a)	while(((p)-(b)) % (a)) { WRITE_BYTE(p, 0); }

#define GET_BYTE(base, pos)		CVAL(base, pos)
#define SET_BYTE(base, pos, val)	SCVAL(base, pos, val)

#define GET_SIGNED_BYTE(base, pos)	CVALS(base, pos)
#define SET_SIGNED_BYTE(base, pos, val)	SCVALS(base, pos, val)

#define GET_WORD(base, pos)		SVAL(base, pos)
#define SET_WORD(base, pos, val)	SSVAL(base, pos, val)

#define GET_SIGNED_WORD(base, pos)	SVALS(base, pos)
#define SET_SIGNED_WORD(base, pos, val)	SSVALS(base, pos, val)

#define GET_BE_WORD(base, pos)		RSVAL(base, pos)
#define SET_BE_WORD(base, pos, val)	RSSVAL(base, pos, val)

#define GET_LONG(base, pos)		IVAL(base, pos)
#define SET_LONG(base, pos, val)	SIVAL(base, pos, val)

#define GET_SIGNED_LONG(base, pos)	IVALS(base, pos)
#define SET_SIGNED_LONG(base, pos, val)	SIVALS(base, pos, val)

#define GET_BE_LONG(base, pos)		RIVAL(base, pos)
#define SET_BE_LONG(base, pos, val)	RSIVAL(base, pos, val)

#define GET_QUAD(base, pos)		BVAL(base, pos)
#define SET_QUAD(base, pos, val)	SBVAL(base, pos, val)

#define GET_SIGNED_QUAD(base, pos)	BVALS(base, pos)
#define SET_SIGNED_QUAD(base, pos, val)	SBVALS(base, pos, val)

#define GET_NT_TIME(base, pos)		BVALS(base, pos)
#define SET_NT_TIME(base, pos, val)	SBVALS(base, pos, val)

#endif /* ATOM_H */
