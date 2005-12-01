#ifndef ATOM_H
#define ATOM_H

typedef unsigned int uint_t;
#define	ZERO_STRUCT(x)	memset((char *)&(x), 0, sizeof(x))
#define	ZERO_STRUCTP(x)	do { if ((x) != NULL) memset((char*)(x), 0, sizeof(*(x))); } while(0)

#define NEW_STRUCT(x) x = calloc(1, sizeof(*(x)))
#define FREE_STRUCT(x) do { free(x); x = NULL; } while(0)

static inline char *push_string(char *p, const char *s) {
	do {
		*p++=*s;
	} while (*s++);
	return p;
}

#define PUSH_STRING(p, s) (p=push_string(p, s))
#define PUSH_FORMAT(p, s, ...) (p+=sprintf(p, s, __VA_ARGS__)+1)

#define PUSH_BYTE(p, v) (SCVAL(p, 0, v),p+=1)
#define PUSH_WORD(p, v) (SSVAL(p, 0, v),p+=2)
#define PUSH_LONG(p, v) (SIVAL(p, 0, v),p+=4)

#define GET_BYTE(base, pos)		CVAL(base, pos)
#define SET_BYTE(base, pos, val)	SCVAL(base, pos, val)

#define GET_SBYTE(base, pos)		CVALS(base, pos)
#define SET_SBYTE(base, pos, val)	SCVALS(base, pos, val)

#define GET_WORD(base, pos)		SVAL(base, pos)
#define SET_WORD(base, pos, val)	SSVAL(base, pos, val)

#define GET_SWORD(base, pos)		SVALS(base, pos)
#define SET_SWORD(base, pos, val)	SSVALS(base, pos, val)

#define GET_RWORD(base, pos)		RSVAL(base, pos)
#define SET_RWORD(base, pos, val)	RSSVAL(base, pos, val)

#define GET_LONG(base, pos)		IVAL(base, pos)
#define SET_LONG(base, pos, val)	SIVAL(base, pos, val)

#define GET_SLONG(base, pos)		IVALS(base, pos)
#define SET_SLONG(base, pos, val)	SIVALS(base, pos, val)

#define GET_RLONG(base, pos)		RIVAL(base, pos)
#define SET_RLONG(base, pos, val)	RSIVAL(base, pos, val)

#define GET_QUAD(base, pos)		BVAL(base, pos)
#define SET_QUAD(base, pos, val)	SBVAL(base, pos, val)

#define GET_SQUAD(base, pos)		BVALS(base, pos)
#define SET_SQUAD(base, pos, val)	SBVALS(base, pos, val)

#define GET_NTTIME(base, pos)		BVALS(base, pos)
#define SET_NTTIME(base, pos, val)	SBVALS(base, pos, val)

#endif /* ATOM_H */
