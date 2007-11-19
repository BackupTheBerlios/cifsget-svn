#include "includes.h"

#include <iconv.h>

//const char *cifs_cp_sys = "ASCII";
const char *cifs_cp_sys = "UTF-8";
const char *cifs_cp_oem = "866";
const char *cifs_cp_ucs = "UCS-2LE";

#define CIFS_CP_NULL ((cifs_cp_t)-1)

cifs_cp_t cifs_cp_sys_to_oem = CIFS_CP_NULL,
			cifs_cp_oem_to_sys = CIFS_CP_NULL,
			cifs_cp_sys_to_ucs = CIFS_CP_NULL,
			cifs_cp_ucs_to_sys = CIFS_CP_NULL;

size_t cifs_cp_block (cifs_cp_t cp, char *out_buf, size_t out_size, const char *in_buf, size_t in_size) {
	size_t in_left = in_size;
	size_t out_left = out_size;
	char *in_ptr = (char*)in_buf;
	char *out_ptr = out_buf;
	if (in_ptr == NULL || out_ptr == NULL) {
		errno = EINVAL;
		return -1;
	}
	iconv(cp, NULL, NULL, NULL, NULL);
	while (iconv(cp, &in_ptr, &in_left, &out_ptr, &out_left) == (size_t)(-1)) {
		switch (errno) {
			case EILSEQ:
			case EINVAL:
				//skip one byte
				
				/* if (out_left < 1 ) {
				    errno = E2BIG;
					return -1;
				}
				*out_ptr++ = '_';
				out_left--;*/

				//HEX it
				if (out_left < 3 ) {
					errno = E2BIG;
					return -1;
				}				
				*out_ptr++ = '%';
				*out_ptr++ = 'A' + (unsigned char)*in_ptr / 16;
				*out_ptr++ = 'A' + (unsigned char)*in_ptr % 16;
				out_left -= 3;

				in_ptr++;
				in_left--;
				break;
			case E2BIG:
			default:
				return -1;
		}
	}
	if (out_left) {
		*out_ptr = '\0';
	}
	return out_size - out_left;
}

char *cifs_cp (cifs_cp_t cp, const char *src) {
	return cifs_cp_buf(cp, src, strlen(src));
}

char *cifs_cp_buf (cifs_cp_t cp, const char *in_buf, size_t in_size) {
	size_t in_left = in_size;
	size_t out_size = in_size+1;
	size_t out_left = out_size;
	size_t out_off;
	char *in_ptr = (char*)in_buf;
	char *out_buf, *out_ptr, *tmp;

	if (in_ptr == NULL) {
		errno = EINVAL;
		return NULL;
	}

	out_buf = malloc(out_size);
	if (out_buf == NULL) {
		errno = ENOMEM;
		return NULL;
	}	
	out_ptr = out_buf;

	iconv(cp, NULL, NULL, NULL, NULL);
	while (iconv(cp, &in_ptr, &in_left, &out_ptr, &out_left) == (size_t)(-1)) {
		switch (errno) {
			case EILSEQ:
			case EINVAL:
				if (out_left >= 3) {
					//skip one byte
					//*out_ptr++ = '_';
					//out_left--;
					*out_ptr++ = '%';
					*out_ptr++ = 'A' + (unsigned char)*in_ptr / 16;
					*out_ptr++ = 'A' + (unsigned char)*in_ptr % 16;
					out_left -= 3;					
					in_ptr++;
					in_left--;
					break;
				}
			case E2BIG:
				//realloc
				out_off = out_ptr - out_buf;
				out_left += out_size;
				out_size *= 2;
				out_buf = realloc(tmp = out_buf, out_size);
				if (out_buf == NULL) {
					free(tmp);
					return NULL;
				}
				out_ptr = out_buf + out_off;
				break;
			default:
				free(out_buf);
				return NULL;
		}
	}
	out_size -= out_left - 1;
	out_buf = realloc(tmp = out_buf, out_size);
	if (out_buf == NULL) {
 		free(tmp);
		return NULL;
	}
	out_buf[out_size-1] = '\0';
	return out_buf;
}

size_t cifs_cp_tobuf (cifs_cp_t cp, char *out_buf, size_t out_size, const char *src) {
	return cifs_cp_block(cp, out_buf, out_size, src, strlen(src));
}

size_t cifs_cp_write (cifs_cp_t cp, char **ptr, char *lim, const char *src) {
	size_t res, in_size, out_size;
	in_size = strlen(src);
	out_size = lim - *ptr;
	res = cifs_cp_block(cp, *ptr, out_size, src, in_size);
	if (res > 0) *ptr += res;
	return res;
}

#define CIFS_CP_REINIT(cp, from, to) do {\
	if (cp != CIFS_CP_NULL) iconv_close(cp);\
	cp = iconv_open(to, from);\
} while(0)

void cifs_cp_init(void) __attribute__((constructor));
void cifs_cp_init(void) {
	CIFS_CP_REINIT(cifs_cp_sys_to_oem, cifs_cp_sys, cifs_cp_oem);
	CIFS_CP_REINIT(cifs_cp_oem_to_sys, cifs_cp_oem, cifs_cp_sys);
	CIFS_CP_REINIT(cifs_cp_sys_to_ucs, cifs_cp_sys, cifs_cp_ucs);
	CIFS_CP_REINIT(cifs_cp_ucs_to_sys, cifs_cp_ucs, cifs_cp_sys);
}

