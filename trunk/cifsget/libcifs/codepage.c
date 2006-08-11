#include "includes.h"

#include <iconv.h>

//const char *smb_cp_sys = "ASCII";
const char *smb_cp_sys = "CP1251";
const char *smb_cp_oem = "866";
const char *smb_cp_ucs = "UCS-2LE";

#define SMB_CP_NULL ((smb_cp_t)-1)

smb_cp_t smb_cp_sys_to_oem = SMB_CP_NULL,
			smb_cp_oem_to_sys = SMB_CP_NULL, 
			smb_cp_sys_to_ucs = SMB_CP_NULL, 
			smb_cp_ucs_to_sys = SMB_CP_NULL;

size_t smb_cp_block (smb_cp_t cp, char *out_buf, size_t out_size, const char *in_buf, size_t in_size) {
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

				*in_ptr++;
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

char *smb_cp (smb_cp_t cp, const char *src) {
	return smb_cp_buf(cp, src, strlen(src));
}

char *smb_cp_buf (smb_cp_t cp, const char *in_buf, size_t in_size) {
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
					*in_ptr++;
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

size_t smb_cp_tobuf (smb_cp_t cp, char *out_buf, size_t out_size, const char *src) {
	return smb_cp_block(cp, out_buf, out_size, src, strlen(src));
}

size_t smb_cp_write (smb_cp_t cp, char **ptr, char *lim, const char *src) {
	size_t res, in_size, out_size;
	in_size = strlen(src);
	out_size = lim - *ptr;
	res = smb_cp_block(cp, *ptr, out_size, src, in_size);
	if (res > 0) *ptr += res;
	return res;
}

#define SMB_CP_REINIT(cp, from, to) do {\
	if (cp != SMB_CP_NULL) iconv_close(cp);\
	cp = iconv_open(to, from);\
} while(0)

void smb_cp_init(void) __attribute__((constructor));
void smb_cp_init(void) {
	SMB_CP_REINIT(smb_cp_sys_to_oem, smb_cp_sys, smb_cp_oem);
	SMB_CP_REINIT(smb_cp_oem_to_sys, smb_cp_oem, smb_cp_sys);
	SMB_CP_REINIT(smb_cp_sys_to_ucs, smb_cp_sys, smb_cp_ucs);
	SMB_CP_REINIT(smb_cp_ucs_to_sys, smb_cp_ucs, smb_cp_sys);
}

