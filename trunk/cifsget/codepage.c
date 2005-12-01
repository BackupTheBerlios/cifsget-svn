#include "includes.h"

static iconv_t cd_utf8_to_dos, cd_local_to_utf8, cd_utf8_to_local, cd_dos_to_local, cd_local_to_dos;

char *iconv_alloc(iconv_t cd, const char *ib) {
	size_t is, os, il, ol;
	char *ob, *op, *tmp, *ip;
	il = is = strlen(ib);
	ol = os = is*2;
	ob = malloc(os+1);
	if (ob == NULL) goto err;
	ip = (char*)ib;
	op = ob;
	while (iconv(cd, &ip, &il, &op, &ol) == (size_t)(-1)) {
		switch (errno) {
			case E2BIG:
				ol += os;
				os *= 2;
				tmp = realloc(ob, os+1);
				if (NULL == tmp) goto err;
				op = tmp + (op - ob);
				ob = tmp;
				break;
			case EILSEQ:
			case EINVAL:
				*op++ = '?';
				ol--;
				*ip++;
				il--;
				break;
			default:
				goto err;
		}
	}
	*op = '\0';
	tmp = realloc(ob, os-ol+1);
	return tmp;
err:
	free(ob);
	return NULL;
}


char *iconv_buf(iconv_t cd, const char *ib, char *buf, size_t size) {
	size_t is, os, il, ol;
	char *ob, *op, *ip;
	il = is = strlen(ib);
	ol = os = size;
	ob = buf;
	if (ob == NULL) return NULL;
	ip = (char*)ib;
	op = ob;
	while (iconv(cd, &ip, &il, &op, &ol) == (size_t)(-1)) {
		switch (errno) {
			case E2BIG:
				return NULL;
			case EILSEQ:
			case EINVAL:
				*op++ = '?';
				ol--;
				*ip++;
				il--;
				break;
			default:
				return NULL;
		}
	}
	*op = '\0';
	return buf;
}


char *iconv_local_to_utf8(const char *s) {
	return iconv_alloc(cd_local_to_utf8, s);
}

char *iconv_utf8_to_dos(const char *s) {
	return iconv_alloc(cd_utf8_to_dos, s);
}

char *iconv_utf8_to_local(const char *s) {
	return iconv_alloc(cd_utf8_to_local, s);
}

char *iconv_dos_to_local(const char *s) {
	return iconv_alloc(cd_dos_to_local, s);
}

char *iconv_local_to_dos(const char *s) {
	return iconv_alloc(cd_local_to_dos, s);
}

char *iconv_dos_to_local_buf(const char *s, char *buf, size_t size) {
	return iconv_buf(cd_dos_to_local, s, buf, size);
}

char *iconv_local_to_dos_buf(const char *s, char *buf, size_t size) {
	return iconv_buf(cd_local_to_dos, s, buf, size);
}



void iconv_init(void) {
	cd_utf8_to_dos = iconv_open(SMB_DOS_CODEPAGE, SMB_UTF8_CODEPAGE);
	cd_utf8_to_local = iconv_open(SMB_LOCAL_CODEPAGE, SMB_UTF8_CODEPAGE);
	cd_local_to_utf8 = iconv_open(SMB_UTF8_CODEPAGE, SMB_LOCAL_CODEPAGE);
	cd_dos_to_local = iconv_open(SMB_LOCAL_CODEPAGE, SMB_DOS_CODEPAGE);
	cd_local_to_dos = iconv_open(SMB_DOS_CODEPAGE, SMB_LOCAL_CODEPAGE);
}

