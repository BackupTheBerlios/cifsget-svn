#ifndef CODEPAGE_H
#define CODEPAGE_H

char *iconv_local_to_utf8(const char *s);
char *iconv_utf8_to_dos(const char *s);
char *iconv_utf8_to_local(const char *s);
char *iconv_dos_to_local(const char *s);
char *iconv_local_to_dos(const char *s);
void iconv_init(void);

char *iconv_dos_to_local_buf(const char *s, char *buf, size_t size);
char *iconv_local_to_dos_buf(const char *s, char *buf, size_t size);
	
#endif
