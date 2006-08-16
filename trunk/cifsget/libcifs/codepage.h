#ifndef CODEPAGE_H
#define CODEPAGE_H

extern const char *cifs_cp_sys;
extern const char *cifs_cp_oem;

typedef void *cifs_cp_t;

extern cifs_cp_t cifs_cp_sys_to_oem, cifs_cp_oem_to_sys, cifs_cp_sys_to_ucs, cifs_cp_ucs_to_sys;

size_t cifs_cp_block (cifs_cp_t cp, char *out_buf, size_t out_size, const char *in_buf, size_t in_size);

char *cifs_cp (cifs_cp_t cp, const char *src);
char *cifs_cp_buf (cifs_cp_t cp, const char *src, size_t size);

size_t cifs_cp_tobuf (cifs_cp_t cp, char *buf, size_t size, const char *src);
size_t cifs_cp_write (cifs_cp_t cp, char **ptr, char *lim, const char *src);

void cifs_cp_init(void);

#define WRITE_BUF_OEM(p,l,s)	cifs_cp_write(cifs_cp_sys_to_oem, &p, l, s)
#define WRITE_BUF_UCS(p,l,s)	cifs_cp_write(cifs_cp_sys_to_ucs, &p, l, s)
#define WRITE_STRING_OEM(p,l,s) do { cifs_cp_write(cifs_cp_sys_to_oem, &p, l, s); WRITE_BYTE(p, 0); } while(0)
#define WRITE_STRING_UCS(p,l,s) do { cifs_cp_write(cifs_cp_sys_to_ucs, &p, l, s); WRITE_WORD(p, 0); } while(0)

#endif

