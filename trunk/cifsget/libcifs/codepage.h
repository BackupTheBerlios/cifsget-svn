#ifndef CODEPAGE_H
#define CODEPAGE_H

extern const char *cifs_cp_sys;
extern const char *cifs_cp_oem;

typedef void *cifs_cp_t;

extern cifs_cp_t cifs_cp_sys_to_oem, cifs_cp_oem_to_sys, cifs_cp_sys_to_ucs, cifs_cp_ucs_to_sys;

size_t cifs_cp_buf (cifs_cp_t cp, char *dst, size_t dst_size, const char *src, size_t src_size);
char *cifs_cp_bufa (cifs_cp_t cp, const char *src, size_t size);

#endif
