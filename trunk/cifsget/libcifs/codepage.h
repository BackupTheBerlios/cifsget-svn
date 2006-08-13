#ifndef CODEPAGE_H
#define CODEPAGE_H

extern const char *smb_cp_sys;
extern const char *smb_cp_oem;

typedef void *smb_cp_t;

extern smb_cp_t smb_cp_sys_to_oem, smb_cp_oem_to_sys, smb_cp_sys_to_ucs, smb_cp_ucs_to_sys;

size_t smb_cp_block (smb_cp_t cp, char *out_buf, size_t out_size, const char *in_buf, size_t in_size);

char *smb_cp (smb_cp_t cp, const char *src);
char *smb_cp_buf (smb_cp_t cp, const char *src, size_t size);

size_t smb_cp_tobuf (smb_cp_t cp, char *buf, size_t size, const char *src);
size_t smb_cp_write (smb_cp_t cp, char **ptr, char *lim, const char *src);

void smb_cp_init(void);

#define WRITE_BUF_OEM(p,l,s)	smb_cp_write(smb_cp_sys_to_oem, &p, l, s)
#define WRITE_BUF_UCS(p,l,s)	smb_cp_write(smb_cp_sys_to_ucs, &p, l, s)
#define WRITE_STRING_OEM(p,l,s) do { smb_cp_write(smb_cp_sys_to_oem, &p, l, s); WRITE_BYTE(p, 0); } while(0)
#define WRITE_STRING_UCS(p,l,s) do { smb_cp_write(smb_cp_sys_to_ucs, &p, l, s); WRITE_WORD(p, 0); } while(0)

#endif

