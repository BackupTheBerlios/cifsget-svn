#ifndef _DEBUG_H 
#define _DEBUG_H

#define PRINT_BYTE(name, val, len)		smb_dump_msg("b %s:\t%02X\t%u\n", #name, val, val)
#define PRINT_WORD(name, val, len)		smb_dump_msg("w %s:\t%04X\t%u\n", #name, val, val)
#define PRINT_LONG(name, val, len)		smb_dump_msg("l %s:\t%08X\t%u\n", #name, val, val)
#define PRINT_QUAD(name, val, len)		smb_dump_msg("q %s:\t%016llX\t%llu\n", #name, val, val)
#define PRINT_RBYTE(name, val, len)		smb_dump_msg("rb %s:\t%02X\t%u\n", #name, val, val)
#define PRINT_RWORD(name, val, len)		smb_dump_msg("rw %s:\t%04X\t%u\n", #name, val, val)
#define PRINT_RLONG(name, val, len)		smb_dump_msg("rl %s:\t%08X\t%u\n", #name, val, val)
#define PRINT_RQUAD(name, val, len)		smb_dump_msg("rq %s:\t%016llX\t%llu\n", #name, val, val)
#define PRINT_SBYTE(name, val, len)		smb_dump_msg("sb %s:\t%02X\t%d\n", #name, val, val)
#define PRINT_SWORD(name, val, len)		smb_dump_msg("sw %s:\t%04X\t%d\n", #name, val, val)
#define PRINT_SLONG(name, val, len)		smb_dump_msg("sl %s:\t%08X\t%d\n", #name, val, val)
#define PRINT_SQUAD(name, val, len)		smb_dump_msg("sq %s:\t%016llX\t%lld\n", #name, val, val)
#define PRINT_NTTIME(name, val, len)		smb_dump_msg("t %s:\t%lld\t%s", #name, val, smb_nttime2unix_str(val))
#define PRINT_BLOB(name, val, len)		smb_dump_buf(#name, val, len)

#define PRINT_ANY(name, type, val, len)	PRINT_##type(name, val, len);

#define PRINT_STRUCT(base, type)		do { smb_dump_msg("struct %s %p\n", #type, base); ITR_##type(base, PRINT_ANY); } while (0)


void smb_dump_msg(const char *fmt, ...);
void smb_dump_buf(const char *name,  void *buf, size_t len);
void smb_dump_header(char *p);
void smb_dump_packet(const char *name, char *p);
void smb_dump_trans(const char *name, smb_trans_p t);

#endif /* _DEBUG_H */
