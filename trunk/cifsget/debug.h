#ifndef _DEBUG_H 
#define _DEBUG_H


/*
smb_log_msg	always
smb_log_hex	always
smb_log_struct	noisy
smb_log_packet  debug & noisy
smb_log_trans	debug & noisy
 * */

void smb_log_msg(const char *fmt, ...);
void smb_log_hex(void *buf, int len);

#define _PRINT_BYTE(name, val, len)		smb_log_msg("b %s:\t%02X\t%u\n", #name, val, val)
#define _PRINT_WORD(name, val, len)		smb_log_msg("w %s:\t%04X\t%u\n", #name, val, val)
#define _PRINT_LONG(name, val, len)		smb_log_msg("l %s:\t%08X\t%u\n", #name, val, val)
#define _PRINT_QUAD(name, val, len)		smb_log_msg("q %s:\t%016llX\t%llu\n", #name, val, val)
#define _PRINT_RBYTE(name, val, len)		smb_log_msg("rb %s:\t%02X\t%u\n", #name, val, val)
#define _PRINT_RWORD(name, val, len)		smb_log_msg("rw %s:\t%04X\t%u\n", #name, val, val)
#define _PRINT_RLONG(name, val, len)		smb_log_msg("rl %s:\t%08X\t%u\n", #name, val, val)
#define _PRINT_RQUAD(name, val, len)		smb_log_msg("rq %s:\t%016llX\t%llu\n", #name, val, val)
#define _PRINT_SBYTE(name, val, len)		smb_log_msg("sb %s:\t%02X\t%d\n", #name, val, val)
#define _PRINT_SWORD(name, val, len)		smb_log_msg("sw %s:\t%04X\t%d\n", #name, val, val)
#define _PRINT_SLONG(name, val, len)		smb_log_msg("sl %s:\t%08X\t%d\n", #name, val, val)
#define _PRINT_SQUAD(name, val, len)		smb_log_msg("sq %s:\t%016llX\t%lld\n", #name, val, val)
#define _PRINT_NTTIME(name, val, len)		smb_log_msg("t %s:\t%lld\t%s", #name, val, smb_nttime2unix_str(val))
#define _PRINT_BLOB(name, val, len)		do { smb_log_msg("blob %s len %d\n", #name, len); smb_log_hex(val, len); } while(0)

#define _PRINT_ANY(name, type, val, len)		_PRINT_##type(name, val, len)

#define smb_log_struct_any(base, type)	do { smb_log_msg("struct %s %p\n", #type, base); ITR_##type(base, _PRINT_ANY); } while(0)

#define smb_log_struct(base, type) 	if (smb_log_level >= SMB_LOG_NOISY) smb_log_struct_any(base, type)

#define SMB_LOG_QUIET   0
#define SMB_LOG_ERROR   1
#define SMB_LOG_WARNING 2
#define SMB_LOG_NORMAL  3
#define SMB_LOG_VERBOSE 4
#define SMB_LOG_DEBUG   5
#define SMB_LOG_NOISY   6

#define smb_log(level, ...)	if (smb_log_level >= level) smb_log_msg(__VA_ARGS__)

#define smb_log_error(...)  	smb_log(SMB_LOG_ERROR, __VA_ARGS__)
#define smb_log_warning(...)  	smb_log(SMB_LOG_WARNING, __VA_ARGS__)
#define smb_log_normal(...)  	smb_log(SMB_LOG_NORMAL, __VA_ARGS__)
#define smb_log_verbose(...)  	smb_log(SMB_LOG_VERBOSE, __VA_ARGS__)
#define smb_log_debug(...)  	smb_log(SMB_LOG_DEBUG, __VA_ARGS__)
#define smb_log_noisy(...)  	smb_log(SMB_LOG_NOISY, __VA_ARGS__)

extern int smb_log_level;

#define smb_log_hex_level(level, buf, len) if (smb_log_level >= level) smb_log_hex(buf, len)

#define smb_log_hex_error(buf, len)  	smb_log_hex_level(SMB_LOG_ERROR, buf, len)
#define smb_log_hex_debug(buf, len)  	smb_log_hex_level(SMB_LOG_DEBUG, buf, len)
#define smb_log_hex_noisy(buf, len)  	smb_log_hex_level(SMB_LOG_NOISY, buf, len)

#define  smb_log_packet(name, p) 	do {\
						smb_log_debug("packet %s command %d\n", name, GET_PACKET_COMMAND(p));\
						smb_log_struct(p, PACKET);\
					} while (0)

void smb_log_trans(const char *name, smb_trans_p t);

void smb_log_flush(void);

#endif /* _DEBUG_H */
