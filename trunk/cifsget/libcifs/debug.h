#ifndef _DEBUG_H
#define _DEBUG_H

extern int cifs_log_level;
extern FILE *cifs_log_stream;

int cifs_log_msg(const char *fmt, ...);
int cifs_log_hex(void *buf, int len);
void cifs_log_flush(void);

#define _PRINT_BYTE(name, val, len)		cifs_log_msg("b %s:\t%02X\t%u\n", #name, val, val)
#define _PRINT_WORD(name, val, len)		cifs_log_msg("w %s:\t%04X\t%u\n", #name, val, val)
#define _PRINT_LONG(name, val, len)		cifs_log_msg("l %s:\t%08X\t%u\n", #name, val, val)
#define _PRINT_QUAD(name, val, len)		cifs_log_msg("q %s:\t%016llX\t%llu\n", #name, val, val)
#define _PRINT_BE_BYTE(name, val, len)		cifs_log_msg("B %s:\t%02X\t%u\n", #name, val, val)
#define _PRINT_BE_WORD(name, val, len)		cifs_log_msg("W %s:\t%04X\t%u\n", #name, val, val)
#define _PRINT_BE_LONG(name, val, len)		cifs_log_msg("L %s:\t%08X\t%u\n", #name, val, val)
#define _PRINT_BE_QUAD(name, val, len)		cifs_log_msg("Q %s:\t%016llX\t%llu\n", #name, val, val)
#define _PRINT_SIGNED_BYTE(name, val, len)	cifs_log_msg("1 %s:\t%02X\t%d\n", #name, val, val)
#define _PRINT_SIGNED_WORD(name, val, len)	cifs_log_msg("2 %s:\t%04X\t%d\n", #name, val, val)
#define _PRINT_SIGNED_LONG(name, val, len)	cifs_log_msg("4 %s:\t%08X\t%d\n", #name, val, val)
#define _PRINT_SIGNED_QUAD(name, val, len)	cifs_log_msg("8 %s:\t%016llX\t%lld\n", #name, val, val)
#define _PRINT_NT_TIME(name, val, len)		cifs_log_msg("t %s:\t%lld\n", #name, val)
#define _PRINT_BLOB(name, val, len)		do { cifs_log_msg("D %s len %d\n", #name, len); cifs_log_hex(val, len); } while(0)

#define _PRINT_ANY(name, type, val, len)		_PRINT_##type(name, val, len)

#define cifs_log_struct_any(base, type)		do { cifs_log_msg("struct %s %p\n", #type, base); ITR_##type(base, _PRINT_ANY); } while(0)

#define cifs_log_struct(base, type) 			if (cifs_log_level >= CIFS_LOG_DEBUG) cifs_log_struct_any(base, type)

#define cifs_log_struct_noisy(base, type) 	if (cifs_log_level >= CIFS_LOG_NOISY) cifs_log_struct_any(base, type)

#define CIFS_LOG_QUIET   0
#define CIFS_LOG_ERROR   1
#define CIFS_LOG_WARNING 2
#define CIFS_LOG_NORMAL  3
#define CIFS_LOG_VERBOSE 4
#define CIFS_LOG_DEBUG   5
#define CIFS_LOG_NOISY   6

#define cifs_log(level, ...)	((cifs_log_level >= level)?cifs_log_msg(__VA_ARGS__):0)

#define cifs_log_error(...)  	cifs_log(CIFS_LOG_ERROR, __VA_ARGS__)
#define cifs_log_warning(...)  	cifs_log(CIFS_LOG_WARNING, __VA_ARGS__)
#define cifs_log_normal(...)  	cifs_log(CIFS_LOG_NORMAL, __VA_ARGS__)
#define cifs_log_verbose(...)  	cifs_log(CIFS_LOG_VERBOSE, __VA_ARGS__)
#define cifs_log_debug(...)  	cifs_log(CIFS_LOG_DEBUG, __VA_ARGS__)
#define cifs_log_noisy(...)  	cifs_log(CIFS_LOG_NOISY, __VA_ARGS__)


#define cifs_log_hex_level(level, buf, len) ((cifs_log_level >= level)?cifs_log_hex(buf, len):0)

#define cifs_log_hex_error(buf, len)  	cifs_log_hex_level(CIFS_LOG_ERROR, buf, len)
#define cifs_log_hex_debug(buf, len)  	cifs_log_hex_level(CIFS_LOG_DEBUG, buf, len)
#define cifs_log_hex_noisy(buf, len)  	cifs_log_hex_level(CIFS_LOG_NOISY, buf, len)

#endif /* _DEBUG_H */
