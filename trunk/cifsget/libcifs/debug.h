#ifndef _DEBUG_H
#define _DEBUG_H

int cifs_log_msg(const char *fmt, ...);
int cifs_log_hex(void *buf, int len);
int cifs_log_buf(cifs_buf_p buf, const char *name);
void cifs_log_flush(void);

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

#define cifs_log_buf_level(level, buf, name) ((cifs_log_level >= level)?cifs_log_buf(buf, name):0)
#define cifs_log_buf_error(buf, name)    cifs_log_buf_level(CIFS_LOG_ERROR, buf, name)
#define cifs_log_buf_debug(buf, name)    cifs_log_buf_level(CIFS_LOG_DEBUG, buf, name)
#define cifs_log_buf_noisy(buf, name)    cifs_log_buf_level(CIFS_LOG_NOISY, buf, name)

#endif /* _DEBUG_H */
