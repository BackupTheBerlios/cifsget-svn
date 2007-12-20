#include "includes.h"

int cifs_log_level = CIFS_LOG_WARNING;

FILE *cifs_log_stream = NULL;

int cifs_log_msg(const char *fmt, ...) {
	if (!cifs_log_stream) return 0;
	int res;
	va_list ap;
	va_start(ap, fmt);
	res = vfprintf(cifs_log_stream, fmt, ap);
	va_end(ap);
	return res;
}

int cifs_log_hex(void *buf, int len) {
	int i, res = 0;
	char line[16*4+3], *p;
	if (!cifs_log_stream) return 0;
	while (len > 0) {
		p = line;
		i = 0;
		while (i < 16 && i < len) {
			p += sprintf(p, "%02X ", ((unsigned char*)buf)[i]);
			i++;
		}
		while (i < 16) {
			*p++ = ' ';
			*p++ = ' ';
			*p++ = ' ';
			i++;
		}
		*p++ = '\t';
		i = 0;
		while (i < 16 && i < len) {
			if (((unsigned char*)buf)[i] >= ' ') {
				*p++ = ((unsigned char*)buf)[i];
			} else {
				*p++ = '.';
			}
			i++;
		}
		*p++ = '\n';
		res += p - line;
		*p++ = '\0';
		fputs(line, cifs_log_stream);
		buf += 16;
		len -= 16;
	}
	return res;
}

void cifs_log_flush(void) {
	if (!cifs_log_stream) return;
	fflush(cifs_log_stream);
}


int cifs_log_buf(cifs_buf_p buf, const char *name) {
    int res = 0;
	res += cifs_log_msg("BUFFER %s S %d L %d\n", name, cifs_buf_size(buf), cifs_buf_len(buf));
	res += cifs_log_hex(buf->b, cifs_buf_size(buf));
    return res;
}

