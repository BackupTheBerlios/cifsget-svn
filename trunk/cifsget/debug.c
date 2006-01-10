#include "includes.h"

int smb_log_level = SMB_LOG_NORMAL;

void smb_log_msg(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void smb_log_hex(void *buf, int len) {
	int i;
	char line[16*4+3], *p;
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
		*p++ = '\0';
		fputs(line, stderr);
		
		buf += 16;
		len -= 16;
	}
}

void smb_log_trans(const char *name, smb_trans_p t) {
	smb_log_debug("trans %s setup %d param %d data %d\n", name, t->setup_total, t->param_total, t->data_total);
	if (smb_log_level >= SMB_LOG_NOISY) {
		smb_log_msg("setup %d\n", t->setup_total);
		smb_log_hex(t->setup, t->setup_total);
		
		smb_log_msg("param %d\n", t->param_total);
		smb_log_hex(t->param, t->param_total);
		
		smb_log_msg("data %d\n", t->data_total);
		smb_log_hex(t->data, t->data_total);
	}
}

void smb_log_flush(void) {
	fflush(stderr);
}
