#include "includes.h"

int cifs_log_level = CIFS_LOG_NORMAL;

int cifs_log_msg(const char *fmt, ...) {
	int res;
	va_list ap;
	va_start(ap, fmt);
	res = vfprintf(stderr, fmt, ap);
	va_end(ap);
	return res;
}

int cifs_log_hex(void *buf, int len) {
	int i, res = 0;
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
		res += p - line;
		*p++ = '\0';
		fputs(line, stderr);
		buf += 16;
		len -= 16;
	}
	return res;
}

void cifs_log_trans(const char *name, cifs_trans_p t) {
	cifs_log_debug("trans %s setup %d param %d data %d\n", name, t->setup_total, t->param_total, t->data_total);
	if (cifs_log_level >= CIFS_LOG_NOISY) {
		cifs_log_msg("setup %d\n", t->setup_total);
		cifs_log_hex(t->setup, t->setup_total);
		
		cifs_log_msg("param %d\n", t->param_total);
		cifs_log_hex(t->param, t->param_total);
		
		cifs_log_msg("data %d\n", t->data_total);
		cifs_log_hex(t->data, t->data_total);
	}
}

void cifs_log_flush(void) {
	fflush(stderr);
}

void cifs_log_packet(char *p) {
	cifs_log_debug("%s command %02X E %d_%d WC %d BC %d\n",
			(GET_PACKET_FLAGS(p)&FLAG_REPLY)?"In ":"Out",
			GET_PACKET_COMMAND(p),
			GET_PACKET_ERROR_CLASS(p), GET_PACKET_ERROR_CODE(p),
			GET_PACKET_WC(p), GET_PACKET_BC(p));
	cifs_log_struct_noisy(p, PACKET);
}

