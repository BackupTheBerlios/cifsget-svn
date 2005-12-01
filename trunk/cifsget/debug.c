#include "includes.h"

void smb_dump_msg(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void smb_dump_buf(const char *name,  void *buf, size_t len) {
	int i, j;
	unsigned char *p = buf;
	fprintf(stderr, "%s len:%d\n", name, len);
	for (i=0;i<len;i+=16) {
		for (j=0;j<16;j++) {
			if ((i+j)<len) {
				fprintf(stderr, "%02X ", p[i+j]);
			} else{
				fprintf(stderr, "   ");
			}
		}
		fprintf(stderr, "\t");
		for (j=0;(j<16)&&(i+j)<len;j++) {
			if (p[i+j]>31) {
				fprintf(stderr, "%c", p[i+j]);
			} else {
				fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

void smb_dump_header(char *p) {
	PRINT_STRUCT(p, PACKET);
}

void smb_dump_packet(const char *name, char *p) {
	smb_dump_msg("\npacket %s ", name);
	smb_dump_header(p);
}

void smb_dump_trans(const char *name, smb_trans_p t) {
	smb_dump_msg("trans %s\n", name);
	smb_dump_buf("setup", t->setup, t->setup_total);
	smb_dump_buf("param", t->param, t->param_total);
	smb_dump_buf("data", t->data, t->data_total);
}

