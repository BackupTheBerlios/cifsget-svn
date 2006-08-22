#include "human.h"

const char *cifs_hsize(uint64_t size, char *buf) {
	static char sbuf[64];	
	double s = size;
	static const double t = 1000.0;
	static const double p = 1024.0;
	if (!buf) buf = sbuf;
	if (s > t*p*p*p) {
		sprintf(buf, "%.1ft", s / (p*p*p*p));
	} else if (s > t*p*p) {
		sprintf(buf, "%.1fg", s / (p*p*p));
	} else if (s > t*p) {
		sprintf(buf, "%.1fm", s / (p*p));
	} else if (s > t) {
		sprintf(buf, "%.1fk", s / p);
	} else {
		sprintf(buf, "%.0fb", s);
	}
	return buf;
}

uint64_t cifs_decode_hsize(const char *s) {
	long long int x;
	char *p;
	x = strtol(s, &p, 10);
	switch (*p) {
		case 't':
		case 'T':
			x *= 1024;
		case 'g':
		case 'G':
			x *= 1024;
		case 'm':
		case 'M':
			x *= 1024;
		case 'k':
		case 'K':
			x *= 1024;
	}
	p++;
	if (*p == 'b' || *p == 'B') p++;
	if (*p != '\0') return -1;
	return x;
}

const char *cifs_htime(time_t time) {
	static char buf[64];
	int d, h, m, s;
	d = time / 86400;
	h = time / 3600 % 24;
	m = time / 60 % 60;
	s = time % 60;
	if (d) {
		sprintf(buf, "%d days %02d:%02d:%02d", d, h, m, s);
	} else if (h) {
		sprintf(buf, "%02d:%02d:%02d", h, m, s);
	} else {
		sprintf(buf, "%02d:%02d", m, s);
	}
	return buf;
}

