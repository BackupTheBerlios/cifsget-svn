#include "flow.h"

#define DEFAULT_INTERVAL 500000

static void cifs_sleep(uint64_t time) {
	struct timespec tm;
	tm.tv_sec = time/1000000;
	tm.tv_nsec = time%1000000*1000+999;
	while (nanosleep(&tm, &tm) && errno == EINTR);
}

static uint64_t cifs_gettime(void) {
	struct timeval cur;
	gettimeofday(&cur, NULL);
	return (uint64_t)cur.tv_sec * 1000000 + cur.tv_usec;
}

void cifs_flow_reset(cifs_flow_p f) {
	ZERO_STRUCTP(f);
	f->interval = DEFAULT_INTERVAL;
	f->start = cifs_gettime();
	f->a = f->b = f->c = f->start;
}

cifs_flow_p cifs_flow_new(void) {
	cifs_flow_p f;
	NEW_STRUCT(f);
	cifs_flow_reset(f);
	return f;
}

int cifs_flow(cifs_flow_p f, int delta) {
	uint64_t t, x, w;	
	
	f->total += delta;	
	f->d += delta;
	f->e += delta;

	x = (uint64_t)f->d * 1000000;

	f->c = cifs_gettime();

	f->time = (f->c - f->start) / 1000000;
	
	t = f->c - f->a;

	if (f->c - f->b > f->interval) {
		f->d = f->e;
		f->e = 0;
		f->a = f->b;
		f->b = f->c;
	}

	if (t > 0) {
		f->speed = x / t;
	} else {
		f->speed = 0;
	}

	if (f->limit > 0) {
		w = x / f->limit;
		if (w > t) cifs_sleep(w - t);
	}
	
	if (f->e == 0) return 1;
	
	return 0;
}

void cifs_flow_free(cifs_flow_p f) {
	free(f);
}

