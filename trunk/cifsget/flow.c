#include "includes.h"

int smb_flow_init(smb_flow_p f, int limit) {
	ZERO_STRUCTP(f);
	f->limit = limit;
	gettimeofday(&f->point, NULL);
	memcpy(&f->point1, &f->point, sizeof(struct timeval));
	return 0;
}

static void smb_sleep(double time) {
	struct timespec tm;
	tm.tv_sec = time;
	tm.tv_nsec = (time - tm.tv_sec) * 1000000000.0 + 1;
	while (nanosleep(&tm, &tm) && errno == EINTR);
}

int smb_flow(smb_flow_p f, int delta) {
	struct timeval cur;
	double t, x, w;
	f->total += delta;
	gettimeofday(&cur, NULL);
	
	f->delta += delta;
	f->delta1 += delta;

	x = f->delta;
	
	t = (cur.tv_sec - f->point.tv_sec) + 
		((double)(cur.tv_usec - f->point.tv_usec))/1000000.0;

	/*x = f->delta - f->delta1;
	
	t = (f->point1.tv_sec - f->point.tv_sec) + 
		((double)(f->point1.tv_usec - f->point.tv_usec))/1000000.0;*/

	if (cur.tv_sec - f->point1.tv_sec > 1) {
		f->delta = f->delta1;
		f->delta1 = 0;
		memcpy(&f->point, &f->point1, sizeof(struct timeval));
		memcpy(&f->point1, &cur, sizeof(struct timeval));
	}

	f->speed = x / t;

	if (f->limit > 0) {
		w = x / f->limit - t;
		if (w > 0) smb_sleep(w);
	}
	
	return 0;
}

