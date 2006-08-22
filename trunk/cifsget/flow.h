#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include "macros.h"

/* time line: ----- start ------------------------ a ---------- b ----- c -----> */


/* d = bytes in a .. c */
/* e = bytes in b .. c */
/* speed = d / (c - a) */
/* time = c - start    */

typedef struct cifs_flow_s {
	int limit, speed;	/* bytes per second */
	uint64_t total;		/* bytes */
	time_t time;		/* work time in seconds */
		
	uint64_t start, a, b, c;
	uint64_t interval; 	/* flip interval in microseconds */
	int d, e;
	
} cifs_flow_t;
typedef cifs_flow_t *cifs_flow_p;


cifs_flow_p cifs_flow_new(void);
void cifs_flow_reset(cifs_flow_p f);
int cifs_flow(cifs_flow_p f, int delta);
void cifs_flow_free(cifs_flow_p f);
	
#endif /* FLOW_H */

