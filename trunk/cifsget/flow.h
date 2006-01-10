#ifndef FLOW_H
#define FLOW_H



/* time line: ----- start ------------------------ a ---------- b ----- c -----> */


/* d = bytes in a .. c */
/* e = bytes in b .. c */
/* speed = d / (c - a) */
/* time = c - start    */

typedef struct smb_flow_s {
	int limit, speed;	/* bytes per second */
	uint64_t total;		/* bytes */
	time_t time;		/* work time in seconds */
		
	uint64_t start, a, b, c;
	uint64_t interval; 	/* flip interval in microseconds */
	int d, e;
	
} smb_flow_t;
typedef smb_flow_t *smb_flow_p;


smb_flow_p smb_flow_new(void);
void smb_flow_reset(smb_flow_p f);
int smb_flow(smb_flow_p f, int delta);
void smb_flow_free(smb_flow_p f);
	
#endif /* FLOW_H */

