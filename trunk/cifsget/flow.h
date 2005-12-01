#ifndef FLOW_H
#define FLOW_H

typedef struct smb_flow_s {
	int limit;
	int speed;
	uint64_t total;
	struct timeval point, point1;
	int delta, delta1;
} smb_flow_t;
typedef smb_flow_t *smb_flow_p;

int smb_flow_init(smb_flow_p f, int limit);

int smb_flow(smb_flow_p f, int delta);
	
#endif /* FLOW_H */
