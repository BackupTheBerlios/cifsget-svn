#ifndef TRANSACT_H
#define TRANSACT_H

#define CIFS_TRANS_TIMEOUT 1000

#define CIFS_TRANS_MAX_SETUP_COUNT 255
#define CIFS_TRANS_MAX_PARAM_COUNT 1024
#define CIFS_TRANS_MAX_DATA_COUNT (60*1024)

typedef struct cifs_trans_s {
    cifs_buf_p setup, param, data;
} *cifs_trans_p;

void cifs_log_trans(const char *name, cifs_trans_p trans);

cifs_trans_p cifs_trans_new(void);
void cifs_trans_free(cifs_trans_p t);

void cifs_trans_req(cifs_connect_p c, int command, char *name, int setup_count, ...);
int cifs_trans_recv(cifs_connect_p c, cifs_trans_p t);

int cifs_trans_request(cifs_connect_p c, cifs_trans_p t);

#define PTR_OTRANS_PARAM(packet)	(PTR_PACKET_MAGIC(packet) + GET_OTRANS_PARAM_OFFSET(PTR_PACKET_W(packet)))
#define PTR_OTRANS_DATA(packet)		(PTR_PACKET_MAGIC(packet) + GET_OTRANS_DATA_OFFSET(PTR_PACKET_W(packet)))

#endif /* TRANSACT_H */
