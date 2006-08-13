#ifndef TRANSACT_H
#define TRANSACT_H

#define SMB_TRANS_TIMEOUT 1000

#define SMB_TRANS_MAX_SETUP_COUNT 255
#define SMB_TRANS_MAX_PARAM_COUNT 1024
#define SMB_TRANS_MAX_DATA_COUNT (60*1024)

typedef struct smb_trans_s {
	char *setup;
	char *param;
	char *data;
	size_t setup_count, setup_total;
	size_t param_count, param_total;
	size_t data_count, data_total;
} smb_trans_t;
typedef smb_trans_t *smb_trans_p;

int smb_trans_alloc(smb_trans_p t);
void smb_trans_free(smb_trans_p t);

void smb_trans_req(smb_connect_p c, int command, char *name, int setup_count, ...);
int smb_trans_recv(smb_connect_p c, smb_trans_p t);

int smb_trans_request(smb_connect_p c, smb_trans_p t);

#define PTR_OTRANS_PARAM(packet)	(PTR_PACKET_MAGIC(packet) + GET_OTRANS_PARAM_OFFSET(PTR_PACKET_W(packet)))
#define PTR_OTRANS_DATA(packet)		(PTR_PACKET_MAGIC(packet) + GET_OTRANS_DATA_OFFSET(PTR_PACKET_W(packet)))

#endif /* TRANSACT_H */
