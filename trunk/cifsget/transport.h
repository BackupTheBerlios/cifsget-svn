#ifndef TRANSPORT_H
#define TRANSPORT_H

#define SMB_MAGIC	0xFF534D42	/* 0xFF 'S' 'M' 'B' */

typedef struct smb_connect_s {
	int sock;
	char *i, *o;
	
	/* async recv routine*/
	int recv_len;
	int recv_done;
	
	int session_key;
	int max_buffer_size;
	int max_raw_size;
	int capabilities;
	int server_time_zone;
	
	int balance;
	int connected;
} smb_connect_t;
typedef smb_connect_t *smb_connect_p;

smb_connect_p smb_connect(const char *server);
int smb_disconnect(smb_connect_p c);
int smb_connected(smb_connect_p c);

int smb_send(smb_connect_p c);
int smb_recv(smb_connect_p c);
int smb_recv_async(smb_connect_p c);
int smb_recv_more(smb_connect_p c);

size_t smb_send_raw(smb_connect_p c, void *buf, size_t len);
size_t smb_recv_raw(smb_connect_p c, void *buf, size_t len);

int smb_request(smb_connect_p c);

#endif /* TRANSPORT_H */
