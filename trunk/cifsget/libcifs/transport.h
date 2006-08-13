#ifndef TRANSPORT_H
#define TRANSPORT_H

#define SMB_MAGIC	0xFF534D42	/* 0xFF 'S' 'M' 'B' */

#define SMB_MAX_BUFFER 65535

#define SMB_MAX_RAW (60*1024)

typedef struct smb_connect_s {
	int sock;
	char *name;
	
	/* I/O buffers*/
	char *i, *o;
	/* I/O buffers ends */
	char *i_end, *o_end;	
	/* async I/O routine*/
	int i_size, i_len, i_done;
	int o_size, o_len, o_done;
	
	int session_key;
	int max_buffer_size;
	int max_raw_size;
	int capabilities;
	
	int connected;

	time_t time;
	int zone;	
} smb_connect_t;
typedef smb_connect_t *smb_connect_p;

int smb_packet_fail(char *packet);

int smb_packet_error(char *packet);

int smb_resolve(const char *host, struct in_addr *addr);

int smb_connect_raw(smb_connect_p conn, const struct in_addr *address, int port, const char *name);

int smb_shutdown(smb_connect_p c);
int smb_disconnect_raw(smb_connect_p conn);

int smb_connected(smb_connect_p c);

int smb_send(smb_connect_p c);
int smb_recv(smb_connect_p c);
int smb_recv_async(smb_connect_p c);
int smb_recv_more(smb_connect_p c);

size_t smb_send_raw(smb_connect_p c, void *buf, size_t len);
size_t smb_recv_raw(smb_connect_p c, void *buf, size_t len);

int smb_request(smb_connect_p c);

#endif /* TRANSPORT_H */

