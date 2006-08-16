#ifndef TRANSPORT_H
#define TRANSPORT_H

#define CIFS_MAGIC	0xFF534D42	/* 0xFF 'S' 'M' 'B' */

#define CIFS_MAX_BUFFER 65535

#define CIFS_MAX_RAW (60*1024)

typedef struct cifs_connect_s {
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
} cifs_connect_t;
typedef cifs_connect_t *cifs_connect_p;

int cifs_packet_fail(char *packet);

int cifs_packet_error(char *packet);

int cifs_resolve(const char *host, struct in_addr *addr);

int cifs_connect_sock(const struct in_addr *address, int port , const char *local_name, const char *remote_name);

cifs_connect_p cifs_connect_new(int sock, const char *name);

void cifs_connect_close(cifs_connect_p c);

int cifs_connected(cifs_connect_p c);

int cifs_send(cifs_connect_p c);
int cifs_recv(cifs_connect_p c);
int cifs_recv_async(cifs_connect_p c);
int cifs_recv_more(cifs_connect_p c);

size_t cifs_send_raw(cifs_connect_p c, void *buf, size_t len);
size_t cifs_recv_raw(cifs_connect_p c, void *buf, size_t len);

int cifs_request(cifs_connect_p c);

#endif /* TRANSPORT_H */

