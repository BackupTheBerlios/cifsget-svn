#ifndef TRANSPORT_H
#define TRANSPORT_H

#define CIFS_MAGIC	"\xffSMB"

#define CIFS_MAX_BUFFER 65535

#define CIFS_MAX_RAW (60*1024)

typedef struct cifs_packet_s {
    cifs_buf_p p;
    cifs_header_p h;
    cifs_words_p w;
    cifs_buf_p b;
} cifs_packet_t;
typedef cifs_packet_t *cifs_packet_p;

#define cifs_packet_ptr(pac, off) cifs_buf_ptr(pac->p,  off+4)
#define cifs_packet_off(pac, ptr) (cifs_buf_off(pac->p,  ptr) - 4)
#define cifs_packet_off_cur(pac) (cifs_buf_off(pac->p,  pac->b->p) - 4)
#define cifs_packet_range(pac, off, len) cifs_buf_range(pac->p, off+4, len)
#define cifs_packet_size(pac)   (cifs_buf_size(pac->p) - 4)

struct cifs_connect_s {
	int sock;

    cifs_packet_p i, o;
	
    char *name;
    int session_key;
	int max_buffer_size;
	int max_raw_size;
	int capabilities;

    int tid;
    int ipc;    //IPC$ TID

	time_t time;
	int zone;	
};

void cifs_packet_setup(cifs_packet_p packet, int command, int words_size);
void cifs_packet_log(cifs_packet_p);
int cifs_packet_errno(cifs_packet_p packet);

int cifs_resolve(const char *host, struct in_addr *addr);
int cifs_connect_sock(const struct in_addr *address, int port , const char *local_name, const char *remote_name);
cifs_connect_p cifs_connect_new(int sock, const char *name);

int cifs_send(cifs_connect_p c);
int cifs_recv(cifs_connect_p c);
int cifs_recv_async(cifs_connect_p c);

size_t cifs_send_raw(cifs_connect_p c, void *buf, size_t count);
size_t cifs_recv_raw(cifs_connect_p c, void *buf, size_t count);

int cifs_request(cifs_connect_p c);

#endif /* TRANSPORT_H */
