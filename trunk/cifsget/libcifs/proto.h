#ifndef CIFS_PROTO_H
#define CIFS_PROTO_H

#define WORDS_STRUCT(p, type, name) struct type *name = (struct type *) (p)->w;

#define CALL_SETUP(cmd, name, w) \
    cifs_packet_p i = c->i; \
    cifs_packet_p o = c->o; \
    WORDS_STRUCT(o, cifs_##name##_req_s, req); \
    WORDS_STRUCT(i, cifs_##name##_res_s, res); \
    ZERO_STRUCTP(req); \
    cifs_packet_setup(o, cmd, sizeof(struct cifs_##name##_req_s) + w); \

#define REQUEST_SETUP(cmd, name, w) \
    cifs_packet_p o = c->o; \
    WORDS_STRUCT(o, cifs_##name##_req_s, req); \
    ZERO_STRUCTP(req); \
    cifs_packet_setup(o, cmd, sizeof(struct cifs_##name##_req_s) + w);

time_t cifs_time(int64_t nttime);

void cifs_path_fix_oem (char *path);
void cifs_path_fix_ucs (char *path);

int cifs_negotiate(cifs_connect_p c);
int cifs_sessionsetup(cifs_connect_p c);

int cifs_tree_connect(cifs_connect_p c, const char *tree);
int cifs_tree_disconnect(cifs_connect_p c, int tid);
int cifs_tree_switch(cifs_connect_p c, int tid);

cifs_connect_p cifs_connect(const char *host,  int port, const char *name);
cifs_connect_p cifs_connect_tree(const char *host, int port, const char *name, const char *tree);

int cifs_open(cifs_connect_p c, const char *name, int mode);
int cifs_close(cifs_connect_p c, int fid);

int cifs_read_send(cifs_connect_p c, int fid, size_t size, uint64_t offset);
size_t cifs_read_get(cifs_connect_p c, void **buf);
size_t cifs_read_recv(cifs_connect_p c, void *buf, size_t size);	
size_t cifs_read(cifs_connect_p c, int fid, void *buf, size_t count, uint64_t offset);

size_t cifs_write(cifs_connect_p c, int fid, void *buf, size_t count, uint64_t offset);

#endif /* CIFS_PROTO_H */
