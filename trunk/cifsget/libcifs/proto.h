#ifndef CIFS_PROTO_H
#define CIFS_PROTO_H

#define WORDS_STRUCT(p, type, name) struct type *name = (struct type *) (p)->w;

#define REQUEST_SETUP(cmd, name, w) \
    cifs_packet_p o = c->o; \
    WORDS_STRUCT(o, cifs_##name##_req_s, req); \
    ZERO_STRUCTP(req); \
    cifs_packet_setup(o, cmd, sizeof(struct cifs_##name##_req_s) + w)

#define RESPONSE_SETUP(name) \
    cifs_packet_p i = c->i; \
    WORDS_STRUCT(i, cifs_##name##_res_s, res)

#define CALL_SETUP(cmd, name, w) \
    REQUEST_SETUP(cmd, name, w); \
    RESPONSE_SETUP(name)

int cifs_negotiate(cifs_connect_p c);
int cifs_sessionsetup(cifs_connect_p c);

int cifs_read_send(cifs_connect_p c, int fid, size_t size, uint64_t offset);
size_t cifs_read_get(cifs_connect_p c, void **buf);
size_t cifs_read_recv(cifs_connect_p c, void *buf, size_t size);

int cifs_tree_ipc(cifs_connect_p c);

#endif /* CIFS_PROTO_H */
