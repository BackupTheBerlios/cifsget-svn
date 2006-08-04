#ifndef PROTO_H
#define PROTO_H

time_t smb_nttime2unix(int64_t nttime);
char *smb_nttime2unix_str(int64_t nttime);
	
int smb_negotiate(smb_connect_p c);
int smb_sessionsetup(smb_connect_p c);

int smb_tree_connect(smb_connect_p c, const char *server, const char *share);
int smb_tree_switch(smb_connect_p c, int tid);
int smb_tree_disconnect(smb_connect_p c, int tid);

smb_connect_p smb_connect(const char *host,  int port, const char *name);
smb_connect_p smb_connect_tree(const char *host, int port, const char *name, const char *tree);
smb_connect_p smb_connect_uri(smb_uri_p uri);
int smb_disconnect(smb_connect_p c);

int smb_open(smb_connect_p c, const char *name, int mode);
int smb_close(smb_connect_p c, int fid);

int smb_read_send(smb_connect_p c, int fid, size_t size, uint64_t offset);
size_t smb_read_get(smb_connect_p c, void **buf);
size_t smb_read_recv(smb_connect_p c, void *buf, size_t size);	
size_t smb_read(smb_connect_p c, int fid, void *buf, size_t count, uint64_t offset);

#endif /* PROTO_H */
