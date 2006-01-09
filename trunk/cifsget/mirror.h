#ifndef MIRROR_H
#define MIRROR_H

typedef struct smb_mirror_s {
	smb_uri_t uri;
	smb_connect_p conn;
	smb_dirinfo_t info;
	smb_flow_t flow;
	int fid;
	int fd;
	uint64_t offset;
	struct smb_mirror_s *next;
} smb_mirror_t;
typedef smb_mirror_t *smb_mirror_p;

int smb_download_mm(smb_mirror_p src, const char *dst);

#endif /* MIRROR_H */

