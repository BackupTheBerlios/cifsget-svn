#ifndef MIRROR_H
#define MIRROR_H

typedef struct cifs_mirror_s {
	cifs_uri_t uri;
	cifs_connect_p conn;	
	cifs_dirinfo_t info;
	cifs_flow_t flow;
	int fid;
	int fd;
	uint64_t offset;
	struct cifs_mirror_s *next;
} cifs_mirror_t;
typedef cifs_mirror_t *cifs_mirror_p;

int cifs_download_mirror(cifs_mirror_p src, const char *dst);

#endif /* MIRROR_H */

