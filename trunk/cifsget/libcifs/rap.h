#ifndef RAP_H
#define RAP_H

enum {
	CIFS_NODE_SHARE,
	CIFS_NODE_SERVER,
	CIFS_NODE_DOMAIN,
};

typedef struct cifs_enum_s cifs_enum_t;
typedef cifs_enum_t *cifs_enum_p;

typedef struct cifs_node_s {
	char name[256];
	char comment[256];
	int type;
	unsigned int attributes;
} cifs_node_t;
typedef cifs_node_t *cifs_node_p;

cifs_enum_p cifs_enum_share (cifs_connect_p c);
cifs_enum_p cifs_enum_server (cifs_connect_p c, const char *domain);
cifs_enum_p cifs_enum_domain (cifs_connect_p c);

int cifs_enum_count(cifs_enum_p e);

int cifs_enum_next(cifs_enum_p e, cifs_node_p n);

void cifs_enum_close(cifs_enum_p e);

#endif /* RAP_H */
