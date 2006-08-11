#ifndef RAP_H
#define RAP_H

enum {
	SMB_NODE_SHARE,
	SMB_NODE_SERVER,
	SMB_NODE_DOMAIN,
};

typedef struct smb_node_enum_s {
	smb_trans_t t;
	char *cur;
	int count;
	int type;
	int conv;
} smb_node_enum_t;
typedef smb_node_enum_t *smb_node_enum_p;

typedef struct smb_node_s {
	char name[256];
	char comment[256];
	int type;
	unsigned int attributes;
} smb_node_t;
typedef smb_node_t *smb_node_p;

int smb_share_enum(smb_connect_p c, smb_node_enum_p e);
int smb_server_enum(smb_connect_p c, smb_node_enum_p e, const char *domain);
int smb_domain_enum(smb_connect_p c, smb_node_enum_p e);

int smb_node_next(smb_connect_p c, smb_node_enum_p e, smb_node_p n);

#endif /* RAP_H */
