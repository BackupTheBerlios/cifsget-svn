#ifndef URI_H
#define URI_H

typedef struct smb_uri_s {
	char *scheme;
	char *host;
	char *share;
	char *path;
	char *file; /* last name in path */
	char *dir;  /* all except file */
	char *login;
	char *password;
	int port;
} smb_uri_t;
typedef smb_uri_t *smb_uri_p;

char *smb_uri_unescape(char *s);
int smb_uri_parse(smb_uri_p uri, const char *s);
void smb_uri_free(smb_uri_p uri);

#endif /* URI_H */
