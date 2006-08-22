#ifndef URI_H
#define URI_H

#include <stdlib.h>
#include <string.h>
#include "macros.h"

typedef struct cifs_uri_s {
	char *scheme;
	char *name;
	char *tree;
	char *path;
	char *file; /* last name in path */
	char *dir;  /* all except file */
	char *login;
	char *password;
	char *addr; /*ip*/
	int port;
} cifs_uri_t;
typedef cifs_uri_t *cifs_uri_p;

char *cifs_uri_unescape(char *s);
int cifs_uri_parse(cifs_uri_p uri, const char *s);
void cifs_uri_free(cifs_uri_p uri);

#endif /* URI_H */
