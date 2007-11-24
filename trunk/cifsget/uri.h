#ifndef URI_H
#define URI_H

// file://path
// scheme://[user[:password]@]host[[:address]:port]/tree/dir/file
// path == dir/file

enum {
    URI_FILE,
    URI_CIFS,
    URI_HTTP,
    URI_FTP,
};

typedef struct cifs_uri_s {
    int scheme;
	char *host;
	char *user;
	char *password;
	char *addr;
	int port;
    char *tree;    
	char *path;
    char *dir; 
    char *file; 
} cifs_uri_t;
typedef cifs_uri_t *cifs_uri_p;

cifs_uri_p cifs_uri_parse(const char *s);
void cifs_uri_free(cifs_uri_p uri);

#endif /* URI_H */
