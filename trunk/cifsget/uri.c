#include <stdlib.h>
#include <string.h>
#include "macros.h"

#include "uri.h"

#define HEX_TO_INT(c)	((c>='0' && c<='9')?(c-'0'):((c>='A' && c<='F')?(c-'A'+10):((c>='a' && c<='f')?(c-'a'+10):0)))

char *cifs_uri_unescape(char *s) {
	char *i=s, *o=s;
	if (s == NULL) return NULL;
        while (*i) {
		switch (*i) {
			case '%':
				if (i[1] && i[2]) {
					*o++ = (HEX_TO_INT(i[1]) << 4) + HEX_TO_INT(i[2]);
					i += 2;
				}
				break;
			/*case '+':
				*o++ = ' ';
				break;*/
			default:
				*o++ = *i;
				break;
		}
		i++;
	}
	*o = '\0';
	return s;
}

cifs_uri_p cifs_uri_parse(const char *str) {
	char *buf, *a, *b;

    cifs_uri_p uri;
    NEW_STRUCT(uri);

	buf = strdup(str);
	cifs_uri_unescape(buf);
    a = buf;
    if (a[0] == '\\' && a[1] == '\\') {
        /* UNC */
        uri->scheme = URI_CIFS;
        b = a;
        while ((b = strchr(b, '\\'))) {
            *b++ = '/';
        }
        a += 2;
    } else {
        b = strstr(a, "://");
        if (b) {
            if (!strncmp(a, "file", b-a)) {
                uri->scheme = URI_FILE;
            } else if (!strncmp(a, "cifs", b-a) || !strncmp(a, "smb", b-a)) {
                uri->scheme = URI_CIFS;
            } else {
                goto err;
            }
            a = b+3;
        } else {
            uri->scheme = URI_FILE;
        }        
    }

    if (uri->scheme != URI_FILE) {
        /*  [user[:password]@]host[:[addr:]port] */
        char *at, *co;
        b = strchr(a, '/');
        if (b) *b = 0;
        at = strchr(a, '@');
        if (at) {
            *at = 0;
            co = strchr(a, ':');
            if (co) {
                uri->user = strndup(a, co-a);
                uri->password = strdup(co+1);
            } else {
                uri->user = strdup(a);
            }
            *at = '@';
            a=at+1;
        }
        co = strchr(a, ':');
        if (co) {
            uri->host = strndup(a, co-a);
            at = strrchr(a, ':');
            if (co != at) {
                uri->addr = strndup(co+1, at-co-1);
            }
            uri->port = atoi(at+1);
        } else {
            uri->host = strdup(a);
        }
        if (b) {
            *b = '/';
            a = b+1;
        } else {
            a += strlen(a);            
        }
    }

    if (a[0] && uri->scheme == URI_CIFS) {
        b = strchr(a, '/');
        if (b) {
            uri->tree = strndup(a, b-a);
            a = b+1;
        } else {
            uri->tree = strdup(a);
            a += strlen(a);
        }
    }
    uri->path = strdup(a);
    b = strrchr(a, '/');
    if (b) {
        uri->file = strdup(b+1);
        uri->dir = strndup(a, b-a);
    } else {
        uri->file = strdup(a);
        uri->dir = strdup("");
    }
	free(buf);
	return uri;
err:
    free(buf);
    free(uri);
    return NULL;
}

void cifs_uri_free(cifs_uri_p uri) {
	free(uri->host);
	free(uri->tree);
	free(uri->path);
	free(uri->file);
	free(uri->dir);
	free(uri->user);
	free(uri->password);
	free(uri->addr);
	ZERO_STRUCTP(uri);
}
