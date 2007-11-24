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

/*int cifs_parse_dest(char *s, cifs_uri_p uri) {
	char *at, *co, *be, *en, *t;
	be = s;
	en = strechr(be, NULL, '/');
	at = strechr(be, en, '@');
	if (at) {
		co = strechr(be, at, ':');
		if (co) {
			uri->login = stredup(be, co);
			uri->password = stredup(co+1, at);
		} else {
			uri->login = stredup(be, at);
			uri->password = NULL;
		}
		co = strechr(at, en, ':');
		if (co) {
			uri->host = stredup(at, co);
			uri->port = strtoul(co+1, &t, 10);
			if (t<en) return -1;
		} else {
			uri->host = stredup(at, en);
			uri->port = 0;
		}
	} else {
		uri->login = NULL;
		uri->password = NULL;
		co = strechr(be, en, ':');
		if (co) {
			uri->host = stredup(be, co);
			uri->port = strtoul(co+1, &t, 10);
			if (t<en) return -1;
		} else {
			uri->host = stredup(be, en);
			uri->port = 0;
		}
	}
	return 0;
}*/

#define SKIP_SLASH(p) while (*p && (*p == '/' || *p == '\\')) p++
#define NEXT_SLASH(p) while (*p && *p != '/' && *p != '\\') p++

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
            uri->path = buf;
            return uri;
        }        
    }

    if (uri->scheme != URI_FILE) {
        b = strchr(a, '/');
        if (b) {
            uri->host = strndup(a, b-a);
            a = b+1;
        } else {
            uri->host = strdup(a);
            a += strlen(a);
        }
        uri->addr = strdup(uri->host);
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
