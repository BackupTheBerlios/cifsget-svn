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

// smb://[login[:password]@]host[:port][/share(/name)*]

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

int cifs_uri_parse(cifs_uri_p uri, const char *str) {
	char *o, *s, *a, *b;

	s = strdup(str);
	cifs_uri_unescape(s);

	a = strstr(s, "://");
	if (a) {
		if (!uri->scheme) uri->scheme = strndup(s, a - s);
		a += 3;
	} else {
		a = s;
	}
	
	o = uri->path = malloc(strlen(a) + 2);	
	o[0] = '\0';
	for (int i = 0 ; (b = strsep(&a, "/\\")) ; ) {
		if (!b[0]) continue;		
		switch (i) {
			case 0:
				if (!uri->name) uri->name = strdup(b);
				if (!uri->addr) uri->addr = strdup(b);
				break;
			case 1:
				if (!uri->tree) uri->tree = strdup(b);
				break;
			default:
				strcat(strcat(o, "/"), b);
				break;
		}
		i++;
	}
	a = strrchr(uri->path, '/');
	if (a) {
		if (!uri->file) uri->file = strdup(a+1);
		if (!uri->dir) uri->dir = strndup(uri->path, a - uri->path);
	} else {
		uri->dir = strdup("");
	}
	free(s);
	return 0;
}

void cifs_uri_free(cifs_uri_p uri) {
	free(uri->scheme);
	free(uri->name);
	free(uri->tree);
	free(uri->path);
	free(uri->file);
	free(uri->dir);
	free(uri->login);
	free(uri->password);
	free(uri->addr);
	ZERO_STRUCTP(uri);
}
