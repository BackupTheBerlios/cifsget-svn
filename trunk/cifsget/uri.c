#include "includes.h"

#define HEX_TO_INT(c)	((c>='0' && c<='9')?(c-'0'):((c>='A' && c<='F')?(c-'A'+10):((c>='a' && c<='f')?(c-'a'+10):0)))

char *smb_uri_unescape(char *s) {
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

#define stredup(s,e) 	strndup(s, e-s)

// smb://[login[:password]@]host[:port][/share(/name)*]

/*int smb_parse_dest(char *s, smb_uri_p uri) {
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

int smb_uri_parse(smb_uri_p uri, const char *str) {
	char *p, *n, *d, *s;
	int i = 0;

	ZERO_STRUCTP(uri);
	
	p = iconv_local_to_utf8(str);
	smb_uri_unescape(p);
	s = iconv_utf8_to_dos(p);
	free(p);

	p = strstr(s, "://");
	if (p) {
		uri->scheme = stredup(s, p);
		p += 3;		
	} else {
		p = s;
	}

	d = uri->path = malloc(strlen(p)+1);

	while (*p && (*p == '/' || *p == '\\')) p++;
	
	while (*p) {
		n = p;
		while (*n && *n != '/' && *n != '\\') n++;
		switch (i) {
			case 0:
				//if (smb_parse_dest(p, uri)) return -1;
				uri->name = stredup(p, n);
				break;
			case 1:
				uri->tree = stredup(p, n);
				break;
			default:
				*d++ = '\\';
				while (p<n) *d++ = *p++;
				break;
		}
		p = n;
		while (*p && (*p == '/' || *p == '\\')) p++;
		i++;
	}
	*d = '\0';
	p = strrchr(uri->path, '\\');
	if (p) {
		uri->file = strdup(p+1);
		uri->dir = stredup(uri->path, p);
	}	
	free(s);
	return 0;
}

void smb_uri_free(smb_uri_p uri) {
	free(uri->scheme);
	free(uri->name);
	free(uri->tree);
	free(uri->path);
	free(uri->file);
	free(uri->dir);
	free(uri->login);
	free(uri->password);
	free(uri->addr);
}
