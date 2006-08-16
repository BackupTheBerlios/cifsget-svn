#include "includes.h"

int main (int argc, char **argv) {
	int i;
	iconv_init();
	cifs_mirror_p mir = NULL, m;
	for (i = 1; i < argc ; i++) {
		NEW_STRUCT(m);
		m->next = mir;
		mir = m;
		cifs_uri_parse(&m->uri, argv[i]);
	}
	cifs_download_mirror(mir, "xxx");
}
