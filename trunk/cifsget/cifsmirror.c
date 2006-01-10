#include "includes.h"

int main (int argc, char **argv) {
	int i;
	iconv_init();
	smb_mirror_p mir = NULL, m;
	for (i = 1; i < argc ; i++) {
		NEW_STRUCT(m);
		m->next = mir;
		mir = m;
		smb_uri_parse(&m->uri, argv[i]);
	}
	smb_download_mirror(mir, "xxx");
}
