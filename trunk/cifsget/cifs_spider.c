#include <stdlib.h>
#include <stdio.h>
#include "libcifs/includes.h"
#include "uri.h"

void cifs_dump_line(int id, int pid, cifs_dirent_p de) {
	printf("%d\t%d\t%s\t%llu\t%d\n", id, pid, de->name, de->st.is_directory?0:de->st.file_size, de->st.is_directory);
}

int cifs_dump_dir(cifs_connect_p c, const char *path, int *id, int pid, int deep) {
	cifs_dirent_p de;
	cifs_dir_p d;
	d = cifs_opendir(c, path);
	if (!d) {
		perror(path);
		return -1;
	}
	while ((de = cifs_readdir(d))) {
		(*id)++;
		cifs_dump_line(*id, pid, de);
		if (de->st.is_directory && deep) {
			cifs_dump_dir(c, de->path, id, *id, deep - 1);
		}
	}
	cifs_closedir(d);
	return 0;
}

int cifs_dump(cifs_uri_p uri) {
	cifs_connect_p c;
	c = cifs_connect(uri->addr, uri->port, uri->host, uri->tree);
	if (!c) {
		perror(uri->tree);
		return -1;
	}
	int id = 0;
	cifs_dump_dir(c, uri->path, &id, 0, 8);
	cifs_connect_close(c);
	return 0;
}

int main(int argc, char** argv) {
	cifs_uri_p uri;
	if (argc == 1) {
		return 2;
	}	
	cifs_log_stream = stderr;
    uri = cifs_uri_parse(argv[1]);
    if (uri == NULL) {
        return 2;
    }
	cifs_dump(uri);
	cifs_uri_free(uri);
}

