#include "includes.h"

void usage() {
	printf("usage: cifsget [OPTION]... (URI|UNC|SHORT)...\n\
  URI:\t(smb|file|cifs)://host/share/path/NAME\n\
  UNC:\t \\\\host\\share\\path\\NAME\n\
  SHORT:\t host/share/path/NAME\n\
  NAME: (file|dir|mask)\n\
  \n\
  -l                    list directory contents\n\
  -o file		output file\n\
  -O dir		output directory\n\
  -s <int>[k|m|g|t]     limit download speed\n\
  -d <int>              debug level\n");
	exit(2);
}

smb_flow_p flow;

void smb_print_file(smb_dirinfo_p di, const char *name) {
	if (di->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		printf(" <dir> %s/\n", name);
	} else {
		printf("%6s %s\n", human_file_size(di->file_size), name);
	}
}

int smb_print_node(smb_node_p n) {
	char *lname, *lcomm, *type;
	lname = n->name?iconv_dos_to_local(n->name):"";
	lcomm = n->comment?iconv_dos_to_local(n->comment):"";
	switch (n->type) {
		case SMB_NODE_SHARE:
			type = "<shr>";
			break;
		case SMB_NODE_SERVER:
			type = "<srv>";
			break;
		case SMB_NODE_DOMAIN:
			type = "<dom>";
			break;	
		default:
			type = "<unk>";
			break;		
	}
	printf(" %s %s\t%s\n", type, lname, lcomm);
	free(lname);
	free(lcomm);
	return 0;
}

int smb_download_file(smb_connect_p c, smb_dirinfo_p di, const char *src, const char *dst) {
	int fid = -1;
	int fd = -1;
	static char buf[64*1024];
	int res, len;
	uint64_t off, rem;
	
	fid = smb_open(c, src, OPEN_FLAGS_OPEN_READ);
	if (fid < 0) goto err;
	
	fd = open(dst, O_CREAT | O_WRONLY | O_LARGEFILE, 0644);
	if (fd < 0) goto err;
	
	off = lseek(fd, 0, SEEK_END);
	if (off == (off_t)-1) goto err;

	rem = di->file_size - off;

	int ll;
	while (rem > 0) {
		len  = (rem < sizeof(buf))?rem:sizeof(buf);
		res = smb_read(c, fid, buf, len, off);
		if (res < 0) goto err;
		if (res > 0) {			
			off += res;
			rem -= res;
			if (write(fd, buf, res) != res)	goto err;
			
		}		
		if (smb_flow(flow, res)) {
			ll = 0;
			ll += printf("%6s of ", human_file_size(off));
			ll += printf("%6s ", human_file_size(di->file_size));
			ll += printf("(%.1f%%) ", (double)off * 100.0 / di->file_size);
			ll += printf("%6s/s ", human_file_size(flow->speed));
			if (flow->speed > 0) {
				ll += printf("ETA: %s ", human_time((di->file_size - off) / flow->speed));
			}
			printf("\r");
			fflush(stdout);
		}
	}
	while (ll--) printf(" ");
	printf("\r");
	fflush(stdout);
	
	close(fd);
	if (smb_close(c, fid)) goto err;
	return 0;
err:
	perror(dst);
	if (fd >= 0) close(fd);
	if (fid >= 0) smb_close(c, fid);
	return -1;
}

int smb_download_dir(smb_connect_p c, const char *src, const char *dst) {
	char *mask, *sname, *dname, *lname;	
	smb_dirinfo_t di;
	smb_find_t f;

	if (mkdir(dst, 0755)) {
		perror(dst);
		return -1;
	}
	
	asprintf(&mask, "%s\\*", src);
	if (smb_find_first(c, &f, mask)) {
		perror(src);
		free(mask);
		return -1;
	}	

	while (!smb_find_next(c, &f, &di)) {
		lname = iconv_dos_to_local(di.name);
		
		asprintf(&sname, "%s\\%s", src, di.name);
		asprintf(&dname, "%s/%s", dst, lname);
		
		smb_print_file(&di, lname);
		
		if (di.attributes & FILE_ATTRIBUTE_DIRECTORY) {
			smb_download_dir(c, sname, dname);
		} else {
			smb_download_file(c, &di, sname, dname);
		}

		free(lname);
		free(sname);
		free(dname);
	}	
	smb_find_close(c, &f);
	free(mask);
	
	return 0;
}

int smb_list_dir(smb_connect_p c, const char *path) {
	char *mask, *lname;
	smb_dirinfo_t di;
	smb_find_t fi;
	uint64_t total = 0;
	asprintf(&mask, "%s\\*", path);
	if (smb_find_first(c, &fi, mask)) {
		free(mask);
		return -1;
	}
	while (!smb_find_next(c, &fi, &di)) {
		lname = iconv_dos_to_local(di.name);
		smb_print_file(&di, lname);
		if (!(di.attributes & FILE_ATTRIBUTE_DIRECTORY)) {
			total += di.file_size;
		}
		free(lname);
	}
	printf("total: %s\n", human_file_size(total));
	smb_find_close(c, &fi);
	free(mask);	
	return 0;
}

int smb_list_node(const char *host) {
	smb_connect_p c;
	smb_node_enum_t e;
	smb_node_t n;
	
	int dc, i;
	char **dom;
	c = smb_connect3(host, "IPC$");	
	
	if (!c) {
		perror(host);
		return -1;
	}
	
	if (!smb_domain_enum(c, &e)) {		
		dc = e.count;
		i=0;
		dom = calloc(dc, sizeof(char*));
		while (!smb_node_next(c, &e, &n)) {
			smb_print_node(&n);
			dom[i++] = strdup(n.name);
		}
		
		printf("\n");
		
		for (i = 0 ; i < dc ; i++) {			
			if (!smb_server_enum(c, &e, dom[i])) {
				printf("%s:\n", dom[i]);
				while (!smb_node_next(c, &e, &n)) {
					smb_print_node(&n);
				}
				printf("\n");
			}			
		}		
	}
	if (!smb_share_enum(c, &e)) {
		while (!smb_node_next(c, &e, &n)) {
			smb_print_node(&n);
		}
	}
	smb_disconnect(c);
	return 0;
}

int smb_ls(char *arg) {
	smb_uri_t uri;
	smb_connect_p c;
	smb_dirinfo_t di;
	smb_find_t f;	

	if (smb_uri_parse(&uri, arg)) {
		errno = EINVAL;
		return -1;
	}
	
	if (uri.share) {
		c = smb_connect3(uri.host, uri.share);
		if (!c) {
			perror(uri.host);
			return -1;
		}
		if (uri.file) {
			if (!smb_find_first(c, &f, uri.path)) {
				while (!smb_find_next(c, &f, &di)) {
					char *name = iconv_dos_to_local(di.name);
					if (di.attributes & FILE_ATTRIBUTE_DIRECTORY) {
						char *dir;
						printf("%s:\n", name);						
						asprintf(&dir, "%s\\%s", uri.dir, di.name);
						smb_list_dir(c, dir);
						free(dir);
						printf("\n");
					} else {
						smb_print_file(&di, name);
					}
					free(name);
				}
				smb_find_close(c, &f);
			} else {
				perror(arg);
			}
		} else {
			smb_list_dir(c, "");
		}
	} else {
		smb_list_node(uri.host);
	}	
	return 0;
}


char *outfile = NULL, *outdir = ".";

int smb_get(char *arg) {
	smb_uri_t uri;
	smb_connect_p c;
	smb_dirinfo_t di;
	smb_find_t f;
	
	if (smb_uri_parse(&uri, arg) || !uri.host) {
		errno = EINVAL;
		return -1;
	}
	
	c = smb_connect3(uri.host, uri.share);
	if (!c) {
		perror(uri.host);
		return -1;
	}
	
	if (uri.file) {
		if (smb_find_first(c, &f, uri.path)) {
			perror(arg);
			smb_disconnect(c);
			return -1;
		}
		
		while (!smb_find_next(c, &f, &di)) {
			char *src, *dst, *name;
			name = iconv_dos_to_local(di.name);
			asprintf(&src, "%s\\%s", uri.dir, di.name);
			
			if (!outfile) {
				asprintf(&dst, "%s/%s", outdir, name);
			} else {
				if (outfile[0] == '/') {
					dst = outfile;
					} else {
						asprintf(&dst, "%s/%s", outdir, outfile);
					}
			}
			
			smb_print_file(&di, name);
			
			if (di.attributes & FILE_ATTRIBUTE_DIRECTORY) {
				smb_download_dir(c, src, dst);
			} else {
				smb_download_file(c, &di, src, dst);
			}
			
			free(src);
			free(dst);				
			free(name);
			outfile = NULL;
		}
		smb_find_close(c, &f);
	} else {
		if (outfile) {
			smb_download_dir(c, "", outfile);
		} else {
			char *name = iconv_dos_to_local(uri.share);
			smb_download_dir(c, "", name);
			free(name);
		}
	}	
	smb_disconnect(c);
	return 0;
}

int main(int argc, char * const argv[]) {
#ifdef WINDOWS
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 0), &wsaData )) {
		exit(2);
	}
#endif
	iconv_init();
	
	flow = smb_flow_new();	

	while (1) {
		int o = getopt(argc, argv, "-l:d:s:o:O:");
		if (o == -1) break;
		switch (o) {
			case 'd':
				smb_log_level = atoi(optarg);
				break;
			case 's':
				flow->limit = from_human_file_size(optarg);
				break;
			case 'O':
				outdir = optarg;
				break;
			case 'o':
				outfile = strdup(optarg);
				break;
			case 'l':
				smb_ls(optarg);
				break;
			case 1:					
				smb_get(optarg);
		}
	}
	
#ifdef WINDOWS
	WSACleanup();
#endif
	return 0;
}

