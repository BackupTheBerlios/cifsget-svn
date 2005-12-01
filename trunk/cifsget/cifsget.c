#include "includes.h"

void usage() {
	printf("usage: cifsget [OPTION]... (URI|UNC|SHORT)...\n\
  URI:\t(smb|file|cifs)://host/share/path/NAME\n\
  UNC:\t \\\\host\\share\\path\\NAME\n\
  SHORT:\t host/share/path/NAME\n\
  NAME: (file|dir|mask)\n\
  \n\
  -l                    list\n\
  -o name		write to file or dir name, instead of original name\n\
  -s <int>[k|m|g|t]     limit download speed\n");
	exit(2);
}

smb_flow_t flow;

int smb_download(smb_connect_p c, smb_dirinfo_p di, const char *src, const char *dst, char *lname);

const char *human_file_size(long long int size) {
	static char buf[64];
	double s = size;
	static const double t = 1000.0;
	static const double p = 1024.0;
	if (s > t*p*p*p) {
		sprintf(buf, "%.1ft", s / (p*p*p*p));
	} else if (s > t*p*p) {
		sprintf(buf, "%.1fg", s / (p*p*p));
	} else if (s > t*p) {
		sprintf(buf, "%.1fm", s / (p*p));
	} else if (s > t) {
		sprintf(buf, "%.1fk", s / p);
	} else {
		sprintf(buf, "%.0fb", s);
	}
	return buf;
}

long long int from_human_file_size(const char *s) {
	long long int x;
	char *p;
	x = strtol(s, &p, 10);
	switch (*p) {
		case 't':
		case 'T':
			x *= 1024;
		case 'g':
		case 'G':
			x *= 1024;
		case 'm':
		case 'M':
			x *= 1024;
		case 'k':
		case 'K':
			x *= 1024;
	}
	p++;
	if (*p == 'b' || *p == 'B') p++;
	if (*p != '\0') return -1;
	return x;
}

const char *human_time(int time) {
	static char buf[64];
	int d, h, m, s;
	d = time / 86400;
	h = time / 3600 % 24;
	m = time / 60 % 60;
	s = time % 60;
	if (d) {
		sprintf(buf, "%d days %02d:%02d:%02d", d, h, m, s);
	} else if (h) {
		sprintf(buf, "%02d:%02d:%02d", h, m, s);
	} else {
		sprintf(buf, "%02d:%02d", m, s);
	}
	return buf;
}

void smb_print_file(smb_dirinfo_p di, const char *name) {
	if (di->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		printf(" <dir> %s/\n", name);
	} else {
		printf("%6s %s\n", human_file_size(di->file_size), name);
	}
}

int smb_download_file(smb_connect_p c, smb_dirinfo_p di, const char *src, const char *dst) {
	int fid = -1;
	int fd = -1;
	static char buf[64*1024];
	int res, len;
	uint64_t off, rem;
	
	fid = smb_open(c, src, OPEN_FLAGS_OPEN_READ);
	if (fid < 0) goto err;
	
	fd = open(dst, O_CREAT | O_WRONLY | O_LARGEFILE, 0664);
	if (fd < 0) goto err;
	
	off = lseek(fd, 0, SEEK_END);
	if (off == (off_t)-1) goto err;

	rem = di->file_size - off;

	while (rem > 0) {
		len  = (rem < sizeof(buf))?rem:sizeof(buf);
		res = smb_read(c, fid, buf, len, off);
		if (res < 0) goto err;
		if (res > 0) {			
			off += res;
			rem -= res;
			if (write(fd, buf, res) != res)	goto err;
			smb_flow(&flow, res);
		}
		printf("%6s  ", human_file_size(off));
		printf("done: %.1f%%  ", (double)off * 100.0 / di->file_size);
		printf("tolal: %s  ", human_file_size(flow.total));
		printf("speed: %s/s  ", human_file_size(flow.speed));
		if (flow.speed) {
			printf("ETA: %s          \r", human_time((di->file_size - off) / flow.speed));
		} else {
			printf("\r");
		}
		fflush(stdout);		
	}	
	printf("                                                                    \r");
	
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
	int res = -1;
	smb_dirinfo_t di;
	smb_find_t f;
	
	asprintf(&mask, "%s\\*", src);
	if (!smb_find_first(c, &f, mask)) {
		mkdir(dst, 0775);
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
		res = 0;
	} else {
		perror(dst);
	}
	free(mask);
	return res;
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

int smb_list(smb_connect_p c, smb_dirinfo_p di, char *path, char *lname) {
	if (di->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		printf("%s:\n", lname);
		smb_list_dir(c, path);
		printf("\n");
	} else {
		smb_print_file(di, lname);
	}
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
		perror("connect");
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

int main(int argc, char * const argv[]) {
	smb_uri_t uri;
	smb_connect_p c;
	smb_dirinfo_t di;
	smb_find_t f;
	char *sname, *lname;
	char action;

	char *out = NULL;
	
	if (argc<2) usage();

#ifdef WINDOWS
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 0), &wsaData )) {
		exit(2);
	}
#endif
	iconv_init();

	action = 'd';

	smb_flow_init(&flow, 0);

	for (int i = 1 ; i<argc ; i++) {
		if (!strcmp(argv[i], "-l")) {
			action = 'l';
		} else if (!strcmp(argv[i], "-d")) {
			action = 'd';
		} else if (!strcmp(argv[i], "-s"))  {
			i++;
			if (i == argc) {
				fprintf(stderr, "-s: parameter needed\n");
				break;
			}
			flow.limit = from_human_file_size(argv[i]);
		} else if (!strcmp(argv[i], "-o")) {
			i++;
			if (i == argc) {
				fprintf(stderr, "-o: parameter needed\n");
				break;
			}
			out = argv[i];
		} else {
			if (smb_uri_parse(&uri, argv[i])) continue;
			
			if (!uri.host) usage();
			
			if (uri.share) {
reconnect:
				c = smb_connect3(uri.host, uri.share);
				if (!c) {
					perror("connect");
					continue;
				}
				if (uri.file) {
					if (!smb_find_first(c, &f, uri.path)) {
						while (!smb_find_next(c, &f, &di)) {
							lname = iconv_dos_to_local(di.name);
							asprintf(&sname, "%s\\%s", uri.dir, di.name);
							switch (action) {
								case 'd':
									smb_print_file(&di, lname);
									if (di.attributes & FILE_ATTRIBUTE_DIRECTORY) {
										smb_download_dir(c, sname, out?out:lname);
									} else {
										smb_download_file(c, &di, sname, out?out:lname);
									}
									break;
								case 'l':
									smb_list(c, &di, sname, lname);
									break;
							}
							free(sname);
							free(lname);
						}
						smb_find_close(c, &f);
					} else {
						perror(argv[i]);
					}
				} else {
					lname = iconv_dos_to_local(uri.share);
					switch (action) {
						case 'd':						
							smb_download_dir(c, "", out?out:lname);
							break;
						case 'l':
							smb_list_dir(c, "");
							break;
					}
					free(lname);
				}
				if (smb_connected(c)) {
					smb_disconnect(c);
				} else {
					smb_disconnect(c);
					printf("reconnect\n");
					goto reconnect;
				}
			} else {
				switch (action) {
					case 'l':
						smb_list_node(uri.host);
						break;
					case 'd':
						smb_list_node(uri.host);
						break;
				}
			}
			out = NULL;
		}
	}
	
#ifdef WINDOWS
	WSACleanup();
#endif
	return 0;
}
