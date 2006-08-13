#include "includes.h"

void usage() {
	smb_log_msg("\
usage: cifsget OPTION | URI | UNC | SHORT ...\n\
  \n\
  URI:    (smb|file|cifs)://host/share/path/NAME\n\
  UNC:    \\\\host\\share\\path\\NAME\n\
  SHORT:  host/share/path/NAME\n\
  NAME:   (file|dir|mask)\n\
  \n\
  OPTION:\n\
  -l                    list directory contents\n\
  -S                    calculate directory size\n\
  -o file               output file\n\
  -O dir                output directory\n\
  -s <int>[k|m|g|t]     limit download speed\n\
  -h                    show this message and exit\n\
  -d [0-6]              debug level, default - 3\n\
  -i ip                 destination ip\n\
  -p port               destination port\n\
");
}

smb_flow_p flow;
int opt_dirsize = 0;

void smb_print_file(smb_dirinfo_p di) {
	int dir = di->attributes & FILE_ATTRIBUTE_DIRECTORY;
	printf("%6s %s%s\n", (!dir || opt_dirsize) ? smb_hsize(di->file_size, NULL) : " <dir>" , di->name, dir ? "/":"");
}

int smb_print_node(smb_node_p n) {
	char *type;
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
	printf(" %s %s\t%s\n", type, n->name, n->comment);
	return 0;
}

int smb_print_status(const char *fmt, ...) {
	static int len = 0;
	int res;
	va_list ap;
	va_start(ap, fmt);
	res = vprintf(fmt, ap);
	va_end(ap);
	while (len-- > res) putchar(' ');
	putchar('\r');
	fflush(stdout);
	len = res;
	return res;
}

int smb_get_size_dir(smb_connect_p c, const char *path, const char *name, uint64_t *size) {
	smb_find_t fi;
	smb_dirinfo_t di;
	char *mask;
	
	
	if (smb_log_level >= SMB_LOG_NORMAL) {
		smb_print_status("%6s %s", smb_hsize(*size, NULL), name);
	}
	
	asprintf(&mask, "%s/*", path);
	if (smb_find_first(c, mask, &fi)) {
		free(mask);
		return -1;
	}
	free(mask);	
	
	while (!smb_find_next(&fi, &di)) {
		if (di.attributes & FILE_ATTRIBUTE_DIRECTORY) {
			char *pt, *nm;
			asprintf(&pt, "%s/%s", path, di.name);
			asprintf(&nm, "%s/%s", name, di.name);
			smb_get_size_dir(c, pt, nm, size);
			free(pt);
			free(nm);
		} else {
			*size += di.file_size;
		}
	}
	
	smb_find_close(&fi);
	
	return 0;
}

int smb_calc_size(smb_connect_p c, const char *path, smb_dirinfo_p di) {
	if (di->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		smb_get_size_dir(c, path,  di->name, &di->file_size);
		if (smb_log_level >= SMB_LOG_NORMAL) {
			smb_print_status("");
		}
	}
	return 0;
}

int smb_download_file(smb_connect_p c, smb_dirinfo_p di, const char *src, const char *dst) {
	int fid = -1;
	int fd = -1;
	static char buf[64*1024];
	int res, len;
	off_t off, rem;

	if (!smb_connected(c)) {
		errno = ENOTCONN;
		return -1;
	}
	
	fid = smb_open(c, src, OPEN_FLAGS_OPEN_READ);
	if (fid < 0) {
		perror(src);
		goto err;
	}
	
	fd = open(dst, O_CREAT | O_WRONLY | O_LARGEFILE, 0644);
	if (fd < 0) {
		perror(dst);
		goto err;
	}
	
	off = lseek(fd, 0, SEEK_END);
	if (off == (off_t)-1) {
		perror(dst);
		goto err;
	}

	rem = di->file_size - off;

	char size_str[10];

	smb_hsize(di->file_size, size_str);

	while (rem > 0) {
		len  = (rem < sizeof(buf))?rem:sizeof(buf);
		res = smb_read(c, fid, buf, len, off);
		if (res < 0) {
			perror(src);
			goto err;
		}
		if (res > 0) {			
			off += res;
			rem -= res;
			if (write(fd, buf, res) != res)	{
				perror(dst);
				goto err;
			}
		}
		if (smb_flow(flow, res) && smb_log_level >= SMB_LOG_NORMAL) {
			char speed_str[10];
			smb_print_status("%6s of %6s (%.1f%%) %6s/s ETA: %s ", 
					smb_hsize(off, NULL), 
					size_str,
					(double)off * 100.0 / di->file_size, 
					smb_hsize(flow->speed, speed_str), 
					flow->speed > 0 ? smb_htime(rem / flow->speed) : "???");
		}
	}
	if (smb_log_level >= SMB_LOG_NORMAL) {
		smb_print_status("");
	}
	close(fd);
	smb_close(c, fid);
	return 0;

err:
	if (fid > 0) smb_close(c, fid);
	if (fd > 0) close(fd);
	return -1;
}

int smb_download_dir(smb_connect_p c, const char *src, const char *dst) {
	char *mask = NULL, *sname, *dname;
	smb_dirinfo_t di;
	smb_find_t fi;

	if (!smb_connected(c)) {
		errno = ENOTCONN;
		goto err;
	}	

	if (mkdir(dst, 0755) && errno != EEXIST) {
		perror(dst);
		goto err;
	}	
	asprintf(&mask, "%s/*", src);
	
	if (smb_find_first(c, mask, &fi)) {
		perror(src);
		return -1;
	}
	
	while (!smb_find_next(&fi, &di)) {
		asprintf(&sname, "%s/%s", src, di.name);
		asprintf(&dname, "%s/%s", dst, di.name);
		
		smb_print_file(&di);
		
		if (di.attributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (smb_download_dir(c, sname, dname)) {
				perror(sname);
				if (!smb_connected(c)) {
					errno = ENOTCONN;
					goto err;
				}
			}			
		} else {
			if (smb_download_file(c, &di, sname, dname)) {
				perror(sname);
				if (!smb_connected(c)) {
					errno = ENOTCONN;
					goto err;
				}
			}
		}
		free(sname);
		free(dname);
	}
	smb_find_close(&fi);
	free(mask);
	return 0;
err:
	smb_find_close(&fi);
	free(mask);
	return -1;
}

int smb_list_dir(smb_connect_p c, const char *path) {
	char *mask;
	smb_dirinfo_t di;
	smb_find_t fi;
	uint64_t total = 0;
	asprintf(&mask, "%s/*", path);
	if (smb_find_first(c, mask, &fi)) {
		perror(path);
		return -1;
	}
	while (!smb_find_next(&fi, &di)) {
		if (di.attributes & FILE_ATTRIBUTE_DIRECTORY && opt_dirsize) {
			char *pt;
			asprintf(&pt, "%s/%s", path, di.name);
			smb_calc_size(c, pt, &di);
			free(pt);
		}
		smb_print_file(&di);
		total += di.file_size;
	}
	smb_find_close(&fi);
	smb_log_normal("total: %s\n", smb_hsize(total, NULL));
	free(mask);
	return 0;
}

int smb_list_node(smb_connect_p c) {
	smb_node_enum_t e;
	smb_node_t n;

	if (!c) return -1;

	if (smb_tree_connect(c, "IPC$")) {
		perror("ipc");
		return -1;
	}
	
	if (!smb_domain_enum(c, &e)) {
		char **dom = calloc(e.count+1, sizeof(char*));
		char **p = dom;
		
		while (!smb_node_next(c, &e, &n)) {
			smb_print_node(&n);
			*p++ = strdup(n.name);
		}
		
		smb_log_normal("\n");
		
		for (p = dom ; *p ; p++) {
			if (!smb_server_enum(c, &e, *p)) {
				smb_log_normal("%s:\n", *p);
				while (!smb_node_next(c, &e, &n)) {
					smb_print_node(&n);
				}
				smb_log_normal("\n");
			}
			free(*p);
		}
		free(dom);
	}
	
	if (!smb_share_enum(c, &e)) {
		while (!smb_node_next(c, &e, &n)) {
			smb_print_node(&n);
		}
	}
	
	smb_tree_disconnect(c, 0);
	return 0;
}

int smb_list(smb_connect_p c, const char *path, smb_dirinfo_p di) {	
	if (path) {
		if (di->attributes & FILE_ATTRIBUTE_DIRECTORY) {
			smb_log_normal("%s:\n", di->name);
			smb_list_dir(c, path);
			smb_log_normal("\n");
		} else {
			smb_print_file(di);
		}
	} else {
		smb_list_node(c);
	}
	return 0;
}

char *outfile = NULL, *outdir = ".";

int smb_download(smb_connect_p c, const char *path, smb_dirinfo_p di) {
	char *dst;
			
	if (!outfile) {
		asprintf(&dst, "%s/%s", outdir, di->name);
	} else {
		if (outfile[0] == '/') {
			dst = strdup(outfile);
		} else {
			asprintf(&dst, "%s/%s", outdir, outfile);
		}
	}
	
	smb_print_file(di);
	
	if (di->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		smb_download_dir(c, path, dst);
	} else {
		smb_download_file(c, di, path, dst);
	}		

	free(dst);
	free(outfile);
	outfile = NULL;
	return 0;
}

int smb_action(int action, smb_uri_p uri) {
	smb_connect_p c;
	smb_find_t fi;
	smb_dirinfo_t di;
	if (uri->tree) {
		c = smb_connect_tree(uri->addr, uri->port, uri->name, uri->tree);
		if (!c) {
			perror(uri->tree);
			return -1;
		}
		if (uri->path && uri->path[0]) {
			if (!c) return -1;
			if (smb_find_first(c, uri->path, &fi)) {
				perror(uri->path);
				smb_disconnect(c);
				return -1;
			}
			while (!smb_find_next(&fi, &di)) {
				char *path;
				asprintf(&path, "%s/%s", uri->dir, di.name);
				switch (action) {
					case 'd':
						smb_download(c, path, &di);
						break;
					case 'l':
						smb_list(c, path, &di);
						break;
				}
			}
			smb_find_close(&fi);
		} else {
			ZERO_STRUCT(di);
			di.attributes = FILE_ATTRIBUTE_DIRECTORY;
			strncpy(di.name, uri->tree, sizeof(di.name));
			switch (action) {
				case 'd':
					smb_download(c, "", &di);
					break;
				case 'l':
					smb_list(c, "", &di);
					break;
			}
		}
	} else {
		c = smb_connect(uri->addr, uri->port, uri->name);
		if (!c) {
			perror(uri->name);
			return -1;
		}
		switch (action) {
			case 'l':
				smb_list(c, NULL, NULL);
				break;
		}
	}
	smb_disconnect(c);
	
	return 0;
}

int main(int argc, char** argv) {
	int opt;
	smb_uri_p uri;
	int action = 'd';
	
	if (argc == 1) {
		usage();
		return 0;
	}
	flow = smb_flow_new();	

	NEW_STRUCT(uri);
	
	do {
		opt = getopt(argc, argv, "-ls:o:O:d:i:p:hS");
		switch (opt) {
			case 'd':
				smb_log_level = atoi(optarg);
				break;
			case 's':			
				flow->limit = smb_decode_hsize(optarg);
				break;
			case 'O':
				outdir = optarg;
				break;
			case 'o':
				outfile = strdup(optarg);
				break;
			case 'l':
				action = 'l';
				break;
			case 'S':
				opt_dirsize = 1;
				break;
			case 'i':
				free(uri->addr);
				uri->addr = strdup(optarg);
				break;
			case 'p':
				uri->port = atoi(optarg);
				break;
			case -1:
			case 1:
				if (uri->name) {
					smb_action(action, uri);
					smb_uri_free(uri);
				}
				if (optarg) {
					smb_uri_parse(uri, optarg);
				}
				break;
			case '?':
			case 'h':
				usage();
				return 2;
		}
	} while (opt != -1);
	return 0;
}

