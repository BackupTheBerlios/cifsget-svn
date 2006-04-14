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
  -o file		output file\n\
  -O dir		output directory\n\
  -s <int>[k|m|g|t]     limit download speed\n\
  -h                    show this message and exit\n\
  -d [0-6]              debug level, default - 3\n\
  -i ip			destination ip\n\
");
}

smb_flow_p flow;

void smb_print_file(smb_dirinfo_p di, const char *name) {
	if (di->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		smb_log_normal(" <dir> %s/\n", name);
	} else {
		smb_log_normal("%6s %s\n", human_file_size(di->file_size), name);
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
	smb_log_normal(" %s %s\t%s\n", type, lname, lcomm);
	free(lname);
	free(lcomm);
	return 0;
}

int smb_download_file(smb_connect_p c, smb_dirinfo_p di, const char *src, const char *dst) {
	int fid = -1;
	int fd = -1;
	static char buf[64*1024];
	int res, len;
	off_t off, rem;
	
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

	int ll = 0;
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
		if (smb_log_level >= SMB_LOG_NORMAL && smb_flow(flow, res)) {
			ll = 0;
			ll += smb_log_msg("%6s of ", human_file_size(off));
			ll += smb_log_msg("%6s ", human_file_size(di->file_size));
			ll += smb_log_msg("(%.1f%%) ", (double)off * 100.0 / di->file_size);
			ll += smb_log_msg("%6s/s ", human_file_size(flow->speed));
			if (flow->speed > 0) {
				ll += smb_log_msg("ETA: %s ", human_time((di->file_size - off) / flow->speed));
			}
			smb_log_msg("\r");
			smb_log_flush();
		}
	}
	if (smb_log_level >= SMB_LOG_NORMAL) {
		while (ll--) smb_log_msg(" ");
		smb_log_msg("\r");
		smb_log_flush();
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
	char *mask, *sname, *dname, *lname;	
	smb_dirinfo_t di;
	smb_find_p f;

	if (mkdir(dst, 0755) && errno != EEXIST) {
		perror(dst);
		return -1;
	}
	
	asprintf(&mask, "%s\\*", src);
	f = smb_find_first2(c, mask);
	if (!f) {
		perror(src);
		free(mask);
		return -1;
	}

	while (!smb_find_next(f, &di)) {
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
	smb_find_close2(f);
	free(mask);
	
	return 0;
}

int smb_list_dir(smb_connect_p c, const char *path) {
	char *mask, *lname;
	smb_dirinfo_t di;
	smb_find_p f;
	uint64_t total = 0;
	asprintf(&mask, "%s\\*", path);
	f = smb_find_first2(c, mask);
	if (!f) {
		free(mask);
		return -1;
	}
	while (!smb_find_next(f, &di)) {
		lname = iconv_dos_to_local(di.name);
		smb_print_file(&di, lname);
		if (!(di.attributes & FILE_ATTRIBUTE_DIRECTORY)) {
			total += di.file_size;
		}
		free(lname);
	}
	smb_log_normal("total: %s\n", human_file_size(total));
	smb_find_close2(f);
	free(mask);	
	return 0;
}

int smb_list_node(const char *addr, const char *name) {
	smb_connect_p c;
	smb_node_enum_t e;
	smb_node_t n;
	
	int dc, i;
	char **dom;
	c = smb_connect_tree(addr, name, "IPC$");
	
	if (!c) return -1;
	
	if (!smb_domain_enum(c, &e)) {		
		dc = e.count;
		i=0;
		dom = calloc(dc, sizeof(char*));
		while (!smb_node_next(c, &e, &n)) {
			smb_print_node(&n);
			dom[i++] = strdup(n.name);
		}
		
		smb_log_normal("\n");
		
		for (i = 0 ; i < dc ; i++) {			
			if (!smb_server_enum(c, &e, dom[i])) {
				smb_log_normal("%s:\n", dom[i]);
				while (!smb_node_next(c, &e, &n)) {
					smb_print_node(&n);
				}
				smb_log_normal("\n");
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

int smb_ls(smb_uri_p uri) {
	smb_connect_p c;
	smb_dirinfo_t di;
	smb_find_p f;
	
	if (uri->tree) {
		c = smb_connect_uri(uri);
		if (!c) return -1;
		if (uri->file) {
			f = smb_find_first2(c, uri->path);
			if (!f) {
				perror(uri->path);
				return -1;
			}
			while (!smb_find_next(f, &di)) {
				char *name = iconv_dos_to_local(di.name);
				if (di.attributes & FILE_ATTRIBUTE_DIRECTORY) {
					char *dir;
					smb_log_normal("%s:\n", name);
					asprintf(&dir, "%s\\%s", uri->dir, di.name);
					smb_list_dir(c, dir);
					free(dir);
					smb_log_normal("\n");
				} else {
					smb_print_file(&di, name);
				}
				free(name);
			}
			smb_find_close2(f);
		} else {
			smb_list_dir(c, "");
		}
	} else {
		smb_list_node(uri->addr, uri->name);
	}
	
	return 0;
}


char *outfile = NULL, *outdir = ".";

int smb_get(smb_uri_p uri) {
	smb_connect_p c;
	smb_dirinfo_t di;
	smb_find_p f;
	
	c = smb_connect_uri(uri);
	if (!c) return -1;
	
	if (uri->file) {
		f = smb_find_first2(c, uri->path);
		if (!f) {
			perror(uri->path);
			smb_disconnect(c);
			return -1;
		}
		while (!smb_find_next(f, &di)) {
			char *src, *dst, *name;
			name = iconv_dos_to_local(di.name);
			asprintf(&src, "%s\\%s", uri->dir, di.name);
			
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
		smb_find_close2(f);
	} else {
		if (outfile) {
			smb_download_dir(c, "", outfile);
		} else {
			char *name = iconv_dos_to_local(uri->tree);
			smb_download_dir(c, "", name);
			free(name);
		}
	}	
	smb_disconnect(c);
	return 0;
}

int main(int argc, char * const argv[]) {
	if (argc == 1) {
		usage();
		return 0;
	}
	
	iconv_init();
	
	flow = smb_flow_new();

	smb_uri_p uri;
	char *addr = NULL;
	int list = 0;
	int opt;

	NEW_STRUCT(uri);	
	
	do {
		opt = getopt(argc, argv, "-ls:o:O:d:i:h");
		switch (opt) {
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
				list = 1;
				break;
			case 'i':
				addr = strdup(optarg);
				break;
			case -1:
			case 1:
				if (uri->name) {
					if (list) {
						smb_ls(uri);
						list = 0;
					} else
						smb_get(uri);
				}
				smb_uri_free(uri);
				if (optarg) smb_uri_parse(uri, optarg);
				if (addr) {
					uri->addr = addr;
					addr = NULL;
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

