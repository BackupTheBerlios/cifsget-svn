#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "libcifs/includes.h"
#include "uri.h"
#include "flow.h"
#include "mirror.h"
#include "human.h"
#include "macros.h"

void usage() {
	fprintf(stderr, "\
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

cifs_flow_p flow;
int opt_dirsize = 0;

void cifs_print_file(cifs_dirinfo_p di) {
	printf("%6s %s%s\n", (!di->directory || opt_dirsize) ? cifs_hsize(di->file_size, NULL) : " <dir>" , di->name, di->directory ? "/":"");
}

int cifs_print_node(cifs_node_p n) {
	char *type;
	switch (n->type) {
		case CIFS_NODE_SHARE:
			type = "<shr>";
			break;
		case CIFS_NODE_SERVER:
			type = "<srv>";
			break;
		case CIFS_NODE_DOMAIN:
			type = "<dom>";
			break;	
		default:
			type = "<unk>";
			break;		
	}
	printf(" %s %s\t%s\n", type, n->name, n->comment);
	return 0;
}

int cifs_print_status(const char *fmt, ...) {
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

int cifs_get_size_dir(cifs_connect_p c, const char *path, const char *name, uint64_t *size) {
	cifs_find_p fi;
	cifs_dirinfo_t di;
	char *mask;
	
	
	if (cifs_log_level >= CIFS_LOG_NORMAL) {
		cifs_print_status("%6s %s", cifs_hsize(*size, NULL), name);
	}
	
	asprintf(&mask, "%s/*", path);
	fi = cifs_find_first(c, mask);
	if (!fi) {
		free(mask);
		return -1;
	}
	free(mask);	
	
	while (!cifs_find_next(fi, &di)) {
		if (di.directory) {
			char *pt, *nm;
			asprintf(&pt, "%s/%s", path, di.name);
			asprintf(&nm, "%s/%s", name, di.name);
			cifs_get_size_dir(c, pt, nm, size);
			free(pt);
			free(nm);
		} else {
			*size += di.file_size;
		}
	}
	
	cifs_find_close(fi);
	
	return 0;
}

int cifs_calc_size(cifs_connect_p c, const char *path, cifs_dirinfo_p di) {
	if (di->directory) {
		cifs_get_size_dir(c, path,  di->name, &di->file_size);
		if (cifs_log_level >= CIFS_LOG_NORMAL) {
			cifs_print_status("");
		}
	}
	return 0;
}

int cifs_download_file(cifs_connect_p c, cifs_dirinfo_p di, const char *src, const char *dst) {
	int fid = -1;
	int fd = -1;
	static char buf[64*1024];
	int res, len;
	off_t off, rem;

	if (!cifs_connected(c)) {
		errno = ENOTCONN;
		return -1;
	}
	
	fid = cifs_open(c, src, O_RDONLY);
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

	cifs_hsize(di->file_size, size_str);

	while (rem > 0) {
		len  = (rem < sizeof(buf))?rem:sizeof(buf);
		res = cifs_read(c, fid, buf, len, off);
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
		if (cifs_flow(flow, res) && cifs_log_level >= CIFS_LOG_NORMAL) {
			char speed_str[10];
			cifs_print_status("%6s of %6s (%.1f%%) %6s/s ETA: %s ", 
					cifs_hsize(off, NULL), 
					size_str,
					(double)off * 100.0 / di->file_size, 
					cifs_hsize(flow->speed, speed_str), 
					flow->speed > 0 ? cifs_htime(rem / flow->speed) : "???");
		}
	}
	if (cifs_log_level >= CIFS_LOG_NORMAL) {
		cifs_print_status("");
	}
	close(fd);
	cifs_close(c, fid);
	return 0;

err:
	if (fid > 0) cifs_close(c, fid);
	if (fd > 0) close(fd);
	return -1;
}

int cifs_download_dir(cifs_connect_p c, const char *src, const char *dst) {
	char *mask = NULL, *sname, *dname;
	cifs_dirinfo_t di;
	cifs_find_p fi;
	int res = -1;

	if (!cifs_connected(c)) {
		errno = ENOTCONN;
		goto err;
	}	

	if (mkdir(dst, 0755) && errno != EEXIST) {
		perror(dst);
		goto err;
	}	
	asprintf(&mask, "%s/*", src);
		
	fi = cifs_find_first(c, mask);
	
	if (!fi) {
		perror(src);
		return -1;
	}
	
	while (!cifs_find_next(fi, &di)) {
		asprintf(&sname, "%s/%s", src, di.name);
		asprintf(&dname, "%s/%s", dst, di.name);
		
		cifs_print_file(&di);
		
		if (di.directory) {
			if (cifs_download_dir(c, sname, dname)) {
				perror(sname);
				if (!cifs_connected(c)) {
					errno = ENOTCONN;
					goto err;
				}
			}			
		} else {
			if (cifs_download_file(c, &di, sname, dname)) {
				perror(sname);
				if (!cifs_connected(c)) {
					errno = ENOTCONN;
					goto err;
				}
			}
		}
		free(sname);
		free(dname);
	}
	res = 0;
err:
	cifs_find_close(fi);
	free(mask);
	return res;
}

int cifs_list_dir(cifs_connect_p c, const char *path) {
	char *mask;
	cifs_dirinfo_t di;
	cifs_find_p fi;
	uint64_t total = 0;
	asprintf(&mask, "%s/*", path);
	
	fi = cifs_find_first(c, mask);
	
	if (!fi) {
		perror(path);
		return -1;
	}
	
	while (!cifs_find_next(fi, &di)) {
		if (di.directory && opt_dirsize) {
			char *pt;
			asprintf(&pt, "%s/%s", path, di.name);
			cifs_calc_size(c, pt, &di);
			free(pt);
		}
		cifs_print_file(&di);
		total += di.file_size;
	}
	cifs_find_close(fi);
	cifs_log_normal("total: %s\n", cifs_hsize(total, NULL));
	free(mask);
	return 0;
}

int cifs_list_node(cifs_connect_p c) {
	cifs_enum_p e;
	cifs_node_t n;

	if (!c) return -1;

	if (cifs_tree_connect(c, "IPC$") < 0) {
		perror("IPC$");
		return -1;
	}
	
	e = cifs_enum_domain(c);
	if (e) {
		int count = cifs_enum_count(e);
		char **dom = calloc(count+1, sizeof(char*));
		char **p = dom;	
		
		while (!cifs_enum_next(e, &n)) {
			cifs_print_node(&n);
			*p++ = strdup(n.name);
		}
		cifs_enum_close(e);
		
		cifs_log_normal("\n");
		
		for (p = dom ; *p ; p++) {
			e = cifs_enum_server(c, *p);
			if (e) {
				cifs_log_normal("%s:\n", *p);
				while (!cifs_enum_next(e, &n)) {
					cifs_print_node(&n);
				}
				cifs_log_normal("\n");
				cifs_enum_close(e);
			}
			free(*p);
		}
		free(dom);
	}
		
	if ((e = cifs_enum_share(c))) {
		while (!cifs_enum_next(e, &n)) {
			cifs_print_node(&n);
		}
		cifs_enum_close(e);
	}
	
	cifs_tree_disconnect(c, 0);
	return 0;
}

int cifs_list(cifs_connect_p c, const char *path, cifs_dirinfo_p di) {	
	if (path) {
		if (di->directory) {
			cifs_log_normal("%s:\n", di->name);
			cifs_list_dir(c, path);
			cifs_log_normal("\n");
		} else {
			cifs_print_file(di);
		}
	} else {
		cifs_list_node(c);
	}
	return 0;
}

char *outfile = NULL, *outdir = ".";

int cifs_download(cifs_connect_p c, const char *path, cifs_dirinfo_p di) {
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
	
	cifs_print_file(di);
	
	if (di->directory) {
		cifs_download_dir(c, path, dst);
	} else {
		cifs_download_file(c, di, path, dst);
	}		

	free(dst);
	free(outfile);
	outfile = NULL;
	return 0;
}

int cifs_action(int action, cifs_uri_p uri) {
	cifs_connect_p c;
	cifs_find_p fi;
	cifs_dirinfo_t di;
	if (uri->tree) {
		c = cifs_connect_tree(uri->addr, uri->port, uri->name, uri->tree);
		if (!c) {
			perror(uri->tree);
			return -1;
		}
		if (uri->path && uri->path[0]) {
			if (!c) return -1;
			fi = cifs_find_first(c, uri->path);
			if (!fi) {
				perror(uri->path);
				cifs_connect_close(c);
				return -1;
			}
			while (!cifs_find_next(fi, &di)) {
				char *path;
				asprintf(&path, "%s/%s", uri->dir, di.name);
				switch (action) {
					case 'd':
						cifs_download(c, path, &di);
						break;
					case 'l':
						cifs_list(c, path, &di);
						break;
				}
			}
			cifs_find_close(fi);
		} else {
			memset(&di, 0, sizeof(di));
			di.directory = 1;
			strncpy(di.name, uri->tree, sizeof(di.name));
			switch (action) {
				case 'd':
					cifs_download(c, "", &di);
					break;
				case 'l':
					cifs_list(c, "", &di);
					break;
			}
		}
	} else {
		c = cifs_connect(uri->addr, uri->port, uri->name);
		if (!c) {
			perror(uri->name);
			return -1;
		}
		switch (action) {
			case 'l':
				cifs_list(c, NULL, NULL);
				break;
		}
	}
	
	cifs_connect_close(c);
	
	return 0;
}

int main(int argc, char** argv) {
	int opt;
	cifs_uri_p uri;
	int action = 'd';
	
	if (argc == 1) {
		usage();
		return 0;
	}
	flow = cifs_flow_new();	

	NEW_STRUCT(uri);

	cifs_log_stream = stderr;
	
	do {
		opt = getopt(argc, argv, "-ls:o:O:d:i:p:hS");
		switch (opt) {
			case 'd':
				cifs_log_level = atoi(optarg);
				break;
			case 's':			
				flow->limit = cifs_decode_hsize(optarg);
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
					cifs_action(action, uri);
					cifs_uri_free(uri);
				}				
				if (optarg) {
					cifs_uri_parse(uri, optarg);
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

