#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "libcifs/cifs.h"
#include "uri.h"
#include "flow.h"
#include "mirror.h"
#include "human.h"

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
  -P file               PUT\n\
");
}

cifs_flow_p flow;
int opt_dirsize = 0;

void cifs_print_file(cifs_dirent_p st) {
	printf("%6s %s%s\n", (!st->st.is_directory || opt_dirsize) ? cifs_hsize(st->st.file_size, NULL) : " <dir>" , st->name, st->st.is_directory ? "/":"");
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
	cifs_dir_p d;
	cifs_dirent_p e;
	
	if (cifs_log_level >= CIFS_LOG_NORMAL) {
		cifs_print_status("%6s %s", cifs_hsize(*size, NULL), name);
	}

	d = cifs_opendir(c, path);
	if (!d) return -1;
	
	while ((e = cifs_readdir(d))) {
		if (e->st.is_directory) {
			char *nm;
			asprintf(&nm, "%s/%s", name, e->name);
			cifs_get_size_dir(c, e->path, nm, size);
			free(nm);
		} else {
			*size += e->st.file_size;
		}
	}
	
	cifs_closedir(d);
	
	return 0;
}

int cifs_calc_size(cifs_connect_p c, cifs_dirent_p e) {
	if (e->st.is_directory) {
		cifs_get_size_dir(c, e->path,  e->name, &e->st.file_size);
		if (cifs_log_level >= CIFS_LOG_NORMAL) {
			cifs_print_status("");
		}
	}
	return 0;
}

int cifs_download_file(cifs_connect_p c, cifs_dirent_p e, const char *dst) {
	int fid = -1;
	int fd = -1;
	static char buf[64*1024];
	int res, len;
	off_t off, rem;

	if (!cifs_connected(c)) {
		errno = ENOTCONN;
		return -1;
	}
	
	fid = cifs_open(c, e->path, O_RDONLY);
	if (fid < 0) {
		perror(e->path);
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

	rem = e->st.file_size - off;

	char size_str[10];

	cifs_hsize(e->st.file_size, size_str);

	while (rem > 0) {
		len  = (rem < sizeof(buf))?rem:sizeof(buf);
		res = cifs_read(c, fid, buf, len, off);
		if (res < 0) {
			perror(e->path);
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
					(double)off * 100.0 / e->st.file_size, 
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

int cifs_download_dir(cifs_connect_p c, cifs_dirent_p src, const char *dst) {
	char *dname;
	cifs_dir_p d;	
	cifs_dirent_p e;
	int res = -1;

	if (!cifs_connected(c)) {
		errno = ENOTCONN;
		goto err;
	}	

	if (mkdir(dst, 0755) && errno != EEXIST) {
		perror(dst);
		goto err;
	}
	
	d = cifs_opendir(c, src->path);
	
	if (!d) {
		perror(src->path);
		return -1;
	}
	
	while ((e = cifs_readdir(d))) {
		asprintf(&dname, "%s/%s", dst, e->name);
		
		cifs_print_file(e);
		
		if (e->st.is_directory) {
			if (cifs_download_dir(c, e, dname)) {
				perror(e->path);
				if (!cifs_connected(c)) {
					errno = ENOTCONN;
					goto err;
				}
			}			
		} else {
			if (cifs_download_file(c, e, dname)) {
				perror(e->path);
				if (!cifs_connected(c)) {
					errno = ENOTCONN;
					goto err;
				}
			}
		}
		free(dname);
	}
	res = 0;
err:
	cifs_closedir(d);
	return res;
}

int cifs_list_dir(cifs_connect_p c, const char *path) {
	cifs_dirent_p e;
	cifs_dir_p d;
	uint64_t total = 0;

	d = cifs_opendir(c, path);
	
	if (!d) {
		perror(path);
		return -1;
	}
	
	while ((e = cifs_readdir(d))) {
		if (e->st.is_directory && opt_dirsize) {
			cifs_calc_size(c, e);
		}
		cifs_print_file(e);
		total += e->st.file_size;
	}
	cifs_closedir(d);
	printf("total: %s\n", cifs_hsize(total, NULL));
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
		
		printf("\n");
		
		for (p = dom ; *p ; p++) {
			e = cifs_enum_server(c, *p);
			if (e) {
				printf("%s:\n", *p);
				while (!cifs_enum_next(e, &n)) {
					cifs_print_node(&n);
				}
				printf("\n");
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

int cifs_list(cifs_connect_p c, cifs_dirent_p di) {	
	if (di) {
		if (di->st.is_directory) {
		    printf("%s:\n", di->name);
			cifs_list_dir(c, di->path);
			printf("\n");
		} else {
			cifs_print_file(di);
		}
	} else {
		cifs_list_node(c);
	}
	return 0;
}

char *outfile = NULL, *outdir = ".";

int cifs_download(cifs_connect_p c, cifs_dirent_p de) {
	char *dst;
			
	if (!outfile) {
		asprintf(&dst, "%s/%s", outdir, de->name);
	} else {
		if (outfile[0] == '/') {
			dst = strdup(outfile);
		} else {
			asprintf(&dst, "%s/%s", outdir, outfile);
		}
	}
	
	cifs_print_file(de);
	
	if (de->st.is_directory) {
		cifs_download_dir(c, de, dst);
	} else {
		cifs_download_file(c, de, dst);
	}		

	free(dst);
	free(outfile);
	outfile = NULL;
	return 0;
}

int cifs_list_uri(cifs_uri_p uri) {
	cifs_connect_p c;
	cifs_dir_p dir;
	cifs_dirent_p de;
	if (uri->tree) {
		c = cifs_connect_tree(uri->addr, uri->port, uri->name, uri->tree);
		if (!c) {
			perror(uri->tree);
			return -1;
		}
		if (uri->path && uri->path[0]) {
			if (!c) return -1;
			dir = cifs_find(c, uri->dir, uri->file);
			if (!dir) {
				perror(uri->path);
				cifs_connect_close(c);
				return -1;
			}
			while ((de = cifs_readdir(dir))) {
				cifs_list(c, de);				
			}
			cifs_closedir(dir);
		} else {
			cifs_dirent_t d;
			ZERO_STRUCT(d);
			d.st.is_directory = 1;
			d.name = uri->tree;
			d.path = "";
			cifs_list(c, &d);
		}
	} else {
		c = cifs_connect(uri->addr, uri->port, uri->name);
		if (!c) {
			perror(uri->name);
			return -1;
		}
		cifs_list(c, NULL);
	}	
	cifs_connect_close(c);	
	return 0;
}

char *putname = NULL;


int cifs_upload_file(cifs_connect_p c, const char *src, cifs_dirent_p dst) {
	int fid = -1;
	int fd = -1;
	static char buf[64*1024];
	int res, len;
	off_t off, rem, size;

	if (!cifs_connected(c)) {
		errno = ENOTCONN;
		return -1;
	}
	
	fid = cifs_open(c, dst->path, O_WRONLY);
	if (fid < 0) {
		perror(dst->path);
		goto err;
	}
	
	fd = open(src, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		perror(src);
		goto err;
	}
	
	size = lseek(fd, 0, SEEK_END);   
	if (size == (off_t)-1) {
		perror(src);
		goto err;
	}

	rem = size - dst->st.file_size;

	char size_str[10];

    off = dst->st.file_size;

	cifs_hsize(off, size_str);

	while (rem > 0) {
		len = rem;
        if (len > sizeof(buf)) {
            len = sizeof(buf);
        }
        len = read(fd, buf, len);
   		if (len < 0) {
			perror(src);
			goto err;
		}
        res = cifs_write(c, fid, buf, len, off);
        if (res < 0) {
    		perror(dst->path);
	    	goto err;
        }
		if (res > 0) {
			off += res;
			rem -= res;
		}
		if (cifs_flow(flow, res) && cifs_log_level >= CIFS_LOG_NORMAL) {
			char speed_str[10];
			cifs_print_status("%6s of %6s (%.1f%%) %6s/s ETA: %s ", 
					cifs_hsize(off, NULL), 
					size_str,
					(double)off * 100.0 / size,
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


int cifs_upload(cifs_connect_p c, cifs_dirent_p de) {
    asprintf(&de->path, "%s/%s", de->path, putname);
    cifs_upload_file(c, putname, de);
    free(putname);
	putname = NULL;
	return 0;
}

int cifs_action(int action, cifs_uri_p uri) {
	cifs_connect_p c;
	cifs_dir_p dir;
	cifs_dirent_p de;
	if (uri->tree) {
		c = cifs_connect_tree(uri->addr, uri->port, uri->name, uri->tree);
		if (!c) {
			perror(uri->tree);
			return -1;
		}
		if (uri->path && uri->path[0]) {
			if (!c) return -1;
			dir = cifs_find(c, uri->dir, uri->file);
			if (!dir) {
				perror(uri->path);
				cifs_connect_close(c);
				return -1;
			}
			while ((de = cifs_readdir(dir))) {
				switch (action) {
					case 'd':
						cifs_download(c, de);
						break;
					case 'l':
						cifs_list(c, de);
						break;
                    case 'p':
                        cifs_upload(c, de);
                        break;
				}
			}
			cifs_closedir(dir);
		} else {
			cifs_dirent_t d;
			ZERO_STRUCT(d);
			d.st.is_directory = 1;
			d.name = uri->tree;
			d.path = "";
			switch (action) {
				case 'd':
					cifs_download(c, &d);
					break;
				case 'l':
					cifs_list(c, &d);
					break;
                case 'p':
                    cifs_upload(c, &d);
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
				cifs_list(c, NULL);
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
		opt = getopt(argc, argv, "-ls:o:O:d:i:p:P:hS");
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
            case 'P':
                action = 'p';
                putname = strdup(optarg);
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

