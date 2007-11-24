#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "libcifs/cifs.h"
#include "uri.h"
#include "flow.h"
#include "human.h"

void usage() {
	fprintf(stderr, "\
usage: \n\
  cifscp -l FILE...\n\
  cifscp [OPTION]... SOURCE DEST\n\
  cifscp [OPTION]... SOURCE... DIRECTORY\n\
  \n\
  URI:    (smb|cifs)://[user[:password]@]host[:[addr:]port]/share/path\n\
  UNC:    \\\\host\\share\\path\n\
  \n\
  OPTION:\n\
  -l                    list directory contents\n\
  -u                    calculate directory size\n\
  -s <int>[k|m|g|t]     limit download speed\n\
  -h                    show this message and exit\n\
  -d [0-6]              debug level, default - 3\n\
");
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

cifs_flow_p flow;
int opt_dirsize = 0;

/* LIST */

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

int cifs_list_uri(cifs_uri_p uri) {
	cifs_connect_p c;
	cifs_dir_p dir;
	cifs_dirent_p de;
	if (uri->tree) {
		c = cifs_connect(uri->addr, uri->port, uri->host, uri->tree);
		if (!c) {
			perror(uri->tree);
			return -1;
		}
		if (uri->path[0]) {
			if (!c) return -1;
			dir = cifs_mask(c, uri->dir, uri->file);
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
		c = cifs_connect(uri->addr, uri->port, uri->host, NULL);
		if (!c) {
			perror(uri->host);
			return -1;
		}
		cifs_list(c, NULL);
	}
	cifs_connect_close(c);	
	return 0;
}

/* DOWNLOAD */

int cifs_download_file(cifs_connect_p c, const char *src, const char *dst) {
	int fid = -1;
	int fd = -1;
	static char buf[64*1024];
	int res, len;
	off_t off, rem;
    cifs_stat_t st;
	
	fid = cifs_open(c, src, O_RDONLY, &st);
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

	rem = st.file_size - off;

	char size_str[10];

	cifs_hsize(st.file_size, size_str);

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
					(double)off * 100.0 / st.file_size, 
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
	char *dname;
	cifs_dir_p dir;
	cifs_dirent_p ent;
    dir = cifs_opendir(c, src);

	if (dir == NULL) {
		perror(src);
		return -1;
	}

	if (mkdir(dst, 0755) && errno != EEXIST) {
		perror(dst);
    	cifs_closedir(dir);
	    return -1;
	}
	
	while ((ent = cifs_readdir(dir)) != NULL) {
		asprintf(&dname, "%s/%s", dst, ent->name);
		
		cifs_print_file(ent);
		
		if (ent->st.is_directory) {
			if (cifs_download_dir(c, ent->path, dname)) {
				perror(ent->path);
			}
		} else {
			if (cifs_download_file(c, ent->path, dname)) {
				perror(ent->path);
			}
		}
		free(dname);
	}
	cifs_closedir(dir);
    return 0;
}

/* UPLOAD */

int cifs_upload_file(cifs_connect_p c, const char *src, const char *dst) {
	int fid = -1;
	int fd = -1;
    char *buf;
	int res, len;
	off_t off, rem, size;
    cifs_stat_t st;
        
	fid = cifs_open(c, dst, O_WRONLY | O_CREAT, &st);
	if (fid < 0) {
		perror(dst);
		goto err;
	}
	
	fd = open(src, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		perror(src);
		goto err;
	}
	
	size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
	if (size == (off_t)-1) {
		perror(src);
		goto err;
	}

    off = st.file_size;

    rem = size - off;

	char size_str[10];

	cifs_hsize(size, size_str);

    buf = malloc(64*1024);

	while (rem > 0) {
		len = rem;
        if (len > 1024) {
            len = 1024;
        }
        len = pread(fd, buf, len, off);
   		if (len < 0) {
			perror(src);
			goto err;
		}
        res = cifs_write(c, fid, buf, len, off);
        if (res < 0) {
    		perror(dst);
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

int cifs_upload_dir(cifs_connect_p c, const char *src, const char *dst) {
    DIR *dir;
    struct dirent *ent;
    char *sname, *dname;
    
    dir = opendir(src);

    if (dir == NULL) {
		perror(src);
		return -1;
	}

	if (cifs_mkdir(c, dst) && errno != EEXIST) {
		perror(dst);
    	closedir(dir);
	    return -1;
	}
	while ((ent = readdir(dir)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
		asprintf(&sname, "%s/%s", src, ent->d_name);
        asprintf(&dname, "%s/%s", dst, ent->d_name);
        struct stat st;
        if (stat(sname, &st)) {
            perror(sname);
            continue;
        }
    	if (S_ISDIR(st.st_mode)) {
            cifs_upload_dir(c, sname, dname);
        }
        if (S_ISREG(st.st_mode)) {
            cifs_upload_file(c, sname, dname);
		}
		free(sname);
		free(dname);
	}
	closedir(dir);
    return 0;
}

int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st)) return 0;
    return S_ISDIR(st.st_mode);
}


int main(int argc, char** argv) {
	int opt, args;
    int list = 0;
    cifs_uri_p suri, duri;
    char *dst, *src;
    int dst_dir = 0;
    cifs_dir_p dir;
    cifs_dirent_p ent;
    cifs_connect_p c;
 
	if (argc == 1) {
		usage();
		return 0;
	}

    if (!strcmp(argv[0], "cifsls")) {
        list = 1;
    }
    
	flow = cifs_flow_new();

	cifs_log_stream = stderr;

    while ((opt = getopt(argc, argv, "hlus:d:")) != -1) {
		switch (opt) {
			case 'd':
				cifs_log_level = atoi(optarg);
				break;
			case 's':			
				flow->limit = cifs_decode_hsize(optarg);
				break;
			case 'l':
                list = 1;
				break;
			case 'u':
				opt_dirsize = 1;
				break;
			case '?':
			case 'h':
				usage();
				return 0;
		}
    }
    args = argc - optind;
   
    if (list) {
        if (args <= 0) {
            usage();
            return 2;
        }
        for (int i = optind ; i < argc ; i++) {
             suri = cifs_uri_parse(argv[i]);
             if (suri->scheme == URI_CIFS) {
                 cifs_list_uri(suri);
             }
        }
        return 0;
    }
    
    if (args < 2) {
        usage();
        return 2;
    }

    dst = argv[argc-1];    
    duri = cifs_uri_parse(dst);
    if (duri == NULL) {
        perror(dst);
        return 2;
    }

    if (duri->scheme == URI_FILE) {
        /* DOWNLOAD */
        dst_dir = is_directory(dst);
        if (args > 2 && !dst_dir) {
            errno = ENOTDIR;
            perror(dst);
            return 2;
        }
        for (int i = optind ; i < argc-1; i++) {
            src = argv[i];
            suri = cifs_uri_parse(src);
            c = cifs_connect(suri->addr, suri->port, suri->host, suri->tree);
            if (!c) {
                perror(src);
                continue;
            }
            dir = cifs_mask(c, suri->dir, suri->file);
			if (!dir) {
				perror(src);
				continue;
			}
			while ((ent = cifs_readdir(dir))) {
                char *dname;
                if (dst_dir) {
                    asprintf(&dname, "%s/%s", dst, ent->name);
                } else {
                    dname = dst;
                }
                if (ent->st.is_directory) {
                    cifs_download_dir(c, ent->path, dname);
                } else {
                    cifs_download_file(c, ent->path, dname);
                }
                if (dst_dir) free(dname);
            }
            cifs_uri_free(suri);
            cifs_connect_close(c);
        }
    } else if (duri->scheme == URI_CIFS) {
        /* UPLOAD */
        c = cifs_connect(duri->addr, duri->port, duri->host, duri->tree);
        if (!c) {
            perror(dst);
            return -1;
        }
        if (duri->path[0]) {
            cifs_stat_t st;
            if (cifs_stat(c, duri->path, &st)) {
                dst_dir = 0;
            } else {
                dst_dir = st.is_directory;
            }
        } else {
            dst_dir = 1;
        }
        if (args > 2 && !dst_dir) {
            errno = ENOTDIR;
            perror(dst);
            return 2;
        }
        for (int i = optind ; i < argc-1; i++) {
            src = argv[i];
            suri = cifs_uri_parse(src);
            char *dname;
            if (dst_dir) {
                asprintf(&dname, "%s/%s", duri->path, suri->file);
            } else {
                dname = duri->path;
            }
            if (is_directory(src)) {
                cifs_upload_dir(c, src, dname);
            } else {
                cifs_upload_file(c, src, dname);
            }
            if (dst_dir) free(dname);
            cifs_uri_free(suri);
        }
    }
    return 0;
}

