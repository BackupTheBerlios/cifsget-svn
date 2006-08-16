#include "includes.h"

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#include <locale.h>

//names in local code page

typedef struct fusecifs_share_s {
	char *name;
	int tid;
	struct fusecifs_share_s *next;
} fusecifs_share_t;
typedef fusecifs_share_t *fusecifs_share_p;

typedef struct fusecifs_host_s {
	char *name;
	cifs_connect_p conn;
	fusecifs_share_p share_list;
	struct fusecifs_host_s *next;
} fusecifs_host_t;
typedef fusecifs_host_t *fusecifs_host_p;

typedef struct fusecifs_path_s {
	char host[PATH_MAX];
	char share[PATH_MAX];
	char path[PATH_MAX];
} fusecifs_path_t;
typedef fusecifs_path_t *fusecifs_path_p;

/*typedef struct fusecifs_file_s {
	cifs_connect_p conn;
	int tid;
	int fid;
	char buf[SMB_MAX_RAW];
	off_t buf_off;
	int buf_len;
} fusecifs_file_t;
typedef fusecifs_file_t *fusecifs_file_p;*/

static int fusecifs_parse_path(const char *path, fusecifs_path_p res) {
	char *p, *o;
	p = iconv_local_to_dos_buf(path, res->path, sizeof(res->path));
	if (!p) return -1;
	while(*p && *p == '/') p++;
	o = res->host;
	while(*p && *p != '/') *o++ = tolower(*p++);
	*o='\0';
	while(*p && *p == '/') p++;
	o = res->share;
	while(*p && *p != '/') *o++ = tolower(*p++);
	*o='\0';
	o = res->path;
	while(*p && *p == '/') p++;
	while(*p) {
		*o++ = '\\';
		while(*p && *p != '/') *o++ = *p++;
		while(*p && *p == '/') p++;
	}
	*o='\0';
	return 0;
}

static void strtolower(char *s) {
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

static fusecifs_host_p fusecifs_host_list = NULL;

static fusecifs_host_p fusecifs_host_find(const char *host_name) {
	fusecifs_host_p host;
	for (host = fusecifs_host_list ; host && strcmp(host_name, host->name) ; host = host->next);
	return host;
}

static fusecifs_share_p fusecifs_share_find(fusecifs_host_p host, const char *share_name) {
	fusecifs_share_p share;
	for ( share = host->share_list ; share && strcmp(share->name, share_name) ; share = share->next);
	return share;
}


static fusecifs_host_p fusecifs_connect_host(const char *host_name) {
	fusecifs_host_p host;
	cifs_connect_p conn;
	
	host = fusecifs_host_find(host_name);
	
	if (!host || !host->conn) {
		conn = cifs_connect2(host_name);
		if (!conn) return NULL;
		if (!host) {
			NEW_STRUCT(host);
			host->name = strdup(host_name);
			host->next = fusecifs_host_list;
			fusecifs_host_list = host;
		}
		host->conn = conn;
	}
	return host;
}

static fusecifs_share_p fusecifs_connect_share(fusecifs_host_p host, const char *share_name) {
	fusecifs_share_p share;
	cifs_connect_p conn;
	int tid;
	char *dos_share_name;

	conn = host->conn;

	share = fusecifs_share_find(host, share_name);
	
	if (share && share->tid >= 0) {
		cifs_tree_switch(conn, share->tid);
		return share;
	}

	dos_share_name = iconv_local_to_dos(share_name);
	tid = cifs_tree_connect(conn, host->name, dos_share_name);
	free(dos_share_name);
	if (tid < 0) return NULL;
	
	if (!share) {
		NEW_STRUCT(share);
		share->name = strdup(share_name);
		share->next = host->share_list;
		host->share_list = share;
	}
	share->tid = tid;
	
	return share;
}

static cifs_connect_p fusecifs_connect(const char *host_name, const char *share_name) {
	fusecifs_host_p host;
	fusecifs_share_p share;	
	
	host = fusecifs_connect_host(host_name);	
	if (!host) return NULL;	
	
	share = fusecifs_connect_share(host, share_name);
	if (!share) return NULL;
	return host->conn;
}

static int fusecifs_list_share(const char *host_name) {
	cifs_node_enum_t e;
	fusecifs_host_p host;
	fusecifs_share_p share;
	cifs_connect_p conn;
	cifs_node_t n;
	char *share_name;
	
	host = fusecifs_connect_host(host_name);
	if (!host) return -1;
	
	if (!fusecifs_connect_share(host, "IPC$")) return -1;
	
	conn = host->conn;	
	
	if (!cifs_share_enum(conn, &e)) {
		while (!cifs_node_next(conn, &e, &n)) {
			share_name = iconv_dos_to_local(n.name);
			strtolower(share_name);
			share = fusecifs_share_find(host, share_name);
			if (!share) {
				NEW_STRUCT(share);
				share->name = share_name;
				share->tid = -1;
				share->next = host->share_list;
				host->share_list = share;
			} else  {
				free(share_name);
			}			
		}
	} else {
		return -1;
	}
	return 0;
}

static int fusecifs_list_host(const char *server, const char *workgroup) {
	cifs_connect_p conn;
	cifs_node_enum_t e;
	cifs_node_t n;
	char *host_name;
	fusecifs_host_p host;
	conn = fusecifs_connect(server, "IPC$");
	if (!cifs_server_enum(conn, &e, workgroup)) {
		while (!cifs_node_next(conn, &e, &n)) {
			host_name = iconv_dos_to_local(n.name);
			strtolower(host_name);
			host = fusecifs_host_find(host_name);
			if (!host) {
				NEW_STRUCT(host);
				host->name = host_name;
				host->next = fusecifs_host_list;
				fusecifs_host_list =  host;
			}
		}
	}
	return 0;
}

static int fusecifs_make_stat (struct stat *st, cifs_dirinfo_p di) {
	st->st_dev = 0;
	st->st_ino = 0;
	
	if (di->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		st->st_mode = S_IFDIR | 0775;
	} else {
		st->st_mode = S_IFREG | 0664;
	}
	st->st_nlink = 1;
	st->st_uid = 0;
	st->st_gid = 0;
	st->st_rdev = 0;
	st->st_size = di->file_size;
	st->st_blksize = SMB_MAX_RAW;
	st->st_blocks = (di->file_size+SMB_MAX_RAW-1) / SMB_MAX_RAW;
	st->st_atime = cifs_nttime2unix(di->access_time);
	st->st_mtime = cifs_nttime2unix(di->write_time);
	st->st_ctime = cifs_nttime2unix(di->change_time);
	return 0;
}

static int fusecifs_getattr (const char *path, struct stat *st) {
	cifs_connect_p conn;
	fusecifs_path_t p;
	cifs_dirinfo_t di;
	fusecifs_parse_path(path, &p);
	if (!p.host[0] || !p.host[0] || !p.path[0])  {
		ZERO_STRUCTP(st);
		st->st_mode = S_IFDIR | 0775;
		return 0;
	}
	conn = fusecifs_connect(p.host, p.share);
	if (!conn) goto err;
	if (cifs_info(conn, p.path, &di)) goto err;
	fusecifs_make_stat(st, &di);
	return 0;
err:
	return -EIO;
}

static int fusecifs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi) {
	cifs_find_t fr;
	cifs_connect_p conn;
	fusecifs_path_t p;
	cifs_dirinfo_t di;
	fusecifs_host_p host;
	fusecifs_share_p share;
	struct stat st;
	char name[PATH_MAX];
	fusecifs_parse_path(path, &p);
	if (!p.host[0]) {
		ZERO_STRUCT(st);
		st.st_mode = S_IFDIR | 0775;
		for (host = fusecifs_host_list ; host ; host = host->next) {
			if (filler(buf, host->name, &st, 0)) return -EIO;
		}		
		return 0;
	}	
	if (!p.share[0]) {
		ZERO_STRUCT(st);
		st.st_mode = S_IFDIR | 0775;
		if (fusecifs_list_share(p.host)) return -ENOENT;
		host = fusecifs_host_find(p.host);
		if (!host) return -ENOENT;
		for (share = host->share_list ; share ; share = share->next) {
			if (filler(buf, share->name, &st, 0)) return -EIO;
		}
		return 0;
	}
	conn = fusecifs_connect(p.host, p.share);
	if (!conn) return -ENOENT;
	strcat(p.path, "\\*");
	if (cifs_find_first(conn, p.path, &fr)) return -ENOENT;
	while (!cifs_find_next(&fr, &di)) {
		fusecifs_make_stat(&st, &di);		
		if (!iconv_dos_to_local_buf(di.name, name, sizeof(name))) continue;
		if (filler(buf, name, &st, 0)) return -EIO;
	}
	if (cifs_find_close(&fr)) return -EIO;
	return 0;
}

static int fusecifs_open(const char *path, struct fuse_file_info *fi) {
	int fid;
	//fusecifs_file_p file;
	fusecifs_host_p host;
	fusecifs_share_p share;
	cifs_connect_p conn;
	fusecifs_path_t p;
	fusecifs_parse_path(path, &p);
	if (!p.host[0] || !p.share[0] || !p.path[0]) return -ENOENT;
	host = fusecifs_connect_host(p.host);
	if (!host) return -ECONNREFUSED;
	share = fusecifs_connect_share(host, p.share);
	if (!share) return -ENOENT;
	conn = host->conn;	
	fid = cifs_open(conn, p.path, OPEN_FLAGS_OPEN_READ);
	if (fid < 0 ) return -EIO;
	
	/*NEW_STRUCT(file);
	file->conn = conn;
	file->tid = share->tid;	
	file->fid = fid;	
	fi->fh = (uint64_t)file;*/
	
	fi->fh = fid;
	
	return 0;
}

static int fusecifs_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
	/*off_t res, off;
	fusecifs_file_p file = (fusecifs_file_p)fi->fh;

	res = file->buf_off + file->buf_len - offset;
	off = offset - file->buf_off;
	
	if (off < 0 || res <= 0) {
		cifs_tree_switch(file->conn, file->tid);
		res = cifs_read(file->conn, file->fid, file->buf, sizeof(file->buf), offset);
		if (res < 0) return -EIO;
		
		file->buf_len = res;
		file->buf_off = offset;
		off = 0;
	}
	
	if (res > size) res = size;
	memcpy(buf, file->buf + off, res);
		
	return res; */	

	int res;

	res = 
}

static int fusecifs_release(const char *path, struct fuse_file_info *fi) {
	fusecifs_file_p file = (fusecifs_file_p)fi->fh;
	cifs_tree_switch(file->conn, file->tid);
	cifs_close(file->conn, file->fid);
	FREE_STRUCT(file);
	fi->fh = 0;
	return 0;
}

static struct fuse_operations fusecifs_oper = {
	.getattr = fusecifs_getattr,
	.readdir = fusecifs_readdir,
	.open	 = fusecifs_open,
	.release = fusecifs_release,
	.read	 = fusecifs_read,
};

int main(int argc, char *argv[]) {
	setlocale(LC_ALL,"");
	iconv_init();
	fusecifs_list_host("server", "HACKERS");
    	return fuse_main(argc, argv, &fusecifs_oper);
}

