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

typedef struct fusesmb_share_s {
	char *name;
	int tid;
	struct fusesmb_share_s *next;
} fusesmb_share_t;
typedef fusesmb_share_t *fusesmb_share_p;

typedef struct fusesmb_host_s {
	char *name;
	smb_connect_p conn;
	fusesmb_share_p share_list;
	struct fusesmb_host_s *next;
} fusesmb_host_t;
typedef fusesmb_host_t *fusesmb_host_p;

typedef struct fusesmb_path_s {
	char host[PATH_MAX];
	char share[PATH_MAX];
	char path[PATH_MAX];
} fusesmb_path_t;
typedef fusesmb_path_t *fusesmb_path_p;

typedef struct fusesmb_file_s {
	smb_connect_p conn;
	int tid;
	int fid;
	char buf[SMB_MAX_RAW];
	off_t buf_off;
	int buf_len;
} fusesmb_file_t;
typedef fusesmb_file_t *fusesmb_file_p;

int fusesmb_parse_path(const char *path, fusesmb_path_p res) {
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

void strtolower(char *s) {
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

fusesmb_host_p fusesmb_host_list = NULL;

fusesmb_host_p fusesmb_host_find(const char *host_name) {
	fusesmb_host_p host;
	for (host = fusesmb_host_list ; host && strcmp(host_name, host->name) ; host = host->next);
	return host;
}

fusesmb_share_p fusesmb_share_find(fusesmb_host_p host, const char *share_name) {
	fusesmb_share_p share;
	for ( share = host->share_list ; share && strcmp(share->name, share_name) ; share = share->next);
	return share;
}


fusesmb_host_p fusesmb_connect_host(const char *host_name) {
	fusesmb_host_p host;
	smb_connect_p conn;
	
	host = fusesmb_host_find(host_name);
	
	if (!host || !host->conn) {
		NEW_STRUCT(conn);
		if (smb_connect2(conn, host_name)) {
			FREE_STRUCT(conn);
			return NULL;
		}
		if (!host) {
			NEW_STRUCT(host);
			host->name = strdup(host_name);
			host->next = fusesmb_host_list;
			fusesmb_host_list = host;
		}
		host->conn = conn;
	}
	return host;
}

fusesmb_share_p fusesmb_connect_share(fusesmb_host_p host, const char *share_name) {
	fusesmb_share_p share;
	smb_connect_p conn;
	int tid;
	char *dos_share_name;

	conn = host->conn;

	share = fusesmb_share_find(host, share_name);
	
	if (share && share->tid >= 0) {
		smb_treeswitch(conn, share->tid);
		return share;
	}

	dos_share_name = iconv_local_to_dos(share_name);
	tid = smb_treeconnect(conn, host->name, dos_share_name);
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

smb_connect_p fusesmb_connect(const char *host_name, const char *share_name) {
	fusesmb_host_p host;
	fusesmb_share_p share;	
	
	host = fusesmb_connect_host(host_name);	
	if (!host) return NULL;	
	
	share = fusesmb_connect_share(host, share_name);
	if (!share) return NULL;
	return host->conn;
}

int fusesmb_list_share(const char *host_name) {
	smb_node_enum_t e;
	fusesmb_host_p host;
	fusesmb_share_p share;
	smb_connect_p conn;
	smb_node_t n;
	char *share_name;
	
	host = fusesmb_connect_host(host_name);
	if (!host) return -1;
	
	if (!fusesmb_connect_share(host, "IPC$")) return -1;
	
	conn = host->conn;	
	
	if (!smb_share_enum(conn, &e)) {
		while (!smb_node_next(conn, &e, &n)) {
			share_name = iconv_dos_to_local(n.name);
			strtolower(share_name);
			share = fusesmb_share_find(host, share_name);
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

int fusesmb_list_host(const char *server, const char *workgroup) {
	smb_connect_p conn;
	smb_node_enum_t e;
	smb_node_t n;
	char *host_name;
	fusesmb_host_p host;
	conn = fusesmb_connect(server, "IPC$");
	if (!smb_server_enum(conn, &e, workgroup)) {
		while (!smb_node_next(conn, &e, &n)) {
			host_name = iconv_dos_to_local(n.name);
			strtolower(host_name);
			host = fusesmb_host_find(host_name);
			if (!host) {
				NEW_STRUCT(host);
				host->name = host_name;
				host->next = fusesmb_host_list;
				fusesmb_host_list =  host;
			}
		}
	}
	return 0;
}

int fusesmb_make_stat (struct stat *st, smb_dirinfo_p di) {
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
	st->st_atime = smb_nttime2unix(di->access_time);
	st->st_mtime = smb_nttime2unix(di->write_time);
	st->st_ctime = smb_nttime2unix(di->change_time);
	return 0;
}

int fusesmb_getattr (const char *path, struct stat *st) {
	smb_connect_p conn;
	fusesmb_path_t p;
	smb_dirinfo_t di;
	fusesmb_parse_path(path, &p);
	if (!p.host[0] || !p.host[0] || !p.path[0])  {
		ZERO_STRUCTP(st);
		st->st_mode = S_IFDIR | 0775;
		return 0;
	}
	conn = fusesmb_connect(p.host, p.share);
	if (!conn) goto err;
	if (smb_info(conn, p.path, &di)) goto err;
	fusesmb_make_stat(st, &di);
	return 0;
err:
	return -EIO;
}

static int fusesmb_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi) {
	smb_find_t fr;
	smb_connect_p conn;
	fusesmb_path_t p;
	smb_dirinfo_t di;
	fusesmb_host_p host;
	fusesmb_share_p share;
	struct stat st;
	char name[PATH_MAX];
	fusesmb_parse_path(path, &p);
	if (!p.host[0]) {
		ZERO_STRUCT(st);
		st.st_mode = S_IFDIR | 0775;
		for (host = fusesmb_host_list ; host ; host = host->next) {
			if (filler(buf, host->name, &st, 0)) return -EIO;
		}		
		return 0;
	}	
	if (!p.share[0]) {
		ZERO_STRUCT(st);
		st.st_mode = S_IFDIR | 0775;
		if (fusesmb_list_share(p.host)) return -ENOENT;
		host = fusesmb_host_find(p.host);
		if (!host) return -ENOENT;
		for (share = host->share_list ; share ; share = share->next) {
			if (filler(buf, share->name, &st, 0)) return -EIO;
		}
		return 0;
	}
	conn = fusesmb_connect(p.host, p.share);
	if (!conn) return -ENOENT;
	strcat(p.path, "\\*");
	if (smb_find_first(conn, &fr, p.path)) return -ENOENT;
	while (!smb_find_next(conn, &fr, &di)) {
		fusesmb_make_stat(&st, &di);		
		if (!iconv_dos_to_local_buf(di.name, name, sizeof(name))) continue;
		if (filler(buf, name, &st, 0)) return -EIO;
	}
	if (smb_find_close(conn, &fr)) return -EIO;
	return 0;
}

static int fusesmb_open(const char *path, struct fuse_file_info *fi) {
	int fid;
	fusesmb_file_p file;
	fusesmb_host_p host;
	fusesmb_share_p share;
	smb_connect_p conn;
	fusesmb_path_t p;
	fusesmb_parse_path(path, &p);
	if (!p.host[0] || !p.share[0] || !p.path[0]) return -ENOENT;
	host = fusesmb_connect_host(p.host);
	if (!host) return -ECONNREFUSED;
	share = fusesmb_connect_share(host, p.share);
	if (!share) return -ENOENT;
	conn = host->conn;	
	fid = smb_open(conn, p.path, OPEN_FLAGS_OPEN_READ);
	if (fid < 0 ) return -EIO;
	
	NEW_STRUCT(file);
	file->conn = conn;
	file->tid = share->tid;	
	file->fid = fid;
	
	fi->fh = (unsigned long int)file;
	
	return 0;
}

static int fusesmb_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
	off_t res, off;
	fusesmb_file_p file = (fusesmb_file_p)fi->fh;

	res = file->buf_off + file->buf_len - offset;
	off = offset - file->buf_off;
	
	if (off < 0 || res <= 0) {
		smb_treeswitch(file->conn, file->tid);
		res = smb_read(file->conn, file->fid, file->buf, sizeof(file->buf), offset);
		if (res < 0) return -EIO;
		
		file->buf_len = res;
		file->buf_off = offset;
		off = 0;
	}
	
	if (res > size) res = size;
	memcpy(buf, file->buf + off, res);
	
	return res;
}

static int fusesmb_release(const char *path, struct fuse_file_info *fi) {
	fusesmb_file_p file = (fusesmb_file_p)fi->fh;
	smb_treeswitch(file->conn, file->tid);
	smb_close(file->conn, file->fid);
	FREE_STRUCT(file);
	fi->fh = 0;
	return 0;
}

static struct fuse_operations fusesmb_oper = {
	.getattr = fusesmb_getattr,
	.readdir = fusesmb_readdir,
	.open	 = fusesmb_open,
	.release = fusesmb_release,
	.read	 = fusesmb_read,
};

int main(int argc, char *argv[]) {
	setlocale(LC_ALL,"");
	iconv_init();
	fusesmb_list_host("server", "HACKERS");
    	return fuse_main(argc, argv, &fusesmb_oper);
}
