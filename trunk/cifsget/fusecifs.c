#include "libcifs/includes.h"

#define FUSE_USE_VERSION 22

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#include <locale.h>

#define ZERO_STRUCT(x)  memset((char *)&(x), 0, sizeof(x))
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char*)(x), 0, sizeof(*(x))); } while (0)

#define NEW_STRUCT(x) x = calloc(1, sizeof(*(x)))
#define FREE_STRUCT(x) do { free(x); x = NULL; } while(0)

typedef struct fusecifs_path_s {
	const char *host;
	int host_len;
	const char *share;
	int share_len;
	const char *path;
} fusecifs_path_t;
typedef fusecifs_path_t *fusecifs_path_p;

static void fusecifs_parse_path(const char *path, fusecifs_path_p res) {
	const char *p = path;
	ZERO_STRUCTP(res);
	p += strspn(p, "/");
	if (!*p) return;
	res->host = p;
	res->host_len = strcspn(p, "/");
	p += res->host_len;	
	p += strspn(p, "/");
	if (!*p) return;
	res->share = p;
	res->share_len = strcspn(p, "/");
	p += res->share_len;
	//p += strspn(p, "/");
	res->path = p;
}

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

static fusecifs_host_p fusecifs_host_list = NULL;

static fusecifs_host_p fusecifs_host_find(fusecifs_path_p path) {
	fusecifs_host_p host = fusecifs_host_list;
	while (host && strncmp(host->name, path->host, path->host_len)) host = host->next;
	return host;
}

static fusecifs_share_p fusecifs_share_find(fusecifs_host_p host, fusecifs_path_p path) {
	fusecifs_share_p share = host->share_list;
	while (share && strncmp(share->name, path->share, path->share_len)) share = share->next;
	return share;
}


static fusecifs_host_p fusecifs_connect_host(fusecifs_path_p path) {
	fusecifs_host_p host;
	cifs_connect_p conn;
	
	host = fusecifs_host_find(path);
	
	if (!host || !host->conn) {
		char *host_name = strndup(path->host, path->host_len);
		
		conn = cifs_connect(host_name, 0, host_name);
		
		if (!conn) {
			free(host_name);
			return NULL;
		}
		
		if (!host) {
			NEW_STRUCT(host);
			host->name = host_name;
			host->next = fusecifs_host_list;
			fusecifs_host_list = host;
		} else {
			free(host_name);
		}
		host->conn = conn;
	}
	return host;
}

static fusecifs_share_p fusecifs_connect_share(fusecifs_host_p host, fusecifs_path_p path) {
	fusecifs_share_p share;
	cifs_connect_p conn;
	int tid;	

	conn = host->conn;

	share = fusecifs_share_find(host, path);
	
	if (share && share->tid >= 0) {
		cifs_tree_switch(conn, share->tid);
		return share;
	}

	char *share_name = strndup(path->share, path->share_len);
	
	tid = cifs_tree_connect(conn, share_name);
	
	if (tid < 0) return NULL;
	
	if (!share) {
		NEW_STRUCT(share);
		share->name = share_name;
		share->next = host->share_list;
		host->share_list = share;
	} else {
		free(share_name);
	}	
	share->tid = tid;
	
	return share;
}

static cifs_connect_p fusecifs_connect(fusecifs_path_p path) {
	fusecifs_host_p host;
	fusecifs_share_p share;
	host = fusecifs_connect_host(path);
	share = fusecifs_connect_share(host, path);
	return host->conn;
}

static int fusecifs_list_share(fusecifs_path_p path) {
	cifs_enum_p e;
	fusecifs_host_p host;
	fusecifs_share_p share;
	cifs_connect_p conn;
	cifs_node_t n;
	
	host = fusecifs_connect_host(path);
	if (!host) return -errno;

	path->share = "IPC$";
	path->share_len = 4;
		
	if (!fusecifs_connect_share(host, path)) return -errno;
	
	conn = host->conn;

	e = cifs_enum_share(conn);
	if (!e) return -errno;
	
	while (!cifs_enum_next(e, &n)) {
		path->share = n.name;
		path->share_len = strlen(n.name);
		share = fusecifs_share_find(host, path);
		if (!share) {
			NEW_STRUCT(share);
			share->name = strdup(n.name);
				share->tid = -1;
				share->next = host->share_list;
				host->share_list = share;
		}
	}
	cifs_enum_close(e);
	return 0;
}

static int fusecifs_list_host(const char *server, const char *workgroup) {
	cifs_connect_p c;
	cifs_enum_p e;
	cifs_node_t n;	

	c = cifs_connect_tree(server, 0, server, "IPC$");
	if (!c) return -errno;
	e = cifs_enum_server(c, workgroup);
	if (!e) {
		cifs_connect_close(c);
		return -errno;
	}
	while (!cifs_enum_next(e, &n)) {
		fusecifs_host_p host = fusecifs_host_list;
		while (host && strcmp(host->name, n.name)) host = host->next;
		if (!host) {
			NEW_STRUCT(host);
			host->name = strdup(n.name);
			host->next = fusecifs_host_list;
			fusecifs_host_list =  host;
		}
	}
	cifs_connect_close(c);
	return 0;
}

static int fusecifs_make_stat (struct stat *st, cifs_stat_p cs) {
	st->st_dev = 0;
	st->st_ino = 0;
	
	if (cs->is_directory) {
		st->st_mode = S_IFDIR | 0775;
	} else {
		st->st_mode = S_IFREG | 0664;
	}
	st->st_nlink = 1;
	st->st_uid = 0;
	st->st_gid = 0;
	st->st_rdev = 0;
	st->st_size = cs->file_size;
	st->st_blksize = 64*1024;
	st->st_blocks = (cs->file_size + st->st_blksize - 1) / st->st_blksize;
	st->st_atime = cifs_time(cs->access_time);
	st->st_mtime = cifs_time(cs->write_time);
	st->st_ctime = cifs_time(cs->change_time);
	return 0;
}

static int fusecifs_getattr (const char *path, struct stat *st) {
	cifs_connect_p conn;
	fusecifs_path_t p;
	cifs_stat_t cs;
	fusecifs_parse_path(path, &p);
	if (!p.host || !p.share || !p.path || !p.path[0])  {
		ZERO_STRUCTP(st);
		st->st_mode = S_IFDIR | 0775;
		return 0;
	}
	conn = fusecifs_connect(&p);
	if (!conn) return -errno;
	if (cifs_stat(conn, p.path, &cs)) return -errno;
	fusecifs_make_stat(st, &cs);
	return 0;	
}

static int fusecifs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi) {
	fusecifs_path_t p;
	cifs_connect_p conn;
	
	cifs_dir_p dir;
	cifs_dirent_p de;
	struct stat st;
	
	fusecifs_host_p host;
	fusecifs_share_p share;
	
	fusecifs_parse_path(path, &p);
	if (!p.host) {
		ZERO_STRUCT(st);
		st.st_mode = S_IFDIR | 0775;		
		for (host = fusecifs_host_list ; host ; host = host->next) {
			if (filler(buf, host->name, &st, 0)) return -EIO;
		}		
		return 0;
	}	
	if (!p.share) {
		ZERO_STRUCT(st);
		st.st_mode = S_IFDIR | 0775;
		if (fusecifs_list_share(&p)) return -errno;
		host = fusecifs_host_find(&p);
		if (!host) return -errno;
		for (share = host->share_list ; share ; share = share->next) {
			if (filler(buf, share->name, &st, 0)) return -EIO;
		}
		return 0;
	}
	conn = fusecifs_connect(&p);
	if (!conn) return -errno;
	
	dir = cifs_opendir(conn, p.path);
	if (!dir) return -errno;
	
	while ((de = cifs_readdir(dir))) {
		fusecifs_make_stat(&st, &de->st);
		if (filler(buf, de->name, &st, 0)) return -EIO;
	}
	cifs_closedir(dir);
	return 0;
}

static int fusecifs_open(const char *path, struct fuse_file_info *fi) {
	int fid;	
	cifs_connect_p conn;
	fusecifs_path_t p;
	fusecifs_parse_path(path, &p);
	conn = fusecifs_connect(&p);
	if (!conn) return -errno;
	fid = cifs_open(conn, p.path, fi->flags);
	if (fid < 0 ) return -EIO;
	fi->fh = fid;
	return 0;
}

static int fusecifs_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
	cifs_connect_p c;
	fusecifs_path_t p;
	fusecifs_parse_path(path, &p);
	c = fusecifs_connect(&p);
	if (!c) return -errno;
	int res = 0, ret;
	while (size) {
		ret = cifs_read(c, fi->fh, buf, size, offset);
		if (ret == 0) return res;
		if (ret < 0)  return -errno;
		buf += ret;
		offset += ret;
		size -= ret;
		res += ret;
	}
	return res;
}

static int fusecifs_release(const char *path, struct fuse_file_info *fi) {
	fusecifs_path_t p;
	cifs_connect_p c;
	fusecifs_parse_path(path, &p);
	c = fusecifs_connect(&p);
	cifs_close(c, fi->fh);
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
	fusecifs_list_host("server", "HACKERS");
    return fuse_main(argc, argv, &fusecifs_oper);
}

