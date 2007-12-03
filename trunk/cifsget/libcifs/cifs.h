#ifndef LIBCIFS_H
#define LIBCIFS_H

#include <stdint.h>

/* CONNECT */

typedef struct cifs_connect_s cifs_connect_t;
typedef cifs_connect_t *cifs_connect_p;

cifs_connect_p cifs_connect(const char *host, int port, const char *name, const char *tree);

int cifs_tree_connect(cifs_connect_p c, const char *tree);
int cifs_tree_disconnect(cifs_connect_p c, int tid);
int cifs_tree_set(cifs_connect_p c, int tid);

void cifs_connect_close(cifs_connect_p c);

/* DIR */

typedef struct cifs_stat_s {
	int64_t creation_time;
	int64_t access_time;
	int64_t write_time;
	int64_t change_time;
	uint64_t file_size;
	uint64_t allocation_size;
	uint32_t attributes;
	int is_directory;
} cifs_stat_t;
typedef cifs_stat_t *cifs_stat_p;

typedef struct cifs_dirent_s {
	cifs_stat_t st;
	char *name;
	char *path;
    char buf[0];
} cifs_dirent_t;
typedef cifs_dirent_t *cifs_dirent_p;

typedef struct cifs_dir_s cifs_dir_t;
typedef cifs_dir_t *cifs_dir_p;

cifs_dir_p cifs_opendir(cifs_connect_p c, const char *path);
cifs_dir_p cifs_mask(cifs_connect_p c, const char *path, const char *mask);
cifs_dirent_p cifs_readdir(cifs_dir_p dir);
int cifs_closedir(cifs_dir_p dir);

int cifs_stat(cifs_connect_p c, const char *path, cifs_stat_p st);

int cifs_mkdir(cifs_connect_p c, const char *path);
int cifs_rmdir(cifs_connect_p c, const char *path);

time_t cifs_time(int64_t nt_time);

cifs_dirent_p *cifs_scandir(cifs_connect_p c, const char *path);

/* FILE */

int cifs_open(cifs_connect_p c, const char *path, int flags, cifs_stat_p stat);
int cifs_close(cifs_connect_p c, int fid);
int cifs_unlink(cifs_connect_p c, const char *path);

size_t cifs_read(cifs_connect_p c, int fid, void *buf, size_t count, uint64_t offset);
size_t cifs_write(cifs_connect_p c, int fid, const void *buf, size_t count, uint64_t offset);

/* RAP NODE */

enum {
	CIFS_NODE_SHARE,
	CIFS_NODE_SERVER,
	CIFS_NODE_DOMAIN,
};

typedef struct cifs_node_s {
	int type;
	unsigned int attributes;
	char name[64];
	char comment[64];
} cifs_node_t;
typedef cifs_node_t *cifs_node_p;

cifs_node_p *cifs_scannode(cifs_connect_p c, int type, const char *domain);

/* DEBUG */

#define CIFS_LOG_QUIET   0
#define CIFS_LOG_ERROR   1
#define CIFS_LOG_WARNING 2
#define CIFS_LOG_NORMAL  3
#define CIFS_LOG_VERBOSE 4
#define CIFS_LOG_DEBUG   5
#define CIFS_LOG_NOISY   6

extern int cifs_log_level;
extern FILE *cifs_log_stream;

#endif /* LIBCIFS_H */
