#ifndef FIND_H
#define FIND_H

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
} cifs_dirent_t;
typedef cifs_dirent_t *cifs_dirent_p;

typedef struct cifs_dir_s cifs_dir_t;
typedef cifs_dir_t *cifs_dir_p;

cifs_dir_p cifs_find(cifs_connect_p c, const char *path, const char *mask);

cifs_dir_p cifs_opendir(cifs_connect_p c, const char *path);

cifs_dirent_p cifs_readdir(cifs_dir_p dir);

int cifs_closedir(cifs_dir_p dir);

int cifs_stat(cifs_connect_p c, const char *path, cifs_stat_p st);

#endif /* FIND_H */
