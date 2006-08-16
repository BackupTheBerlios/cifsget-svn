#ifndef FIND_H
#define FIND_H

#define CIFS_MAX_PATH 260

typedef struct cifs_dirinfo_s {
	int64_t creation_time;
	int64_t access_time;
	int64_t write_time;
	int64_t change_time;
	uint64_t file_size;
	uint64_t allocation_size;
	int directory;
	//uint32_t attributes;
	char name[CIFS_MAX_PATH];
} cifs_dirinfo_t;
typedef cifs_dirinfo_t *cifs_dirinfo_p;

typedef struct cifs_find_s cifs_find_t;
typedef cifs_find_t *cifs_find_p;

cifs_find_p cifs_find_first(cifs_connect_p c, const char *mask);
int cifs_find_next(cifs_find_p fi, cifs_dirinfo_p di);
int cifs_find_close(cifs_find_p fi);

cifs_dirinfo_p cifs_info(cifs_connect_p c, const char *name);

#endif /* FIND_H */
