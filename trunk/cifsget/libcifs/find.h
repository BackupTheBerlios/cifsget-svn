#ifndef FIND_H
#define FIND_H

#define SMB_MAX_PATH 260

typedef struct smb_dirinfo_s {
	int64_t creation_time;
	int64_t access_time;
	int64_t write_time;
	int64_t change_time;
	uint64_t file_size;
	uint64_t allocation_size;
	char directory;
	//uint32_t attributes;
	char name[SMB_MAX_PATH];
} smb_dirinfo_t;
typedef smb_dirinfo_t *smb_dirinfo_p;

typedef struct smb_find_s {
	smb_connect_p c;
	smb_trans_t t;
	int sid;
	int end;
	char *cur;
	int count;
} smb_find_t;
typedef smb_find_t *smb_find_p;

int smb_find_first(smb_connect_p c, const char *mask, smb_find_p fi);
int smb_find_next(smb_find_p fi, smb_dirinfo_p di);
int smb_find_close(smb_find_p fi);

smb_dirinfo_p smb_info(smb_connect_p c, const char *name);

#endif /* FIND_H */
