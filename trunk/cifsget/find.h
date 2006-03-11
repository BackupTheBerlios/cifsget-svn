#ifndef FIND_H
#define FIND_H

typedef struct smb_dirinfo_s {
	int64_t creation_time;
	int64_t access_time;
	int64_t write_time;
	int64_t change_time;
	uint64_t file_size;
	uint64_t allocation_size;
	uint32_t attributes;
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

void smb_build_dirinfo(smb_dirinfo_p d, char *p);

int smb_find_first_req(smb_connect_p c, const char *mask);
int smb_find_next_req(smb_connect_p c, int sid);
int smb_find_close_req(smb_connect_p c, int sid);

int smb_find_first(smb_connect_p c, const char *mask, smb_find_p f);
int smb_find_next(smb_find_p f, smb_dirinfo_p d);
int smb_find_close(smb_find_p f);

smb_find_p smb_find_first2(smb_connect_p c, const char *mask);
smb_dirinfo_p smb_find_next2(smb_find_p f);
int smb_find_close2(smb_find_p f);

int smb_info(smb_connect_p c, const char *name, smb_dirinfo_p d);
smb_dirinfo_p smb_info2(smb_connect_p c, const char *name);

#endif /* FIND_H */
