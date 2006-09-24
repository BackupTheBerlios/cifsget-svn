#include "includes.h"

struct cifs_dir_s {
	cifs_connect_p c;
	cifs_trans_t t;
	int sid;
	int end;
	char *cur;
	int count;
	char buf[PATH_MAX + NAME_MAX + 2];
	cifs_dirent_t de;
};

static void cifs_build_stat(char *p, cifs_stat_p st) {
	st->creation_time = GET_DIRINFO_CREATION_TIME(p);
	st->access_time = GET_DIRINFO_ACCESS_TIME(p);
	st->write_time = GET_DIRINFO_WRITE_TIME(p);
	st->change_time = GET_DIRINFO_CHANGE_TIME(p);
	st->file_size = GET_DIRINFO_FILE_SIZE(p);
	st->allocation_size = GET_DIRINFO_ALLOCATION_SIZE(p);
	st->attributes = GET_DIRINFO_ATTRIBUTES(p);
	st->is_directory = GET_DIRINFO_ATTRIBUTES(p) & FILE_ATTRIBUTE_DIRECTORY ? 1 : 0;
}

static void cifs_build_dirent(cifs_connect_p c, char *p, cifs_dirent_p de) {
	int nl;
	cifs_build_stat(p, &de->st);
	nl = GET_DIRINFO_NAME_LEN(p);
	if (c->capabilities & CAP_UNICODE) {
		cifs_cp_block(cifs_cp_ucs_to_sys, de->name, NAME_MAX, PTR_DIRINFO_NAME(p), nl);
	} else {
		cifs_cp_block(cifs_cp_oem_to_sys, de->name, NAME_MAX, PTR_DIRINFO_NAME(p), nl);
	}
}

static int cifs_find_first_req(cifs_connect_p c, const char *path, const char *mask) {
	char *o=c->o, *b, *w, *p;
	cifs_trans_req(c, SMBtrans2, NULL, 1, TRANSACT2_FINDFIRST);
	
	w = PTR_PACKET_W(o);
	b = PTR_PACKET_B(o);
	
	SET_OFINDFIRST_SEARCH_ATTRIBUTES(b, 0x37);
	SET_OFINDFIRST_SEARCH_COUNT(b, -1);
	SET_OFINDFIRST_FLAGS(b, FLAG_TRANS2_FIND_CLOSE_IF_END);
	SET_OFINDFIRST_INFORMATION_LEVEL(b, SMB_FIND_DIRECTORY_INFO);
	SET_OFINDFIRST_SEARCH_STORAGE_TYPE(b, 0);

	p = PTR_OFINDFIRST_MASK(b);
	if (c->capabilities & CAP_UNICODE) {
		//WTF!!!???
		//WRITE_ALIGN(p, c->o, 2);
		char *tmp = p;
		if (path && path[0]) {
			WRITE_BUF_UCS(p, c->o_end, "/");
			WRITE_BUF_UCS(p, c->o_end, path);
		}
		if (mask && mask[0]) {
			WRITE_BUF_UCS(p, c->o_end, "/");
			WRITE_BUF_UCS(p, c->o_end, mask);
		}
		WRITE_WORD(p, 0);
		cifs_path_fix_ucs(tmp);
	} else {
		if (path && path[0]) {
			WRITE_BUF_OEM(p, c->o_end, "/");
			WRITE_BUF_OEM(p, c->o_end, path);
		}
		if (mask && mask[0]) {
			WRITE_BUF_OEM(p, c->o_end, "/");
			WRITE_BUF_OEM(p, c->o_end, mask);
		}
		WRITE_BYTE(p, 0);
		cifs_path_fix_oem(PTR_OFINDFIRST_MASK(b));
	}
	END_PACKET_B(o, p);
	SET_OTRANS_PARAM_COUNT(w, LEN_PACKET_B(o));
	SET_OTRANS_TOTAL_PARAM_COUNT(w, LEN_PACKET_B(o));
	
	cifs_log_struct(b, OFINDFIRST);

	return 0;
}

static int cifs_find_next_req(cifs_connect_p c, int sid) {
	char *o=c->o, *b, *w;
	cifs_trans_req(c, SMBtrans2, NULL, 1, TRANSACT2_FINDNEXT);
	
	w = PTR_PACKET_W(o);
	b = PTR_PACKET_B(o);
	
	SET_OFINDNEXT_SID(b, sid);
	SET_OFINDNEXT_SEARCH_COUNT(b, -1);
	SET_OFINDNEXT_INFORMATION_LEVEL(b, SMB_FIND_DIRECTORY_INFO);
	SET_OFINDNEXT_RESUME_KEY(b, 0);
	SET_OFINDNEXT_FLAGS(b, FLAG_TRANS2_FIND_CLOSE_IF_END | FLAG_TRANS2_FIND_CONTINUE);
	strcpy(PTR_OFINDFIRST_MASK(b), "");
	
	SETLEN_PACKET_B(o, LEN_OFINDNEXT(b));
	
	SET_OTRANS_PARAM_COUNT(w, LEN_PACKET_B(o));
	SET_OTRANS_TOTAL_PARAM_COUNT(w, LEN_PACKET_B(o));
	
	cifs_log_struct(b, OFINDNEXT);

	return 0;
}

static int cifs_find_close_req(cifs_connect_p c, int sid) {
	char *o=c->o;
	SET_PACKET_COMMAND(o, SMBfindclose);
	SETLEN_PACKET_W(o, 2);
	SETLEN_PACKET_B(o, 0);
	SET_WORD(PTR_PACKET_W(o), 0, sid);
	return 0;
}

cifs_dir_p cifs_find(cifs_connect_p c, const char *path, const char *mask) {
	cifs_dir_p d;

	NEW_STRUCT(d);
	
	if (d == NULL) return NULL;
	
	if (cifs_trans_alloc(&d->t)) {
		FREE_STRUCT(d);
		return NULL;
	}
			
	d->c = c;
	
	cifs_find_first_req(c, path, mask);
	
	if (cifs_trans_request(c, &d->t)) {
		cifs_trans_free(&d->t);
		FREE_STRUCT(d);
		return NULL;
	}

	cifs_log_trans("findfirst", &d->t);
	cifs_log_struct(d->t.param, IFINDFIRST);

	d->end = GET_IFINDFIRST_END_OF_SEARCH(d->t.param);
	d->sid = GET_IFINDFIRST_SID(d->t.param);
	d->cur = d->t.data;
	d->count = GET_IFINDFIRST_SEARCH_COUNT(d->t.param);
	
	d->de.path = d->buf;
	char *p = d->buf;
	WRITE_BUF(p, path);
	WRITE_BUF(p, "/");
	*p = '\0';
	d->de.name = p;
	
	return d;
}

cifs_dir_p cifs_opendir(cifs_connect_p c, const char *path) {
	return cifs_find(c, path, "*");
}

cifs_dirent_p cifs_readdir(cifs_dir_p f) {
loop:
	if (f->count == 0) {
		if (f->end) {
			errno = ENOENT;
			return NULL;
		}
		cifs_find_next_req(f->c, f->sid);
		
		if (cifs_send(f->c)) return NULL;
		if (cifs_trans_recv(f->c, &f->t)) return NULL;

		cifs_log_trans("findnext", &f->t);
		cifs_log_struct(f->t.param, IFINDNEXT);

		f->end = GET_IFINDNEXT_END_OF_SEARCH(f->t.param);
		f->cur = f->t.data;
		f->count = GET_IFINDNEXT_SEARCH_COUNT(f->t.param);
		
		if (f->count == 0) {
			errno = ENOENT;
			return NULL;
		}
	}	
	cifs_build_dirent(f->c, f->cur, &f->de);
	f->cur += GET_DIRINFO_NEXT_ENTRY_OFFSET(f->cur);
	f->count--;
	if (f->de.st.is_directory && (!strcmp(f->de.name, ".") || !strcmp(f->de.name, ".."))) {
		goto loop;
	}
	return &f->de;
}

int cifs_closedir(cifs_dir_p f) {
	cifs_trans_free(&f->t);
	if (!f->end) {
		cifs_find_close_req(f->c, f->sid);
		if (cifs_request(f->c)) return -1;
	}
	return 0;
}

int cifs_stat(cifs_connect_p c, const char *path, cifs_stat_p st) {
	cifs_trans_t tr;

	if (cifs_trans_alloc(&tr)) return -1;
	cifs_find_first_req(c, path, NULL);	
	if (cifs_trans_request(c, &tr)) {
		cifs_trans_free(&tr);
		return -1;
	}

	cifs_log_trans("info", &tr);
	cifs_log_struct(tr.param, IFINDFIRST);

	if (GET_IFINDFIRST_SEARCH_COUNT(tr.param) != 1) {		
		if (!GET_IFINDFIRST_END_OF_SEARCH(tr.param)) {
			cifs_find_close_req(c, GET_IFINDFIRST_SID(tr.param));
			cifs_request(c);
		}
		cifs_trans_free(&tr);
		errno = EMLINK;
		return -1;
	}
	cifs_build_stat(tr.data, st);
	cifs_trans_free(&tr);
	return 0;
}

