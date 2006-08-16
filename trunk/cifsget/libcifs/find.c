#include "includes.h"

struct cifs_find_s {
	cifs_connect_p c;
	cifs_trans_t t;
	int sid;
	int end;
	char *cur;
	int count;
};

static void cifs_build_dirinfo(cifs_connect_p c, cifs_dirinfo_p d, char *p) {
	int nl;
	nl = GET_DIRINFO_NAME_LEN(p);
	nl = (nl<CIFS_MAX_PATH)?nl:(CIFS_MAX_PATH-1);
	d->creation_time = GET_DIRINFO_CREATION_TIME(p);
	d->access_time = GET_DIRINFO_ACCESS_TIME(p);
	d->write_time = GET_DIRINFO_WRITE_TIME(p);
	d->change_time = GET_DIRINFO_CHANGE_TIME(p);
	d->file_size = GET_DIRINFO_FILE_SIZE(p);
	d->allocation_size = GET_DIRINFO_ALLOCATION_SIZE(p);
	//d->attributes = GET_DIRINFO_ATTRIBUTES(p);
	d->directory = GET_DIRINFO_ATTRIBUTES(p)&FILE_ATTRIBUTE_DIRECTORY ? 1 : 0;
	if (c->capabilities & CAP_UNICODE) {
		cifs_cp_block(cifs_cp_ucs_to_sys, d->name, sizeof(d->name), PTR_DIRINFO_NAME(p), nl);
	} else {
		cifs_cp_block(cifs_cp_oem_to_sys, d->name, sizeof(d->name), PTR_DIRINFO_NAME(p), nl);
	}
}

static int cifs_find_first_req(cifs_connect_p c, const char *mask) {
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
		WRITE_STRING_UCS(p, c->o_end, mask);
		cifs_path_fix_ucs(tmp);
	} else {
		WRITE_STRING_OEM(p, c->o_end, mask);
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

cifs_find_p cifs_find_first(cifs_connect_p c, const char *mask) {
	cifs_find_p f;

	NEW_STRUCT(f);
	
	if (f == NULL) return NULL;
	
	if (cifs_trans_alloc(&f->t)) {
		FREE_STRUCT(f);
		return NULL;
	}
			
	f->c = c;
	
	cifs_find_first_req(c, mask);
	
	if (cifs_trans_request(c, &f->t)) {
		cifs_trans_free(&f->t);
		FREE_STRUCT(f);
		return NULL;
	}

	cifs_log_trans("findfirst", &f->t);
	cifs_log_struct(f->t.param, IFINDFIRST);

	f->end = GET_IFINDFIRST_END_OF_SEARCH(f->t.param);
	f->sid = GET_IFINDFIRST_SID(f->t.param);
	f->cur = f->t.data;
	f->count = GET_IFINDFIRST_SEARCH_COUNT(f->t.param);
	
	return f;
}

int cifs_find_next(cifs_find_p f, cifs_dirinfo_p d) {
loop:
	if (f->count == 0) {
		if (f->end) return 1;
		cifs_find_next_req(f->c, f->sid);
		
		if (cifs_send(f->c)) return -1;
		if (cifs_trans_recv(f->c, &f->t)) return -1;

		cifs_log_trans("findnext", &f->t);
		cifs_log_struct(f->t.param, IFINDNEXT);

		f->end = GET_IFINDNEXT_END_OF_SEARCH(f->t.param);
		f->cur = f->t.data;
		f->count = GET_IFINDNEXT_SEARCH_COUNT(f->t.param);
		
		if (f->count == 0) return 1;
	}
	cifs_build_dirinfo(f->c, d, f->cur);
	f->cur += GET_DIRINFO_NEXT_ENTRY_OFFSET(f->cur);
	f->count--;
	if (d->directory && (!strcmp(d->name, ".") || !strcmp(d->name, ".."))) goto loop;
	return 0;
}

int cifs_find_close(cifs_find_p f) {
	cifs_trans_free(&f->t);
	if (!f->end) {
		cifs_find_close_req(f->c, f->sid);
		if (cifs_request(f->c)) return -1;
	}
	return 0;
}

cifs_dirinfo_p cifs_info(cifs_connect_p c, const char *name) {
	cifs_trans_t tr;
	cifs_dirinfo_p di;

	cifs_find_first_req(c, name);
	if (cifs_trans_alloc(&tr)) return NULL;
	if (cifs_trans_request(c, &tr)) {
		cifs_trans_free(&tr);
		return NULL;	
	}	

	cifs_log_trans("info", &tr);
	cifs_log_struct(tr.param, IFINDFIRST);

	if (GET_IFINDFIRST_SEARCH_COUNT(tr.param) != 1) {
		cifs_trans_free(&tr);
		if (!GET_IFINDFIRST_END_OF_SEARCH(tr.param)) {
			cifs_find_close_req(c, GET_IFINDFIRST_SID(tr.param));
			cifs_request(c);
		}
		errno = EMLINK;
		return NULL;
	}
	
	NEW_STRUCT(di);
	cifs_build_dirinfo(c, di, tr.data);
	cifs_trans_free(&tr);
	return di;
}

