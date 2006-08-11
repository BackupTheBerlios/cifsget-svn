#include "includes.h"

void smb_build_dirinfo(smb_connect_p c, smb_dirinfo_p d, char *p) {
	int nl;
	nl = GET_DIRINFO_NAME_LEN(p);
	nl = (nl<SMB_MAX_PATH)?nl:(SMB_MAX_PATH-1);
	d->creation_time = GET_DIRINFO_CREATION_TIME(p);
	d->access_time = GET_DIRINFO_ACCESS_TIME(p);
	d->write_time = GET_DIRINFO_WRITE_TIME(p);
	d->change_time = GET_DIRINFO_CHANGE_TIME(p);
	d->file_size = GET_DIRINFO_FILE_SIZE(p);
	d->allocation_size = GET_DIRINFO_ALLOCATION_SIZE(p);
	d->attributes = GET_DIRINFO_ATTRIBUTES(p);
	if (c->capabilities & CAP_UNICODE) {
		smb_cp_block(smb_cp_ucs_to_sys, d->name, sizeof(d->name), PTR_DIRINFO_NAME(p), nl);
	} else {
		smb_cp_block(smb_cp_oem_to_sys, d->name, sizeof(d->name), PTR_DIRINFO_NAME(p), nl);
	}
}

int smb_find_first_req(smb_connect_p c, const char *mask) {
	char *o=c->o, *b, *w, *p;
	smb_trans_req(c, SMBtrans2, NULL, 1, TRANSACT2_FINDFIRST);
	
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
		smb_path_fix_ucs(tmp);
	} else {
		WRITE_STRING_OEM(p, c->o_end, mask);
		smb_path_fix_oem(PTR_OFINDFIRST_MASK(b));
	}
	END_PACKET_B(o, p);
	SET_OTRANS_PARAM_COUNT(w, LEN_PACKET_B(o));
	SET_OTRANS_TOTAL_PARAM_COUNT(w, LEN_PACKET_B(o));
	
	smb_log_struct(b, OFINDFIRST);

	return 0;
}

int smb_find_next_req(smb_connect_p c, int sid) {
	char *o=c->o, *b, *w;
	smb_trans_req(c, SMBtrans2, NULL, 1, TRANSACT2_FINDNEXT);
	
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
	
	smb_log_struct(b, OFINDNEXT);

	return 0;
}

int smb_find_close_req(smb_connect_p c, int sid) {
	char *o=c->o;
	SET_PACKET_COMMAND(o, SMBfindclose);
	SETLEN_PACKET_W(o, 2);
	SETLEN_PACKET_B(o, 0);
	SET_WORD(PTR_PACKET_W(o), 0, sid);
	return 0;
}

int smb_find_first(smb_connect_p c, const char *mask, smb_find_p f) {
	
	f->c = c;
	
	smb_find_first_req(c, mask);

	if (smb_trans_alloc(&f->t)) return -1;
	
	if (smb_trans_request(c, &f->t)) {
		smb_trans_free(&f->t);
		errno = ENOENT;
		return -1;
	}

	smb_log_trans("findfirst", &f->t);
	smb_log_struct(f->t.param, IFINDFIRST);

	f->end = GET_IFINDFIRST_END_OF_SEARCH(f->t.param);
	f->sid = GET_IFINDFIRST_SID(f->t.param);
	f->cur = f->t.data;
	f->count = GET_IFINDFIRST_SEARCH_COUNT(f->t.param);
	
	return 0;
}

int smb_find_next(smb_find_p f, smb_dirinfo_p d) {
loop:
	if (f->count == 0) {
		if (f->end) return 1;
		smb_find_next_req(f->c, f->sid);
		
		if (smb_send(f->c)) return -1;
		if (smb_trans_recv(f->c, &f->t)) return -1;


		smb_log_trans("findnext", &f->t);
		smb_log_struct(f->t.param, IFINDNEXT);

		f->end = GET_IFINDNEXT_END_OF_SEARCH(f->t.param);
		f->cur = f->t.data;
		f->count = GET_IFINDNEXT_SEARCH_COUNT(f->t.param);
		
		if (f->count == 0) return 1;
	}
	smb_build_dirinfo(f->c, d, f->cur);
	f->cur += GET_DIRINFO_NEXT_ENTRY_OFFSET(f->cur);
	f->count--;
	if ((d->attributes & FILE_ATTRIBUTE_DIRECTORY) && (!strcmp(d->name, ".") || !strcmp(d->name, ".."))) goto loop;
	return 0;
}

int smb_find_close(smb_find_p f) {
	smb_trans_free(&f->t);
	if (!f->end) {
		smb_find_close_req(f->c, f->sid);
		if (smb_request(f->c)) return -1;
	}
	return 0;
}


smb_find_p smb_find_first2(smb_connect_p c, const char *mask) {
	smb_find_p f;
	NEW_STRUCT(f);
	if (smb_find_first(c, mask, f)) {
		FREE_STRUCT(f);
		return NULL;
	}
	return f;
}

smb_dirinfo_p smb_find_next2(smb_find_p f) {
	smb_dirinfo_p d;
	NEW_STRUCT(d);
	if (smb_find_next(f, d)) {
		FREE_STRUCT(d);
		return NULL;
	}
	return d;
}

int smb_find_close2(smb_find_p f) {
	smb_find_close(f);
	FREE_STRUCT(f);
	return 0;
}


int smb_info(smb_connect_p c, const char *name, smb_dirinfo_p d) {
	smb_trans_t t;
	smb_find_first_req(c, name);
	if (smb_trans_alloc(&t)) return -1;
	if (smb_trans_request(c, &t)) {
		smb_trans_free(&t);
		return -1;	
	}	

	smb_log_trans("info", &t);
	smb_log_struct(t.param, IFINDFIRST);

	if (GET_IFINDFIRST_SEARCH_COUNT(t.param) != 1) {
		smb_trans_free(&t);
		if (!GET_IFINDFIRST_END_OF_SEARCH(t.param)) {
			smb_find_close_req(c, GET_IFINDFIRST_SID(t.param));
			smb_request(c);
		}
		errno = EMLINK;
		return -1;
	}
	
	smb_build_dirinfo(c, d, t.data);
	smb_trans_free(&t);
	return 0;
}

smb_dirinfo_p smb_info2(smb_connect_p c, const char *name) {
	smb_dirinfo_p d;
	NEW_STRUCT(d);
	if (smb_info(c, name, d)) {
		FREE_STRUCT(d);
		return NULL;
	}
	return d;
}

