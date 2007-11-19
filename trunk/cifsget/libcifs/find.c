#include "includes.h"

struct cifs_dir_s {
	cifs_connect_p c;
	cifs_trans_t t;
	int sid;
	int end;
    int count;
    cifs_buf_p buf;
    cifs_buf_p path;
	cifs_dirent_t de;
};

static void cifs_build_stat(struct cifs_dirinfo_s *di, cifs_stat_p st) {
	st->creation_time = di->creation_time;
	st->access_time = di->access_time;
	st->write_time = di->write_time;
	st->change_time = di->change_time;
	st->file_size = di->file_size;
	st->allocation_size = di->allocation_size;
	st->attributes = di->attributes;
	st->is_directory = di->attributes & FILE_ATTRIBUTE_DIRECTORY ? 1 : 0;
}

static void cifs_build_dirent(cifs_connect_p c, struct cifs_dirinfo_s *di, cifs_dirent_p de) {
	cifs_build_stat(di, &de->st);
	if (c->capabilities & CAP_UNICODE) {
		cifs_cp_block(cifs_cp_ucs_to_sys, de->name, NAME_MAX, di->name, di->name_len);
	} else {
		cifs_cp_block(cifs_cp_oem_to_sys, de->name, NAME_MAX, di->name, di->name_len);
	}
}

static int cifs_find_first_req(cifs_connect_p c, const char *path, const char *mask) {
	cifs_trans_req(c, SMBtrans2, NULL, 1, TRANSACT2_FINDFIRST);
    cifs_buf_p b = c->o->b;
    CIFS_BUF_STRUCT(b, cifs_find_first_req_s, f);

    f->search_attributes = 0x37;
    f->search_count = -1;
    f->flags = FLAG_TRANS2_FIND_CLOSE_IF_END;
    f->information_level = SMB_FIND_DIRECTORY_INFO;
    f->search_storage_type = 0;

	if (c->capabilities & CAP_UNICODE) {
		if (path && path[0]) {
            cifs_write_ucs(b, "/");
            cifs_write_ucs(b, path);
		}
		if (mask && mask[0]) {
            cifs_write_ucs(b, "/");
            cifs_write_ucs(b, mask);
		}
        cifs_write_word(b, 0);
		cifs_path_fix_ucs(f->mask);
	} else {
		if (path && path[0]) {
            cifs_write_oem(b, "/");
            cifs_write_oem(b, path);
		}        
		if (mask && mask[0]) {
            cifs_write_oem(b, "/");
            cifs_write_oem(b, mask);
		}
        cifs_write_byte(b, 0);
		cifs_path_fix_oem(f->mask);
	}
    c->o->w->transaction_req.total_param_count = cifs_buf_len(b);
    c->o->w->transaction_req.param_count = cifs_buf_len(b);
	return 0;
}

static int cifs_find_next_req(cifs_connect_p c, int sid) {
    cifs_trans_req(c, SMBtrans2, NULL, 1, TRANSACT2_FINDNEXT);
    cifs_buf_p b = c->o->b;
    CIFS_BUF_STRUCT(b, cifs_find_next_req_s, f);
    f->sid = sid;
    f->search_count = -1;	
    f->information_level = SMB_FIND_DIRECTORY_INFO;
    f->resume_key = 0;
    f->flags = FLAG_TRANS2_FIND_CLOSE_IF_END | FLAG_TRANS2_FIND_CONTINUE;
    cifs_write_byte(b, 0);
    c->o->w->transaction_req.param_count = cifs_buf_len(b);
    c->o->w->transaction_req.total_param_count = cifs_buf_len(b);
    return 0;
}

static int cifs_find_close_req(cifs_connect_p c, int sid) {
    cifs_packet_setup(c->o, SMBnegprot, 2);
    c->o->h->w[0] = sid;
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
    
    CIFS_BUF_STRUCT(d->t.param, cifs_find_first_res_s, ff);
    
	d->end = ff->end_of_search;
	d->sid = ff->sid;
	d->buf = d->t.data;
	d->count = ff->search_count;

    d->path = cifs_buf_new(PATH_MAX + NAME_MAX + 2);

	d->de.path = cifs_buf_cur(d->path);
    cifs_write_str(d->path, path);
    cifs_write_str(d->path, "/");
	d->de.name = cifs_buf_cur(d->path);
	
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

        CIFS_BUF_STRUCT(f->t.param, cifs_find_next_res_s, fn);

		f->end = fn->end_of_search;
		f->count = fn->search_count;
		f->buf = f->t.data;
		
		if (f->count == 0) {
			errno = ENOENT;
			return NULL;
		}
	}
    CIFS_BUF_STRUCT_PTR(f->buf, cifs_dirinfo_s, di);
	cifs_build_dirent(f->c, di, &f->de);
    cifs_buf_inc(f->buf, di->next_entry_offset);
	f->count--;
	if (f->de.st.is_directory && (!strcmp(f->de.name, ".") || !strcmp(f->de.name, ".."))) {
		goto loop;
	}
	return &f->de;
}

int cifs_closedir(cifs_dir_p f) {
	cifs_trans_free(&f->t);
    cifs_buf_free(f->path);
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
    CIFS_BUF_STRUCT(tr.param, cifs_find_first_res_s, ff);
   
	if (ff->search_count != 1) {		
		if (!ff->end_of_search) {
			cifs_find_close_req(c, ff->sid);
			cifs_request(c);
		}
		cifs_trans_free(&tr);
		errno = EMLINK;
		return -1;
	}
    CIFS_BUF_STRUCT(tr.data, cifs_dirinfo_s, di);    
	cifs_build_stat(di, st);
	cifs_trans_free(&tr);
	return 0;
}

