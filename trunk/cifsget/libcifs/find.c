#include "includes.h"

time_t cifs_time(int64_t nt_time) {
	return (time_t)((nt_time/10000000) - 11644473600);
}

struct cifs_dir_s {
	cifs_connect_p c;
	cifs_trans_p t;
	int sid;
	int end;
    int count;
    cifs_buf_p buf;
    cifs_buf_p path;
	cifs_dirent_t de;
};

static void cifs_build_stat(struct cifs_find_dirinfo_s *di, cifs_stat_p st) {
	st->creation_time = di->creation_time;
	st->access_time = di->access_time;
	st->write_time = di->write_time;
	st->change_time = di->change_time;
	st->file_size = di->file_size;
	st->allocation_size = di->allocation_size;
	st->attributes = di->ext_file_attributes;
	st->is_directory = di->ext_file_attributes & FILE_ATTRIBUTE_DIRECTORY ? 1 : 0;
}

static void cifs_build_dirent(cifs_connect_p c, struct cifs_find_dirinfo_s *di, cifs_dirent_p de) {
	cifs_build_stat(di, &de->st);
	if (c->capabilities & CAP_UNICODE) {
		cifs_cp_buf(cifs_cp_ucs_to_sys, de->name, NAME_MAX, di->name, di->name_length);
	} else {
		cifs_cp_buf(cifs_cp_oem_to_sys, de->name, NAME_MAX, di->name, di->name_length);
	}
}

static int cifs_find_first_req(cifs_connect_p c, const char *path, const char *mask) {
	cifs_trans_req(c, SMBtrans2, NULL, 1, TRANSACT2_FINDFIRST);
    cifs_buf_p b = c->o->b;
    
    struct cifs_find_first_req_s *f= cifs_buf_cur(b);
    cifs_buf_inc(b, sizeof(*f));

    f->search_attributes = 0x37;
    f->search_count = -1;
    f->flags = FLAG_TRANS2_FIND_CLOSE_IF_END;
    f->information_level = SMB_FIND_DIRECTORY_INFO;
    f->search_storage_type = 0;
	if (c->capabilities & CAP_UNICODE) {
        cifs_write_path_ucs(b, path);
        if (mask) {
            cifs_write_ucs(b, "\\");
            cifs_write_ucs(b, mask);
        }
        cifs_write_word(b, 0);
	} else {
        cifs_write_path_oem(b, path);
		if (mask) {
            cifs_write_oem(b, "\\");
            cifs_write_oem(b, mask);
        }
        cifs_write_byte(b, 0);
	}
    c->o->w->transaction_req.total_param_count = cifs_buf_len(b);
    c->o->w->transaction_req.param_count = cifs_buf_len(b);
	return 0;
}

static int cifs_find_next_req(cifs_connect_p c, int sid) {
    cifs_trans_req(c, SMBtrans2, NULL, 1, TRANSACT2_FINDNEXT);
    cifs_buf_p b = c->o->b;
    struct cifs_find_next_req_s *f = cifs_buf_cur(b);
    cifs_buf_inc(b, sizeof(*f));
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

cifs_dir_p cifs_mask(cifs_connect_p c, const char *path, const char *mask) {
	cifs_dir_p d;

	NEW_STRUCT(d);
	
	if (d == NULL) return NULL;

    d->t = cifs_trans_new();
	
	if (d->t == NULL) {
		FREE_STRUCT(d);
		return NULL;
	}
			
	d->c = c;
	
	cifs_find_first_req(c, path, mask);
	
	if (cifs_trans_request(c, d->t)) {
		cifs_trans_free(d->t);
		FREE_STRUCT(d);
		return NULL;
	}

	cifs_log_trans("findfirst", d->t);

    struct cifs_find_first_res_s *ff = cifs_buf_cur(d->t->param);
        
	d->end = ff->end_of_search;
	d->sid = ff->sid;
	d->buf = d->t->data;
	d->count = ff->search_count;

    d->path = cifs_buf_new(PATH_MAX + NAME_MAX + 2);

	d->de.path = cifs_buf_cur(d->path);
    cifs_write_str(d->path, path);
    cifs_write_str(d->path, "/");
	d->de.name = cifs_buf_cur(d->path);
	
	return d;
}

cifs_dir_p cifs_opendir(cifs_connect_p c, const char *path) {
    return cifs_mask(c, path, "*");
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
		if (cifs_trans_recv(f->c, f->t)) return NULL;

		cifs_log_trans("findnext", f->t);

        struct cifs_find_next_res_s *fn = cifs_buf_cur(f->t->param);

		f->end = fn->end_of_search;
		f->count = fn->search_count;
		f->buf = f->t->data;
		
		if (f->count == 0) {
			errno = ENOENT;
			return NULL;
		}
	}
    struct cifs_find_dirinfo_s *di = cifs_buf_cur(f->buf);
	cifs_build_dirent(f->c, di, &f->de);
    cifs_buf_inc(f->buf, di->next_entry_offset);
	f->count--;
	if (f->de.st.is_directory && (!strcmp(f->de.name, ".") || !strcmp(f->de.name, ".."))) {
		goto loop;
	}
	return &f->de;
}

int cifs_closedir(cifs_dir_p f) {
    int res = 0;
	if (!f->end) {
		cifs_find_close_req(f->c, f->sid);
		res = cifs_request(f->c);
	}
	cifs_trans_free(f->t);
    cifs_buf_free(f->path);
  	free(f);
	return res;
}

int cifs_stat(cifs_connect_p c, const char *path, cifs_stat_p st) {
	cifs_trans_p tr = cifs_trans_new();

	if (tr == NULL) return -1;
	cifs_find_first_req(c, path, NULL);	
	if (cifs_trans_request(c, tr)) {
		cifs_trans_free(tr);
		return -1;
	}
	cifs_log_trans("stat", tr);

    struct cifs_find_first_res_s *ff = cifs_buf_cur(tr->param);
	if (ff->search_count != 1) {
		if (!ff->end_of_search) {
			cifs_find_close_req(c, ff->sid);
			cifs_request(c);
		}
		cifs_trans_free(tr);
		errno = EMLINK;
		return -1;
	}
    struct cifs_find_dirinfo_s *di = cifs_buf_cur(tr->data);
	cifs_build_stat(di, st);
	cifs_trans_free(tr);
	return 0;
}

cifs_dirent_p *cifs_scandir(cifs_connect_p c, const char *path) {
    cifs_dir_p dir;
    cifs_dirent_p ent, tmp;
    int size = 16, cnt = 0;
    cifs_dirent_p *nl = NULL;
	dir = cifs_opendir(c, path);
	if (!dir) return NULL;
    nl = calloc(size, sizeof(cifs_dirent_p));
	while ((ent = cifs_readdir(dir))) {
        if (cnt == size) {
            size *= 2;
            nl = realloc(nl, size * sizeof(cifs_dirent_p));
        }
        tmp = (cifs_dirent_p)malloc(sizeof(cifs_dirent_t) + strlen(ent->path) + 1);
        memcpy(tmp, ent, sizeof(cifs_dirent_t));
        strcpy(tmp->buf, ent->path);
        tmp->path = tmp->buf;
        tmp->name = tmp->path + (ent->name - ent->path);
        nl[cnt++] = tmp;
    }
	cifs_closedir(dir);
    nl = realloc(nl, (cnt + 1) * sizeof(cifs_dirent_p));
    nl[cnt] = NULL;
    return nl;
}

