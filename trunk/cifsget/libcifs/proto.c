#include "includes.h"

#include "struct2.h"

time_t cifs_time(int64_t nttime) {
	return (time_t)(((nttime)/10000000) - 11644473600);
}

void cifs_path_fix_oem (char *path) {
	for (char *p = path; *p ; p++) if (*p == '/') *p = '\\';
}

void cifs_path_fix_ucs (char *path) {
	for (uint16_t *p = (uint16_t *)path; *p ; p++) if (*p == '/') *p = '\\';
}

int cifs_negotiate(cifs_connect_p c) {
    cifs_packet_p i = c->i;
    cifs_packet_p o = c->o;
    ZERO_STRUCTP(o->h);
    WORDS_STRUCT(i, cifs_negotiate_res_s, res);
    cifs_packet_setup(o, SMBnegprot, 0);
    strncpy(o->h->magic, "\xFFSMB", 4);
    o->h->flags = FLAG_CANONICAL_PATHNAMES | FLAG_CASELESS_PATHNAMES;
    o->h->flags2 = FLAGS2_LONG_PATH_COMPONENTS | FLAGS2_IS_LONG_NAME;
    o->h->tid = -1;
    cifs_write_oemz(o->b, "\x02NT LM 0.12");

    if (cifs_request(c)) return -1;

    c->session_key = res->session_key;
	
	c->max_buffer_size = res->max_buffer_size;
	if (c->max_buffer_size > CIFS_MAX_BUFFER) c->max_buffer_size = CIFS_MAX_BUFFER;
	
	c->max_raw_size = res->max_raw_size;
	if (c->max_raw_size > CIFS_MAX_RAW) c->max_raw_size = CIFS_MAX_RAW;
	
	c->capabilities = res->capabilities;

	c->time = res->time;
	c->zone = res->zone * 60;

	cifs_log_verbose("server zone: UTC %+d time: %s\n", c->zone/3600, ctime(&c->time));

	//c->capabilities &= !CAP_UNICODE;
	
	if (c->capabilities & CAP_UNICODE) {
        o->h->flags2 |= FLAGS2_UNICODE_STRINGS;
	}
    return 0;
}

int cifs_sessionsetup(cifs_connect_p c) {
    REQUEST_SETUP(SMBsesssetupX, session_setup, 0);
    req->andx.cmd = -1;
    req->max_buffer_size = CIFS_MAX_BUFFER;
    req->max_mpx_count = 1;
    req->session_key = c->session_key;
    req->capabilities = c->capabilities & (CAP_RAW_MODE | CAP_LARGE_FILES | CAP_UNICODE);
	
	if (c->capabilities & CAP_UNICODE) {
        cifs_write_align(o->b, 2);
        cifs_write_ucsz(o->b, "GUEST");
        cifs_write_ucsz(o->b, "");
        cifs_write_ucsz(o->b, "LINUX");
        cifs_write_ucsz(o->b, "LIBCIFS");
	} else {
        cifs_write_oemz(o->b, "GUEST");
        cifs_write_oemz(o->b, "");
        cifs_write_oemz(o->b, "LINUX");
        cifs_write_oemz(o->b, "LIBCIFS");
	}
    
	if (cifs_request(c)) return -1;   
    o->h->uid = c->i->h->uid;
	return 0;
}


int cifs_tree_connect(cifs_connect_p c, const char *tree) {
    REQUEST_SETUP(SMBtconX, tree_connect, 0);
    o->h->tid = -1;
    req->andx.cmd = -1;
	if (c->capabilities & CAP_UNICODE) {
//        cifs_write_align(o->b, 2);
        cifs_write_byte(o->b, 0);
        cifs_write_ucs(o->b, "\\\\");
		cifs_write_ucs(o->b, c->name);
		cifs_write_ucs(o->b, "\\");
		cifs_write_ucsz(o->b,  tree);
	} else {
        cifs_write_oem(o->b, "\\\\");
		cifs_write_oem(o->b, c->name);
		cifs_write_oem(o->b, "\\");
		cifs_write_oemz(o->b,  tree);
	}
    cifs_write_strz(o->b, "?????");
	
	if (cifs_request(c)) return -1;

    o->h->tid = c->i->h->tid;

	return o->h->tid;
}

int cifs_tree_switch(cifs_connect_p c, int tid) {
	int t;
	t = c->o->h->tid;
    c->o->h->tid = tid;
	return t;
}


int cifs_tree_disconnect(cifs_connect_p c, int tid) {
    cifs_packet_setup(c->o, SMBtdis, 0);
    if (tid >= 0) c->o->h->tid = tid;
	if (cifs_request(c)) return -1;
    c->o->h->tid = -1;
	return 0;
}

int cifs_open(cifs_connect_p c, const char *name, int flags) {
    cifs_packet_setup(c->o, SMBopen, 4);

	int mode = 0;	
		
	if (flags & O_RDWR) {
		mode |= OPEN_FLAGS_OPEN_RDWR;
	} else if (flags & O_WRONLY) {
		mode |= OPEN_FLAGS_OPEN_WRITE;
	} else {
		mode |= OPEN_FLAGS_OPEN_READ;
	}

    c->o->h->w[0] = mode;	
    c->o->h->w[1] = 0x37;

    cifs_write_byte(c->o->b, '\x04');
	
	if (c->capabilities & CAP_UNICODE) {
        cifs_write_align(c->o->b, 2);
        cifs_write_ucsz(c->o->b, name);
	} else {
        cifs_write_oem(c->o->b, name);
	}
    cifs_path_fix_ucs(c->o->b->b);
	if (cifs_request(c)) return -1;
	return c->i->h->w[0];
}
/*
int cifs_ntopen(cifs_connect_p c, const char *name, int flags) {
	char *o = c->o, *w;

	SET_PACKET_COMMAND(o, SMBntcreateX);
			
	w = PTR_PACKET_W(o);
    SETLEN_PACKET_W(o, LEN_ONTCREATEX(w));
    SET_ONTCREATEX_ANDX(w, 0xFF);
    SET_ONTCREATEX_RESERVED(w, 0);
    if (flags & O_DIRECTORY) {
        SET_ONTCREATEX_FLAGS(w, NTCREATEX_FLAGS_OPEN_DIRECTORY);
    } else {
        SET_ONTCREATEX_FLAGS(w, 0);
    }
    SET_ONTCREATEX_ROOT_FID(w, 0);
    if (flags & O_RDWR) {
        SET_ONTCREATEX_ACCESS(w, FILE_GENERIC_READ | FILE_GENERIC_WRITE);
	} else if (flags & O_WRONLY) {
        SET_ONTCREATEX_ACCESS(w, FILE_GENERIC_WRITE);
	} else {
        SET_ONTCREATEX_ACCESS(w, FILE_GENERIC_READ);
	}   
    SET_ONTCREATEX_ALLOCATION_SIZE(w, 0);
    SET_ONTCREATEX_EXT_FILE_ATTRIBUTES(w, 0);
    SET_ONTCREATEX_SHARE_ACCESS(w, NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE);  

    if (flags & O_CREAT) {
        if (flags & O_EXCL) {
            SET_ONTCREATEX_DISPOSITION(w, NTCREATEX_DISP_CREATE);
        } else {
            if (flags & O_TRUNC) {
                SET_ONTCREATEX_DISPOSITION(w, NTCREATEX_DISP_OVERWRITE_IF);
            } else {
                SET_ONTCREATEX_DISPOSITION(w, NTCREATEX_DISP_OPEN_IF);
            }
        }
    } else {
        if (flags & O_TRUNC) {
            SET_ONTCREATEX_DISPOSITION(w, NTCREATEX_DISP_OVERWRITE);
        } else {
            SET_ONTCREATEX_DISPOSITION(w, NTCREATEX_DISP_OPEN);
        }
    }
    SET_ONTCREATEX_CREATE_OPTION(w, 0);
    SET_ONTCREATEX_SECUTITY(w, 0);
    SET_ONTCREATEX_SECURITY_FLAGS(w, 0);

    SET_ONTCREATEX_NAME_LENGTH(w, 0);
	
    cifs_cp_tobuf(cifs_)

	if (c->capabilities & CAP_UNICODE) {
		WRITE_ALIGN(p, c->o, 2);
		char *tmp = p;
		WRITE_STRING_UCS(p, c->o_end, name);
		cifs_path_fix_ucs(tmp);
	} else {
		char *tmp = p;
		WRITE_STRING_OEM(p, c->o_end, name);
		cifs_path_fix_ucs(tmp);
	}

	if (cifs_request(c)) return -1;
    
	return 
}*/

int cifs_close(cifs_connect_p c, int fid) {
    cifs_packet_setup(c->o, SMBclose, 6);
    c->o->h->w[0] = fid;
    c->o->h->w[1] = -1;
    c->o->h->w[2] = -1;
	if (cifs_request(c)) return -1;
	return 0;
}


static int cifs_read_andx_send(cifs_connect_p c, int fid, int count, uint64_t offset) {
    REQUEST_SETUP(SMBreadX, readx, 0);
	
	if (count > c->max_buffer_size) count = c->max_buffer_size; //FIXME

    req->andx.cmd = -1;
    req->fid = fid;
    req->offset = offset;
    req->offset_high = offset>>32;
    req->max_count = count;
	return cifs_send(c);
}

static int cifs_read_raw_send(cifs_connect_p c, int fid, int count, uint64_t offset) {
    REQUEST_SETUP(SMBreadbraw, readraw, 0);
	if (count > c->max_raw_size) count = c->max_raw_size;
    req->fid = fid;
    req->max_count = count;
    req->offset = offset;
    req->offset_high = offset>>32;
	return cifs_send(c);
}

static size_t cifs_read_andx_get(cifs_connect_p c, void **buf) {
    int len = c->i->w->readx_res.data_count;
    int off = c->i->w->readx_res.data_offset;
    if (cifs_packet_range(c->i, off, len)) return -1;
    *buf = cifs_packet_ptr(c->i, off);
	return len;
}

static size_t cifs_read_raw_get(cifs_connect_p c, void **buf) {
	return -1;
}

static size_t cifs_read_andx_recv(cifs_connect_p c, void *buf, size_t count) {
	int len;
	void *src;
	if (cifs_recv(c)) return -1;
	len = cifs_read_andx_get(c, &src);
	if (len < 0) return -1;
	if (len > count) {
		errno = ENOMEM;
		return -1;
	}
	memcpy(buf, src, len);
	return len;
}

int cifs_read_send(cifs_connect_p c, int fid, size_t count, uint64_t offset) {
	if (c->capabilities & CAP_RAW_MODE) {
		return cifs_read_raw_send(c, fid, count, offset);
	} else {
		return cifs_read_andx_send(c, fid, count, offset);
	}
}

size_t cifs_read_get(cifs_connect_p c, void **buf) {
	if (c->capabilities & CAP_RAW_MODE) {
		return cifs_read_raw_get(c, buf);
	} else {
		return cifs_read_andx_get(c, buf);
	}
}

size_t cifs_read_recv(cifs_connect_p c, void *buf, size_t count) {
	if (c->capabilities & CAP_RAW_MODE) {
		return cifs_recv_raw(c, buf, count);
	} else {
		return cifs_read_andx_recv(c, buf, count);
	}
}

size_t cifs_read(cifs_connect_p c, int fid, void *buf, size_t count, uint64_t offset) {
	int res;
	if (c->capabilities & CAP_RAW_MODE) {
		if (cifs_read_raw_send(c, fid, count, offset)) return -1;
		res = cifs_recv_raw(c, buf, count);
		if (res != 0) return res;
	}
	if (cifs_read_andx_send(c, fid, count, offset)) return -1;
	return cifs_read_andx_recv(c, buf, count);
}


size_t cifs_write_andx(cifs_connect_p c, int fid, void *buf, size_t count, uint64_t offset) {
    CALL_SETUP(SMBwriteX, writex, 0);

    if (count > c->max_buffer_size) count = c->max_buffer_size; //FIXME
    req->andx.cmd = -1;	
    req->fid = fid;
    req->offset = offset;
    req->offset_high = offset>>32;
    req->data_length = count;
    req->data_offset = cifs_packet_off_cur(o);
    cifs_write_buf(o->b, buf, count);
	
    if (cifs_request(c)) return -1;

    return res->count;
}

size_t cifs_write(cifs_connect_p c, int fid, void *buf, size_t count, uint64_t offset) {
    return cifs_write_andx(c, fid, buf, count, offset);
}

cifs_connect_p cifs_connect(const char *host, int port, const char *name) {
	cifs_connect_p c;
	struct in_addr address;
	int sock;
	if (cifs_resolve(host, &address)) return NULL;
	sock = cifs_connect_sock(&address, port, "", name);
	if (sock < 0) return NULL;
	c = cifs_connect_new(sock, name);
	if (c == NULL) {
		close(sock);
		return NULL;
	}
	if (cifs_negotiate(c) || cifs_sessionsetup(c)) {
		cifs_connect_close(c);
		return NULL;
	}
	return c;
}

cifs_connect_p cifs_connect_tree(const char *host, int port, const char *name, const char *tree) {
	cifs_connect_p c;
	c = cifs_connect(host, port, name);
	if (!c) return NULL;
	if (cifs_tree_connect(c, tree) < 0) {
		cifs_connect_close(c);
		return NULL;
	}
	return c;
}

