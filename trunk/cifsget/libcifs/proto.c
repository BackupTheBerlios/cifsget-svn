#include "includes.h"

int cifs_negotiate(cifs_connect_p c) {
    cifs_packet_p i = c->i;
    cifs_packet_p o = c->o;
    ZERO_STRUCTP(o->h);
    WORDS_STRUCT(i, cifs_negotiate_res_s, res);
    cifs_packet_setup(o, SMBnegprot, 0);
    strncpy(o->h->magic, CIFS_MAGIC, 4);
    o->h->flags = FLAG_CANONICAL_PATHNAMES | FLAG_CASELESS_PATHNAMES;
    o->h->flags2 = FLAGS2_LONG_PATH_COMPONENTS | FLAGS2_IS_LONG_NAME;
    o->h->tid = -1;
    cifs_write_strz(o->b, "\x02NT LM 0.12");

    if (cifs_request(c)) return -1;


    c->session_key = res->session_key;	
	c->max_buffer_size = res->max_buffer_size;
	if (c->max_buffer_size > CIFS_MAX_BUFFER) c->max_buffer_size = CIFS_MAX_BUFFER;
	c->max_raw_size = res->max_raw_size;
	if (c->max_raw_size > CIFS_MAX_RAW) c->max_raw_size = CIFS_MAX_RAW;
	
	c->capabilities = res->capabilities;

	c->time = cifs_time(res->time);
	c->zone = res->zone * 60;

    cifs_log_debug("max buffer %d raw %d cap %lX \n", res->max_buffer_size, res->max_raw_size, res->capabilities);
    cifs_log_verbose("server time: UTC %+d %s\n", c->zone/3600, ctime(&c->time));

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
//FIXME:        cifs_write_align(o->b, 2);
//        cifs_write_byte(o->b, 0);
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

int cifs_tree_disconnect(cifs_connect_p c, int tid) {
    cifs_packet_setup(c->o, SMBtdis, 0);
    if (tid >= 0) c->o->h->tid = tid;
	if (cifs_request(c)) return -1;
    c->o->h->tid = -1;
	return 0;
}

int cifs_tree_set(cifs_connect_p c, int tid) {
    if (tid < 0) {
        c->o->h->tid = c->tid;
    } else {
        c->o->h->tid = tid;
    }
	return 0;
}

int cifs_tree_ipc(cifs_connect_p c) {
    if (c->ipc < 0) {
        c->ipc = cifs_tree_connect(c, "IPC$");
        if (c->ipc < 0) return -1;
    } else {
        cifs_tree_set(c, c->ipc);
    }
    return 0;
}
/*
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
        cifs_write_path_ucsz(c->o->b, name);
	} else {
        cifs_write_path_oemz(c->o->b, name);
	}
	if (cifs_request(c)) return -1;
	return c->i->h->w[0];
}*/

//#define FILE_GENERIC_ALL           0x10000000
//#define FILE_GENERIC_EXECUTE       0x20000000
#define GENERIC_WRITE         0x40000000
#define GENERIC_READ          0x80000000

int cifs_open(cifs_connect_p c, const char *name, int flags, cifs_stat_p stat) {
    CALL_SETUP(SMBntcreateX, nt_createx, 0);

    req->andx.cmd = -1;
    if (flags & O_DIRECTORY) {
        req->flags = NTCREATEX_FLAGS_OPEN_DIRECTORY;
    }
    if (flags & O_RDWR) {
        req->access = GENERIC_READ | GENERIC_WRITE;
	} else if (flags & O_WRONLY) {
        req->access = GENERIC_WRITE;
	} else {
        req->access = GENERIC_READ;
	}
    
    req->share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_DELETE;

    if (flags & O_CREAT) {
        if (flags & O_EXCL) {
            req->disposition = NTCREATEX_DISP_CREATE;
        } else {
            if (flags & O_TRUNC) {
                req->disposition = NTCREATEX_DISP_OVERWRITE_IF;
            } else {
                req->disposition = NTCREATEX_DISP_OPEN_IF;
            }
        }
    } else {
        if (flags & O_TRUNC) {
            req->disposition = NTCREATEX_DISP_OVERWRITE;
        } else {
            req->disposition = NTCREATEX_DISP_OPEN;
        }
    }
	
	if (c->capabilities & CAP_UNICODE) {
        cifs_write_byte(o->b, 0);
        cifs_write_path_ucs(o->b, name);
        req->name_length = cifs_buf_len(o->b)-1;
	} else {
        cifs_write_path_oem(o->b, name);
        req->name_length = cifs_buf_len(o->b);
	}    
    if (cifs_request(c)) return -1;
    if (stat != NULL) {
        stat->creation_time = res->creation_time;
        stat->access_time = res->access_time;
        stat->write_time = res->write_time;
        stat->change_time = res->change_time;
        stat->file_size = res->file_size;
        stat->allocation_size = res->allocation_size;
        stat->attributes = res->ext_file_attributes;
    }
    return res->fid;
}

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
    *buf = cifs_packet_ptr(c->i, 0);
    return cifs_packet_size(c->i);
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

cifs_buf_p cifs_write_andx_req(cifs_connect_p c, int fid, uint64_t offset) {
    REQUEST_SETUP(SMBwriteX, writex, 0);
    req->andx.cmd = -1;	
    req->fid = fid;
    req->offset = offset;
    req->offset_high = offset>>32;
    req->data_offset = cifs_packet_off_cur(o);	
    return o->b;    
}

size_t cifs_write_andx_res(cifs_connect_p c) {
    RESPONSE_SETUP(writex);
    return res->count;
}

int cifs_write_andx_send(cifs_connect_p c) {
    c->o->w->writex_req.data_length = cifs_buf_len(c->o->b);
    return cifs_send(c);
}

size_t cifs_write_andx(cifs_connect_p c, int fid, const void *buf, size_t count, uint64_t offset) {
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

size_t cifs_write(cifs_connect_p c, int fid, const void *buf, size_t count, uint64_t offset) {
    return cifs_write_andx(c, fid, buf, count, offset);
}

cifs_connect_p cifs_connect(const char *addr, int port, const char *host, const char *tree) {
	cifs_connect_p c;
	struct in_addr address;
	int sock;
    if (addr == NULL) {
        addr = host;
    }
	if (cifs_resolve(addr, &address)) return NULL;
	sock = cifs_connect_sock(&address, port, "", host);
	if (sock < 0) return NULL;
	c = cifs_connect_new(sock, host);
	if (c == NULL) {
		close(sock);
		return NULL;
	}
	if (cifs_negotiate(c) || cifs_sessionsetup(c)) {
		cifs_connect_close(c);
		return NULL;
	}
    if (tree != NULL) {
        c->tid = cifs_tree_connect(c, tree);
    	if (c->tid < 0) {
	    	cifs_connect_close(c);
		    return NULL;
    	}
    }
	return c;
}

int cifs_mkdir(cifs_connect_p c, const char *path) {
    cifs_packet_setup(c->o, SMBmkdir, 0);
    cifs_write_byte(c->o->b, '\x04');
	if (c->capabilities & CAP_UNICODE) {
        cifs_write_path_ucsz(c->o->b, path);
	} else {
        cifs_write_path_oemz(c->o->b, path);
	}
    if (cifs_request(c)) {
        int e = errno;
        cifs_stat_t st;
        if (cifs_stat(c, path, &st)) {
            errno = e;
            return -1;
        } else {
            if (st.is_directory) {
                errno = 0;
                return 0;
            } else {
                errno = ENOTDIR;
                return -1;
            }
        }
    }
    return 0;
}

int cifs_unlink(cifs_connect_p c, const char *path) {
    cifs_packet_setup(c->o, SMBunlink, 2);
    c->o->h->w[0] = 0x37;
    cifs_write_byte(c->o->b, '\x04');
	if (c->capabilities & CAP_UNICODE) {
        cifs_write_path_ucsz(c->o->b, path);
	} else {
        cifs_write_path_oemz(c->o->b, path);
	}
    return cifs_request(c);
}

int cifs_rmdir(cifs_connect_p c, const char *path) {
    cifs_packet_setup(c->o, SMBrmdir, 0);
    cifs_write_byte(c->o->b, '\x04');
	if (c->capabilities & CAP_UNICODE) {
        cifs_write_path_ucsz(c->o->b, path);
	} else {
        cifs_write_path_oemz(c->o->b, path);
	}
    return cifs_request(c);
}

