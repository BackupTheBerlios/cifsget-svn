#include "includes.h"

void cifs_packet_log(cifs_packet_p p) {
	cifs_log_debug("%s command %02X E %d_%d WC %d BC %d\n",
            (p->h->flags & FLAG_REPLY) ?"In ":"Out",
			p->h->cmd,
			p->h->error_class, p->h->error,
			p->h->wc, cifs_buf_size(p->b));
	cifs_log_hex_debug(p->h->w, p->h->wc * 2);
    cifs_log_buf_noisy(p->b, "B");
}

int cifs_recv_skip_sock(int sock, int size);

int cifs_packet_parse(cifs_packet_p packet) {
    int size = cifs_buf_size(packet->buf);
    int wc, bc;
	if (size <  sizeof(struct cifs_header_s)) return -1;
	if (memcmp((unsigned char*)packet->h->magic, "\xFFSMB", 4)) return -1;
    wc = packet->h->wc;
	if (size < sizeof(struct cifs_header_s) + wc*2) return -1;
    bc = packet->h->w[wc];
	if (size != sizeof(struct cifs_header_s) + wc*2 + bc) return -1;
    cifs_buf_setup(packet->b, (char *)packet->h->w + wc + 1, bc);
	return 0;
}

int cifs_packet_unparse(cifs_packet_p packet) {
    packet->b->l = packet->b->p;
    packet->buf->l = packet->b->p;
    int size = cifs_buf_size(packet->buf) - 4;
    packet->h->length[2] = size;
    packet->h->length[1] = size>>8;
    packet->h->w[packet->h->wc] = cifs_buf_len(packet->b);
    return size + 4;
}

int cifs_packet_length(cifs_packet_p packet) {
    return packet->h->length[2] + (packet->h->length[1] << 8);
}

void cifs_packet_setup(cifs_packet_p packet, int cmd, int words_size) {
    cifs_buf_limit(packet->buf, -1);
    packet->h->cmd = cmd;
    int wc = (words_size + 1) / 2;
    packet->h->wc = wc;
    int off = cifs_buf_off(packet->buf, (char *)(packet->h->w+wc+1));
    cifs_buf_setup(packet->b, cifs_buf_ptr(packet->buf, off), cifs_buf_size(packet->buf) - off);
}

int cifs_packet_errno(cifs_packet_p packet) {
    int err = 0;
    if (packet->h->error == 0) return 0;
	switch (packet->h->error_class) {
		case 0:
			return 0;
		case ERRDOS:
			switch (packet->h->error) {                  
				case ERRbadfile:
				case ERRbadpath:
				case ERRnosuchshare:
					err = ENOENT;
                    break;
				case ERRnofids:
					err = EMFILE;
                    break;
				case ERRnoaccess:
				case ERRbadaccess:
				case ERRlogonfailure:
					err = EACCES;
                    break;
				case ERRbadfid:
					err = EBADF;
                    break;
                default:
                    err = EIO;
                    break;
			}
		break;
		case ERRSRV:
			switch (packet->h->error) {
				case ERRerror:
					err = EIO;
                    break;
				case ERRbadpw:
				case ERRaccess:
					err = EACCES;
                    break;
                default:
                    err = EIO;
                    break;
			}
		break;
	}
    if (err) {
        errno = err;
    }
    return err;
}

char *cifs_nbt_name(char *buf, const char *name) {
	int i;
	int c;
	for (i = 0 ; i<16 && name[i] ; i++) {
		c = toupper(name[i]);
		buf[i*2 ]  = 'A' + ((c >> 4) & 0xF);
		buf[i*2+1] = 'A' + (c & 0xF);
	}
	for (; i<16 ; i++) {
		buf[i*2]   = 'C';
		buf[i*2+1] = 'A';
	}
	buf[32] = '\0';
	return buf;
}

/* int cifs_nbt_session(int sock, const char *local, const char *remote) {
	char b[LEN_NBTSESSION(NULL)];
	char h[LEN_NBTHEADER(NULL)];
	unsigned char code;
	int len, type;
	SET_NBTSESSION_TYPE(b, 0x81);
	SET_NBTSESSION_FLAGS(b, 0);
	SET_NBTSESSION_LENGTH(b, 68);
	SET_NBTSESSION_SRC_TYPE(b, 0x20);
	SET_NBTSESSION_DST_TYPE(b, 0x20);
	cifs_nbt_name(PTR_NBTSESSION_SRC(b), local);
	cifs_nbt_name(PTR_NBTSESSION_DST(b), remote);
	
	cifs_log_struct(b, NBTSESSION);

	
	
	if (send(sock, b, sizeof(b), 0) != sizeof(b)) return -1;
	if (recv(sock, h, sizeof(h), 0) != sizeof(h)) return -1;
	
	cifs_log_struct(h, NBTHEADER);

	type = GET_NBTHEADER_TYPE(h);

	len = GET_NBTHEADER_LENGTH(h);

	if (type == 0x82) return 0;

	if (type == 0x83 && len == 1 && recv(sock, &code, 1, 0) == 1) {
		cifs_log_error("netbios negative session response 0x%0X code 0x%0X for \"%s\"\n", type, code, remote);
		errno = ENOENT;
		return -1;
	}
	cifs_log_error("netbios negative session response 0x%0X for \"%s\"\n", type, remote);
	if (len) cifs_recv_skip_sock(sock, len);
	errno = ECONNABORTED;
	return -1;
} */


int cifs_resolve(const char *host, struct in_addr *addr) {
	struct hostent *hp;
	/* IP */
	if (inet_aton(host, addr)) return 0;
	/* DNS */
	if ((hp = gethostbyname(host))) {
		memcpy(addr, hp->h_addr, sizeof(struct in_addr));
		return 0;
	}
	/* FAILURE */
	errno = ENONET;
	return -1;
}

int cifs_connect_sock(const struct in_addr *address, int port , const char *local_name, const char *remote_name) {
	struct sockaddr_in addr;
	int sock;
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, address, sizeof(struct in_addr));
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) return -1;
	if (port) {
		addr.sin_port =  htons(port);
		cifs_log_verbose("connecting to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) goto err;
		//if (port == 139 && cifs_nbt_session(sock, local_name, remote_name)) goto err;
	} else {
		addr.sin_port =  htons(445);
		cifs_log_verbose("connecting to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
			addr.sin_port =  htons(139);
			cifs_log_verbose("connecting to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) goto err;
			//if (cifs_nbt_session(sock, local_name, remote_name)) goto err;
		}
	}
	return sock;
err:
	close(sock);
	return -1;
}

cifs_connect_p cifs_connect_new(int sock, const char *name) {
	cifs_connect_p c;
	NEW_STRUCT(c);
    NEW_STRUCT(c->i);
    NEW_STRUCT(c->o);
    c->i->buf = cifs_buf_new(CIFS_MAX_BUFFER + 4);
    c->i->h = (cifs_header_p) c->i->buf->b;
    c->i->w = (cifs_words_p) c->i->h->w;
    c->i->b = cifs_buf_new(0);

	c->o->buf = cifs_buf_new(CIFS_MAX_BUFFER + 4);
    c->o->h = (struct cifs_header_s*) c->o->buf->b;
    c->o->w = (cifs_words_p) c->o->h->w;
    c->o->b = cifs_buf_new(0);
	c->sock = sock;
	c->name = strdup(name);
	c->connected = 1;
	return c;
}

void cifs_connect_close(cifs_connect_p c) {
	close(c->sock);
	free(c->name);
	free(c);
}

int cifs_connected(cifs_connect_p c) {
	return c->connected;
}

size_t cifs_send_raw(cifs_connect_p c, void *buf, size_t count) {
	int r;
	char *p = buf;
    int len = count;
    	
	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
    	
	while (len) {
		r = send(c->sock, p, len, 0);
		if (r < 0) return -1;
		len -= r;
		p += r;
	}
	return 0;
}

int cifs_send(cifs_connect_p c) {
	int len, res;
    void *p;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}

	len = cifs_packet_unparse(c->o);
    p = cifs_buf_ptr(c->o->buf, 0);
	cifs_packet_log(c->o);

    while (len) {
		res = send(c->sock, p, len, 0);
		if (res < 0) return -1;
		len -= res;
		p += res;
	}
	return 0;
}

int cifs_recv_skip_sock(int sock, int size) {
	unsigned char buf;
	int res;
	cifs_log_debug("skip %d bytes\n", size);
	while (size > 0) {
		res = recv(sock, &buf, 1, MSG_WAITALL);
		if (res == 0) continue;
		if (res < 0) return -1;
		size--;
		cifs_log_noisy("%02X ", buf);
		if (size % 16 == 0) cifs_log_noisy("\n");
	}	
	return 0;
}

int cifs_recv_skip(cifs_connect_p c, int size) {
	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
	if (cifs_recv_skip_sock(c->sock, size)) return -1;	
	return 0;
}

int cifs_recv_size(cifs_connect_p c) {
	uint32_t size;
	char *p;
	int l, r, type;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}

	do {
		p = (char*)&size;
		l = 4;
		while (l) {
			r = recv(c->sock, p, l, MSG_WAITALL);
			if (r < 0) return -1;			
			l -= r;
			p += r;
		}
		size = ntohl(size);
		type = size >> 24;
		size &= 0x0000FFFF; // FIXME
		if (type && size) {
			cifs_log_debug("skip type: %d size: %d\n", type, size);
			cifs_recv_skip(c, size);
		}
	} while (type);
	return size;
}

size_t cifs_recv_raw(cifs_connect_p c, void* buf, size_t len) {
	int size;
	int r, l;
	void *p;
	
	size = cifs_recv_size(c);

	if (size < 0) {
		return -1;
	}
	
	if (size > len) {
		cifs_log_error("cifs_recv_raw: buffer to small %d - packet size is %d\n", len, size);
		cifs_recv_skip(c, size);
		errno = ENOMEM;		
		return -1;
	}
	
	l = size;
	p = buf;
	
	while (l) {
		r = recv(c->sock, p, l, MSG_WAITALL);
		if (r < 0) return -1;		
		l -= r;
		p += r;
	}

	cifs_log_debug("recv_raw size: %d\n", size);

	return size;
}

int cifs_recv(cifs_connect_p c) {
	int res, size;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}

    cifs_buf_p buf = c->i->buf;

    cifs_buf_limit(buf, 4);
    cifs_buf_reset(buf);
    	
	do {
		res = recv(c->sock, cifs_buf_cur(buf), cifs_buf_left(buf), MSG_WAITALL);
		if (res < 0) return -1;
        cifs_buf_inc(buf, res);
		if (cifs_buf_left(buf) == 0 && cifs_buf_len(buf) == 4) {
			size = cifs_packet_length(c->i);
			if (c->i->h->type) {
                // FIXME: call special callback
				cifs_recv_skip(c, size);
                cifs_buf_reset(buf);
			} else {
                size += 4;
				if (cifs_buf_limit(buf, size)) {
					cifs_log_error("cifs_recv: buffer to small: need %d bytes\n", size);
					errno = ENOMEM;
					return -1;
				}
			}
		}
	} while (cifs_buf_left(buf) != 0);

    
	if (cifs_packet_parse(c->i)) {
		cifs_log_error("incorect packet %d bytes\n", cifs_buf_len(buf));
		cifs_log_hex_noisy(buf->b, cifs_buf_len(buf));
		errno = EIO;
		return -1;
	}
	
	cifs_packet_log(c->i);

	return 0;
}

int cifs_request(cifs_connect_p c) {
	if (cifs_send(c)) return -1;
	if (cifs_recv(c)) return -1;
	if (c->i->h->cmd != c->o->h->cmd) {

		cifs_log_error("sync error %d %d\n", c->i->h->cmd, c->o->h->cmd);
		cifs_packet_log(c->i);
		cifs_packet_log(c->o);
		
		errno = EIO;
		return -1;
	}    
	if (cifs_packet_errno(c->i)) {
		return -1;
	}
	return 0;
}


int cifs_recv_async(cifs_connect_p c) {
	int size;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}	
    
    cifs_buf_p buf = c->i->buf;
	
	if (cifs_buf_left(buf) == 0) {
        cifs_buf_limit(buf, 4);
        cifs_buf_reset(buf);
	}

    size = recv(c->sock, cifs_buf_cur(buf), cifs_buf_left(buf), MSG_DONTWAIT);
    if (size < 0) return -1;
    cifs_buf_inc(buf, size);

	
    if (cifs_buf_left(buf) == 0) {
        if (cifs_buf_len(buf) == 4) {
            /* size done */
            size = cifs_packet_length(c->i) + 4;
			if (cifs_buf_limit(buf, size)) {
				cifs_log_error("cifs_recv_async: buffer to small for %d bytes packet\n", size);
				errno = ENOMEM;
				return -1;
			}
        } else {
            if (c->i->h->type) {
                /* drop */
            	errno = EAGAIN;
                return -1;
            } else {
                /* all done */
                return 0;
            }
        }
    }
	errno = EAGAIN;
	return -1;
}

