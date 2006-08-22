#include "includes.h"

void cifs_log_packet(char *p) {
	cifs_log_debug("%s command %02X E %d_%d WC %d BC %d\n",
			(GET_PACKET_FLAGS(p)&FLAG_REPLY)?"In ":"Out",
			GET_PACKET_COMMAND(p),
			GET_PACKET_ERROR_CLASS(p), GET_PACKET_ERROR_CODE(p),
			GET_PACKET_WC(p), GET_PACKET_BC(p));
	cifs_log_struct_noisy(p, PACKET);
}

int cifs_recv_skip_sock(int sock, int size);

static int cifs_check_packet(char *p, int size) {
	if (size < OFF_PACKET_WC(p) + LEN_PACKET_WC(p)) return -1;
	if (GET_PACKET_MAGIC(p) != CIFS_MAGIC) return -1;
	if (size < OFF_PACKET_BC(p) + LEN_PACKET_BC(p)) return -1;
	if (size < LEN_PACKET(p)) return -1;
	return 0;
}

int cifs_packet_isfail(char *packet) {
	return GET_PACKET_ERROR_CODE(packet)?-1:0;
}

int cifs_packet_errno(char *packet) {
	switch (GET_PACKET_ERROR_CLASS(packet)) {
		case 0:
			return 0;
		case ERRDOS:
			switch (GET_PACKET_ERROR_CODE(packet)) {
				case ERRsuccess:
					return 0;
				case ERRbadfile:
				case ERRbadpath:
				case ERRnosuchshare:
					return ENOENT;
				case ERRnofids:
					return EMFILE;
				case ERRnoaccess:
				case ERRbadaccess:
				case ERRlogonfailure:
					return EACCES;
				case ERRbadfid:
					return EBADF;
			}
		break;
		case ERRSRV:
			switch (GET_PACKET_ERROR_CODE(packet)) {
				case 0:
					return 0;
				case ERRerror:
					return EIO;
				case ERRbadpw:
				case ERRaccess:
					return EACCES;
			}
		break;
	}
	return EIO;
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

int cifs_nbt_session(int sock, const char *local, const char *remote) {
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
}


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
		if (port == 139 && cifs_nbt_session(sock, local_name, remote_name)) goto err;
	} else {
		addr.sin_port =  htons(445);
		cifs_log_verbose("connecting to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
			addr.sin_port =  htons(139);
			cifs_log_verbose("connecting to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) goto err;
			if (cifs_nbt_session(sock, local_name, remote_name)) goto err;
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
	c->i_size = CIFS_MAX_BUFFER + 4;
	c->i = malloc(c->i_size);
	c->i_end = c->i + c->i_size;
	c->o_size = CIFS_MAX_BUFFER + 4;
	c->o = malloc(c->o_size);
	c->o_end = c->o + c->o_size;
	c->sock = sock;
	c->name = strdup(name);
	c->connected = 1;
	return c;
}

void cifs_connect_close(cifs_connect_p c) {
	close(c->sock);
	free(c->name);
	free(c->i);
	free(c->o);	
	free(c);
}

int cifs_connected(cifs_connect_p c) {
	return c->connected;
}

size_t cifs_send_raw(cifs_connect_p c, void *buf, size_t len) {
	int r;
	char *p = buf;
	
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
	int len, r;
	char *p;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
	
	len = LEN_PACKET(c->o);
	SET_PACKET_LENGTH(c->o, len - 4);

	cifs_log_packet(c->o);

	p = c->o;
	while (len) {
		r = send(c->sock, p, len, 0);
		if (r < 0) return -1;		
		len -= r;
		p += r;
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

size_t cifs_recv_raw(cifs_connect_p c, void *buf, size_t len) {
	int size;
	int r, l;
	char *p;
	
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
	int size;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
	
	c->i_len = 4;
	c->i_done = 0;
	
	do {
		size = recv(c->sock, c->i + c->i_done, c->i_len - c->i_done, MSG_WAITALL);
		if (size < 0) return -1;		
		c->i_done += size;
		if (c->i_done == 4 && c->i_len == 4) {
			size = GET_PACKET_LENGTH(c->i);
			if (GET_PACKET_TYPE(c->i)) {
				cifs_recv_skip(c, size);
				c->i_done = 0;
			} else {
				c->i_len += size;
				if (c->i_len > c->i_size) {
					cifs_log_error("cifs_recv: buffer to small %d packet size %d\n", c->i_len, c->i_size);
					cifs_recv_skip(c, size);
					errno = ENOMEM;
					return -1;
				}
			}
		}
	} while (c->i_len != c->i_done);	
	
	if (cifs_check_packet(c->i, c->i_len)) {
		cifs_log_error("incorect packet %d bytes\n", c->i_len);
		cifs_log_hex_noisy(c->i, c->i_len);
		errno = EIO;
		return -1;
	}
	

	cifs_log_packet(c->i);

	return 0;
}

int cifs_request(cifs_connect_p c) {
	if (cifs_send(c)) return -1;
	if (cifs_recv(c)) return -1;
	if (GET_PACKET_COMMAND(c->i) != GET_PACKET_COMMAND(c->o)) {

		cifs_log_error("sync error %d %d\n", GET_PACKET_COMMAND(c->i), GET_PACKET_COMMAND(c->o));
		cifs_log_packet(c->i);
		cifs_log_packet(c->o);
		
		errno = EIO;
		return -1;
	}
	if (cifs_packet_isfail(c->i)) {
		errno = cifs_packet_errno(c->i);
		return -1;
	}
	return 0;
}


int cifs_recv_async(cifs_connect_p c) {
	int size, type;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}	
	
	/* stage1: try recv size field */
	if (c->i_len == c->i_done) {
		c->i_len = 4;
		c->i_done = 0;
	}
	
	if (c->i_done >= 0) {
		/*recv data*/
		size = recv(c->sock, c->i + c->i_done, c->i_len - c->i_done, MSG_DONTWAIT);
	} else {
		/*skip junk*/
		size = -c->i_done;
		if (size > c->i_size) size = c->i_size;
		size = recv(c->sock, c->i, size, MSG_DONTWAIT);
	}
	if (size < 0) return -1;
	c->i_done += size;
	
	/* stage2: recv size finished */
	if (c->i_len == 4 && c->i_done == 4) {
		size = GET_PACKET_LENGTH(c->i);
		type = GET_PACKET_TYPE(c->i);
		if (type) {
			/* skip size bytes */
			c->i_done = -size;
		} else {
			/* recv body */
			c->i_len += size;
			if (c->i_len > c->i_size) {
				cifs_log_error("cifs_recv_async: buffer to small %d packet size %d\n", c->i_len, c->i_size);
				cifs_recv_skip(c, size);
				errno = ENOMEM;
				return -1;
			}
		}
	}
	if (c->i_done == c->i_len) return 0;
	errno = EAGAIN;
	return -1;
}

