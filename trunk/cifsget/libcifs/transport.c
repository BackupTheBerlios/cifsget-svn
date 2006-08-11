#include "includes.h"

#ifdef WINDOWS
#ifndef MSG_WAITALL
#define MSG_WAITALL 0
#endif
#endif

int smb_recv_skip_sock(int sock, int size);

static int smb_check_packet(char *p, int size) {
	if (size < OFF_PACKET_WC(p) + LEN_PACKET_WC(p)) return -1;
	if (GET_PACKET_MAGIC(p) != SMB_MAGIC) return -1;
	if (size < OFF_PACKET_BC(p) + LEN_PACKET_BC(p)) return -1;
	if (size < LEN_PACKET(p)) return -1;
	return 0;
}

char *smb_nbt_name(char *buf, const char *name) {
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

int smb_nbt_session(int sock, const char *local, const char *remote) {
	char b[LEN_NBTSESSION(NULL)];
	char h[LEN_NBTHEADER(NULL)];
	unsigned char code;
	int len, type;
	SET_NBTSESSION_TYPE(b, 0x81);
	SET_NBTSESSION_FLAGS(b, 0);
	SET_NBTSESSION_LENGTH(b, 68);
	SET_NBTSESSION_SRC_TYPE(b, 0x20);
	SET_NBTSESSION_DST_TYPE(b, 0x20);
	smb_nbt_name(PTR_NBTSESSION_SRC(b), local);
	smb_nbt_name(PTR_NBTSESSION_DST(b), remote);
	
	smb_log_struct(b, NBTSESSION);

	
	
	if (send(sock, b, sizeof(b), 0) != sizeof(b)) return -1;
	if (recv(sock, h, sizeof(h), 0) != sizeof(h)) return -1;
	
	smb_log_struct(h, NBTHEADER);

	type = GET_NBTHEADER_TYPE(h);

	len = GET_NBTHEADER_LENGTH(h);

	if (type == 0x82) return 0;

	if (type == 0x83 && len == 1 && recv(sock, &code, 1, 0) == 1) {
		smb_log_error("netbios negative session response 0x%0X code 0x%0X for \"%s\"\n", type, code, remote);
		errno = ENOENT;
		return -1;
	}
	smb_log_error("netbios negative session response 0x%0X for \"%s\"\n", type, remote);
	if (len) smb_recv_skip_sock(sock, len);
	errno = ECONNABORTED;
	return -1;
}


int smb_resolve(const char *host, struct in_addr *addr) {
	struct hostent *hp;
	/* IP */
	if (inet_aton(host, addr)) return 0;
	/* DNS */
	if ((hp = gethostbyname(host))) {
		memcpy(hp->h_addr, addr, sizeof(struct in_addr));
		return 0;
	}
	/* FAILURE */
	errno = ENONET;
	return -1;
}

int smb_connect_raw(smb_connect_p conn, const struct in_addr *address, int port , const char *name) {
	struct sockaddr_in addr;
	if (conn->connected) {
		errno = EALREADY;
		return -1;
	}
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, address, sizeof(struct in_addr));
	if (conn->sock <= 0) {
		conn->sock = socket(PF_INET, SOCK_STREAM, 0);
		if (conn->sock < 0) return -1;
	}
	if (port) {
		addr.sin_port =  htons(port);
		smb_log_verbose("connecting to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		if (connect(conn->sock, (struct sockaddr*)&addr, sizeof(addr))) return -1;
		if (port == 139 && smb_nbt_session(conn->sock, "", name)) return -1;
	} else {
		addr.sin_port =  htons(445);
		smb_log_verbose("connecting to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		if (connect(conn->sock, (struct sockaddr*)&addr, sizeof(addr))) {
			addr.sin_port =  htons(139);
			smb_log_verbose("connecting to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			if (connect(conn->sock, (struct sockaddr*)&addr, sizeof(addr))) return -1;
			if (smb_nbt_session(conn->sock, "", name)) return -1;
		}
	}
	conn->connected = 1;
	conn->i_size = SMB_MAX_BUFFER + 4;
	if (!conn->i) conn->i = malloc(conn->i_size);
	conn->i_end = conn->i + conn->i_size;
	conn->o_size = SMB_MAX_BUFFER + 4;
	if (!conn->o) conn->o = malloc(conn->o_size);
	conn->o_end = conn->o + conn->o_size;
	return 0;
}

int smb_disconnect_raw(smb_connect_p c) {
	assert(c);
	free(c->i);
	free(c->o);
	close(c->sock);
	ZERO_STRUCT(c);
	return 0;
}

int smb_shutdown(smb_connect_p c) {
	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
	c->connected = 0;
	return shutdown(c->sock, 0);
}

int smb_connected(smb_connect_p c) {
	assert(c);
	return c->connected;
}

size_t smb_send_raw(smb_connect_p c, void *buf, size_t len) {
	int r;
	char *p = buf;
	
	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
	
	while (len) {
		r = send(c->sock, p, len, 0);
		if (r < 0) {
			smb_shutdown(c);
			return -1;
		}
		len -= r;
		p += r;
	}
	return 0;
}


int smb_send(smb_connect_p c) {
	int len, r;
	char *p;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
	
	len = LEN_PACKET(c->o);
	SET_PACKET_LENGTH(c->o, len - 4);

	smb_log_packet("send", c->o);

	p = c->o;
	while (len) {
		r = send(c->sock, p, len, 0);
		if (r < 0) {
			smb_shutdown(c);
			return -1;
		}
		len -= r;
		p += r;
	}
	return 0;
}


int smb_recv_skip_sock(int sock, int size) {
	unsigned char buf;
	int res;
	smb_log_debug("skip %d bytes\n", size);
	while (size > 0) {
		res = recv(sock, &buf, 1, MSG_WAITALL);
		if (res == 0) continue;
		if (res < 0) return -1;
		size--;
		smb_log_noisy("%02X ", buf);
		if (size % 16 == 0) smb_log_noisy("\n");
	}	
	return 0;
}

int smb_recv_skip(smb_connect_p c, int size) {
	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
	if (smb_recv_skip_sock(c->sock, size)) {
		smb_shutdown(c);
		return -1;
	}
	return 0;
}

int smb_recv_size(smb_connect_p c) {
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
			if (r < 0) {
				smb_shutdown(c);
				return -1;
			}
			l -= r;
			p += r;
		}
		size = ntohl(size);
		type = size >> 24;
		size &= 0x0000FFFF; // FIXME
		if (type && size) {
			smb_log_debug("skip type: %d size: %d\n", type, size);
			smb_recv_skip(c, size);
		}
	} while (type);
	return size;
}

size_t smb_recv_raw(smb_connect_p c, void *buf, size_t len) {
	int size;
	int r, l;
	char *p;
	
	size = smb_recv_size(c);

	if (size < 0) {
		return -1;
	}
	
	if (size > len) {
		smb_log_error("smb_recv_raw: buffer to small %d - packet size is %d\n", len, size);
		smb_recv_skip(c, size);
		errno = ENOMEM;		
		return -1;
	}
	
	l = size;
	p = buf;
	
	while (l) {
		r = recv(c->sock, p, l, MSG_WAITALL);
		if (r < 0) {
			smb_shutdown(c);
			return -1;
		}
		l -= r;
		p += r;
	}

	smb_log_debug("recv_raw size: %d\n", size);

	return size;
}

int smb_recv(smb_connect_p c) {
	int size;

	if (!c->connected) {
		errno = ENOTCONN;
		return -1;
	}
	
	c->i_len = 4;
	c->i_done = 0;
	
	do {
		size = recv(c->sock, c->i + c->i_done, c->i_len - c->i_done, MSG_WAITALL);
		if (size < 0) {
			smb_shutdown(c);
			return -1;
		}
		c->i_done += size;
		if (c->i_done == 4 && c->i_len == 4) {
			size = GET_PACKET_LENGTH(c->i);
			if (GET_PACKET_TYPE(c->i)) {
				smb_recv_skip(c, size);
				c->i_done = 0;
			} else {
				c->i_len += size;
				if (c->i_len > c->i_size) {
					smb_log_error("smb_recv: buffer to small %d packet size %d\n", c->i_len, c->i_size);
					smb_recv_skip(c, size);
					errno = ENOMEM;
					return -1;
				}
			}
		}
	} while (c->i_len != c->i_done);	
	
	if (smb_check_packet(c->i, c->i_len)) {
		smb_log_error("incorect packet %d bytes\n", c->i_len);
		smb_log_hex_noisy(c->i, c->i_len);
		smb_shutdown(c);
		errno = EIO;
		return -1;
	}
	

	smb_log_packet("recv", c->i);

	return 0;
}


int smb_recv_more(smb_connect_p c) {
	return smb_recv(c);
}

int smb_request(smb_connect_p c) {
	if (smb_send(c)) return -1;
	if (smb_recv(c)) return -1;
	if (GET_PACKET_COMMAND(c->i) != GET_PACKET_COMMAND(c->o)) {

		smb_log_error("sync error %d %d\n", GET_PACKET_COMMAND(c->i), GET_PACKET_COMMAND(c->o));
		smb_log_packet("i", c->i);
		smb_log_packet("o", c->o);


		smb_shutdown(c);
		
		errno = EIO;
		return -1;
	}
	if (GET_PACKET_STATUS(c->i)) {
		errno = EIO;
		return -1;
	}
	return 0;
}


int smb_recv_async(smb_connect_p c) {
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
				smb_log_error("smb_recv_async: buffer to small %d packet size %d\n", c->i_len, c->i_size);
				smb_recv_skip(c, size);
				errno = ENOMEM;
				return -1;
			}
		}
	}
	if (c->i_done == c->i_len) return 0;
	errno = EAGAIN;
	return -1;
}

