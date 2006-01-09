#include "includes.h"

#ifdef WINDOWS
#ifndef MSG_WAITALL
#define MSG_WAITALL 0
#endif
#endif

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

int smb_nbt_session(int sock, const char *name) {
	char b[LEN_NBTSESSION(NULL)];
	char h[LEN_NBTHEADER(NULL)];
	SET_NBTSESSION_TYPE(b, 0x81);
	SET_NBTSESSION_FLAGS(b, 0);
	SET_NBTSESSION_LENGTH(b, 68);
	SET_NBTSESSION_SRC_TYPE(b, 0x20);
	SET_NBTSESSION_DST_TYPE(b, 0x20);
	smb_nbt_name(PTR_NBTSESSION_SRC(b), "LOCALHOST"); // $)
	smb_nbt_name(PTR_NBTSESSION_DST(b), name);
#ifdef DEBUG
	PRINT_STRUCT(b, NBTSESSION);
#endif
	if (send(sock, b, sizeof(b), 0) != sizeof(b)) return -1;
	if (recv(sock, h, sizeof(h), 0) != sizeof(h)) return -1;
#ifdef DEBUG
	PRINT_STRUCT(h, NBTHEADER);
	unsigned char buf;
	int i;	
	i = GET_NBTHEADER_LENGTH(h);
	while(i--) {
		if (recv(sock, &buf, 1, 0) != 1) break;
		printf("%02X", buf);
	}
#endif
	if (GET_NBTHEADER_TYPE(h) != 0x82) return -1;
	return 0;
}

smb_connect_p smb_connect(const char *server) {
	struct sockaddr_in addr;
	struct hostent *hp;
	int sock;
	smb_connect_p c;

	ZERO_STRUCT(addr);
	if ((addr.sin_addr.s_addr = inet_addr(server)) == INADDR_NONE) {
		hp = gethostbyname(server);
		if (!hp) {
			errno = ENOENT;
			return NULL;
		}
		memcpy(&addr.sin_addr, hp->h_addr, sizeof(struct in_addr));
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(445);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) return NULL;
	
	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
		addr.sin_port = htons(139);
		if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) 
				|| smb_nbt_session(sock, server)) {
			close(sock);
			errno = ECONNREFUSED;
			return NULL;
		}
	}

	NEW_STRUCT(c);
	
	c->connected = 1;
	c->sock = sock;
	c->i_size = SMB_MAX_BUFFER + 4;
	c->i = malloc(c->i_size);
	c->o = malloc(SMB_MAX_BUFFER + 4);

	return c;
}

int smb_disconnect(smb_connect_p c) {
	assert(c);
	free(c->i);
	free(c->o);
	close(c->sock);
	free(c);
	return 0;
}

int smb_connected(smb_connect_p c) {
	assert(c);
	return c->connected;
}

size_t smb_send_raw(smb_connect_p c, void *buf, size_t len) {
	int r;
	char *p = buf;
	while (len) {
		r = send(c->sock, p, len, 0);
		if (r < 0) {
			c->connected = 0;
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
	
	len = LEN_PACKET(c->o);
	SET_PACKET_LENGTH(c->o, len - 4);
	
#ifdef SMB_DUMP_PACKET
	smb_dump_packet("send", c->o);
#endif
	p = c->o;
	while (len) {
		r = send(c->sock, p, len, 0);
		if (r < 0) {
			c->connected = 0;
			return -1;
		}
		len -= r;
		p += r;
	}
	return 0;
}

int smb_recv_skip(smb_connect_p c, int size) {
	unsigned char buf; // %)
	for (int i = 0 ; i < size ; i++) {
		if (recv(c->sock, &buf, 1, 0) != 1) {
			c->connected = 0;
			return -1;
		}
#ifdef DEBUG
		printf("%02X", buf);
#endif
	}
#ifdef DEBUG
	printf("\n");
#endif
	return 0;
}

int smb_recv_size(smb_connect_p c) {
	uint32_t size;
	char *p;
	int l, r, type;
	do {
		p = (char*)&size;
		l = 4;
		while (l) {
			r = recv(c->sock, p, l, MSG_WAITALL);
			if (r < 0) {
				c->connected = 0;
				return -1;
			}
			l -= r;
			p += r;
		}
		size = ntohl(size);
		type = size >> 24;
		size &= 0x0000FFFF; // FIXME
		if (type && size) {
#ifdef DEBUG
			smb_dump_msg("skip\ttype: %d size: %d\n", type, size);
#endif
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
		smb_dump_msg("smb_recv_raw: buffer to small %d packet size %d\n", len, size);
		smb_recv_skip(c, size);
		errno = ENOMEM;		
		return -1;
	}
	
	l = size;
	p = buf;
	
	while (l) {
		r = recv(c->sock, p, l, MSG_WAITALL);
		if (r < 0) {
			c->connected = 0;
			return -1;
		}
		l -= r;
		p += r;
	}
#ifdef SMB_DUMP_PACKET
	smb_dump_msg("recv_raw size: %d\n", size);
#endif	
	return size;
}

int smb_recv(smb_connect_p c) {
	int size;

	c->i_len = 4;
	c->i_done = 0;
	
	do {
		size = recv(c->sock, c->i + c->i_done, c->i_len - c->i_done, MSG_WAITALL);
		if (size < 0) {
			c->connected = 0;
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
					smb_recv_skip(c, size);
					errno = ENOMEM;
					return -1;
				}
			}
		}
	} while (c->i_len != c->i_done);	
	
	if (smb_check_packet(c->i, c->i_len)) {
#ifdef SMB_DUMP_FATAL
		smb_dump_buf("incorect packet", c->i, c->i_len);
#endif
		errno = EIO;
		return -1;
	}
	
#ifdef SMB_DUMP_PACKET
	smb_dump_packet("recv", c->i);
#endif
	return 0;
}


int smb_recv_more(smb_connect_p c) {
	return smb_recv(c);
}

int smb_request(smb_connect_p c) {
	if (smb_send(c)) return -1;
	if (smb_recv(c)) return -1;
	if (GET_PACKET_COMMAND(c->i) != GET_PACKET_COMMAND(c->o)) {
#ifdef SMB_DUMP_FATAL
		smb_dump_msg("sync error %d %d\n", GET_PACKET_COMMAND(c->i), GET_PACKET_COMMAND(c->o));
		smb_dump_packet("i", c->i);
		smb_dump_packet("o", c->o);
#endif
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
	
	/* stage1: try recv size field */
	if (c->i_len == c->i_done) {
		c->i_len = 4;
		c->i_done = 0;
	}
	
	if (c->i_done > 0) {
		size = recv(c->sock, c->i + c->i_done, c->i_len - c->i_done, MSG_DONTWAIT);
	} else {
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
				errno = ENOMEM;
				return -1;
			}
		}
	}

	if (c->i_done == c->i_len) return 0;
	
	errno = EAGAIN;
	return -1;	
}

