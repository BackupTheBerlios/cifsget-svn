#include "includes.h"

time_t smb_nttime2unix(int64_t nttime) {
	return (time_t)(((nttime)/10000000) - 11644473600);
}

char *smb_nttime2unix_str(int64_t nttime) {
	time_t t = smb_nttime2unix(nttime);
	return ctime(&t);
}

int smb_negotiate(smb_connect_p c) {
	char *o=c->o, *p;

	SET_PACKET_TYPE(o, 0);
	SET_PACKET_ZERO(o, 0);

	SET_PACKET_MAGIC(o, SMB_MAGIC);
	SET_PACKET_COMMAND(o, SMBnegprot);
	SET_PACKET_STATUS(o, 0);
	SET_PACKET_FLAGS(o, FLAG_CANONICAL_PATHNAMES | FLAG_CASELESS_PATHNAMES);
	SET_PACKET_FLAGS2(o, FLAGS2_LONG_PATH_COMPONENTS | FLAGS2_IS_LONG_NAME | FLAGS2_32_BIT_ERROR_CODES);
	SET_PACKET_PIDH(o, 0);
	SET_PACKET_SIGNATURE(o, 0ll);
	SET_PACKET_UNUSED(o, 0);
	SET_PACKET_TID(o, -1);
	SET_PACKET_PID(o, 0);
	SET_PACKET_UID(o, 0);
	SET_PACKET_MID(o, 0);

	SETLEN_PACKET_W(o, 0);
	
	p = PTR_PACKET_B(o);
	PUSH_STRING(p, "\x02NT LM 0.12");
	END_PACKET_B(o, p);
	
	if (smb_request(c)) return -1;
	
	p = GET_PACKET_W(c->i);	
	c->session_key = GET_INEGOT_SESSIONKEY(p);
	
	c->max_buffer_size = GET_INEGOT_MAXBUFFERSIZE(p);
	if (c->max_buffer_size > SMB_MAX_BUFFER) c->max_buffer_size = SMB_MAX_BUFFER;
	
	c->max_raw_size = GET_INEGOT_MAXRAWSIZE(p);
	if (c->max_raw_size > SMB_MAX_RAW) c->max_raw_size = SMB_MAX_RAW;
	
	c->capabilities = GET_INEGOT_CAPABILITIES(p);
	c->server_time_zone = GET_INEGOT_SERVERTIMEZONE(p);
	

	smb_log_struct(p, INEGOT);

	return 0;
}

int smb_sessionsetup(smb_connect_p c) {
	char *o=c->o, *p;
	
	SET_PACKET_COMMAND(o, SMBsesssetupX);
	
	p = GET_PACKET_W(o);
	SETLEN_PACKET_W(o, LEN_OSESSIONSETUP(p));

	SET_OSESSIONSETUP_ANDX(p, 0xFF);
	SET_OSESSIONSETUP_MAXBUFFERSIZE(p, SMB_MAX_BUFFER);
	SET_OSESSIONSETUP_MAXMPXCOUNT(p, 1);
	SET_OSESSIONSETUP_VCNUMBER(p, 0);
	SET_OSESSIONSETUP_SESSIONKEY(p, c->session_key);
	SET_OSESSIONSETUP_IPWDLEN(p, 0);
	SET_OSESSIONSETUP_PWDLEN(p, 0);
	SET_OSESSIONSETUP_RESERVED(p, 0);
	SET_OSESSIONSETUP_CAPABILITIES(p, CAP_STATUS32 |CAP_RAW_MODE|CAP_LARGE_FILES);


	smb_log_struct(p, OSESSIONSETUP);

		
	p = PTR_PACKET_B(o);
	
	PUSH_STRING(p, "GUEST");
	PUSH_STRING(p, "");
	PUSH_STRING(p, "LINUX");
	PUSH_STRING(p, "XSMB");

	END_PACKET_B(o, p);
		
	if (smb_request(c)) return -1;
	

	p = GET_PACKET_W(c->i);
	smb_log_struct(p, ISESSIONSETUP);

	SET_PACKET_UID(c->o, GET_PACKET_UID(c->i));
	return 0;
}


int smb_tree_connect(smb_connect_p c, const char *server, const char *share) {
	char *o=c->o, *p;
	int tid;
	
	SET_PACKET_COMMAND(o, SMBtconX);
	
	SET_PACKET_TID(o, -1);
		
	p = GET_PACKET_W(o);
	SETLEN_PACKET_W(o, LEN_OTREECONNECT(p));
	SET_OTREECONNECT_ANDX(p, 0xFF);
	SET_OTREECONNECT_FLAGS(p, 0);
	SET_OTREECONNECT_PWDLEN(p, 0);


	smb_log_struct(p, OTREECONNECT);

	p = GET_PACKET_B(o);
	PUSH_FORMAT(p, "\\\\%s\\%s", server, share);
	PUSH_STRING(p, "?????");
	END_PACKET_B(o, p);
	
	if (smb_request(c)) return -1;
	
	tid = GET_PACKET_TID(c->i);
	
	SET_PACKET_TID(c->o, tid);
	

	p = GET_PACKET_W(c->i);
	smb_log_struct(p, ITREECONNECT);

	return tid;
}

int smb_tree_switch(smb_connect_p c, int tid) {
	int t;
	t = GET_PACKET_TID(c->i);
	SET_PACKET_TID(c->o, tid);
	return t;
}


int smb_tree_disconnect(smb_connect_p c, int tid) {
	char *o=c->o;

	if (tid >= 0) SET_PACKET_TID(o, tid);
	
	SET_PACKET_COMMAND(o, SMBtdis);
		
	SETLEN_PACKET_W(o, 0);
	SETLEN_PACKET_B(o, 0);
	
	if (smb_request(c)) return -1;
	
	SET_PACKET_TID(o, -1);

	return 0;
}

int smb_open(smb_connect_p c, const char *name, int mode) {
	char *o = c->o, *p;
	
	SET_PACKET_COMMAND(o, SMBopen);
			
	p = PTR_PACKET_W(o);
	PUSH_WORD(p, mode);
	PUSH_WORD(p, 0x37);
	END_PACKET_W(o, p);
	
	p = PTR_PACKET_B(o);
	PUSH_BYTE(p, '\x04');
	PUSH_STRING(p, name);
	END_PACKET_B(o, p);
	
	if (smb_request(c)) return -1;
	
	return GET_WORD(c->i, OFF_PACKET_W(c->i));
}

int smb_close(smb_connect_p c, int fid) {
	char *o = c->o, *w;
	
	if (!c->connected) return -1;
	
	SET_PACKET_COMMAND(o, SMBclose);
	w = PTR_PACKET_W(o);
	SET_OCLOSE_FID(w, fid);
	SET_OCLOSE_LAST_WRITE_TIME(w, -1);
	SETLEN_PACKET_W(o, LEN_OCLOSE(w));
	SETLEN_PACKET_B(o, 0);
	
	if (smb_request(c)) return -1;
	
	return 0;
}


static int smb_read_andx_send(smb_connect_p c, int fid, int count, uint64_t offset) {
	char *o = c->o, *w;
	
	if (count > c->max_buffer_size) count = c->max_buffer_size; //FIXME
	
	SET_PACKET_COMMAND(o, SMBreadX);
	w = PTR_PACKET_W(o);
	SETLEN_PACKET_W(o, LEN_OREADX(w));
	SETLEN_PACKET_B(o, 0);
	SET_OREADX_ANDX(w, 0xFF);
	SET_OREADX_FID(w, fid);
	SET_OREADX_OFFSET(w, offset);
	SET_OREADX_OFFSET_HIGH(w, offset>>32);
	SET_OREADX_MAX_COUNT(w, count);
	SET_OREADX_MIN_COUNT(w, 0);
	SET_OREADX_RESERVED(w, 0);
	SET_OREADX_REMAINING(w, 0);

	smb_log_struct(w, OREADX);
	return smb_send(c);
}

static int smb_read_raw_send(smb_connect_p c, int fid, int count, uint64_t offset) {
	char *o = c->o, *w;
	if (count > c->max_raw_size) count = c->max_raw_size;
	SET_PACKET_COMMAND(o, SMBreadbraw);
	w = PTR_PACKET_W(o);	
	SETLEN_PACKET_W(o, LEN_OREADRAW(w));
	SETLEN_PACKET_B(o, 0);
	SET_OREADRAW_FID(w, fid);
	SET_OREADRAW_MAX_COUNT(w, count);
	SET_OREADRAW_MIN_COUNT(w, 0);
	SET_OREADRAW_TIMEOUT(w, 0);
	SET_OREADRAW_RESERVED(w, 0);
	SET_OREADRAW_OFFSET(w, offset);
	SET_OREADRAW_OFFSET_HIGH(w, offset>>32);

	smb_log_struct(w, OREADRAW);
	return smb_send(c);
}

static size_t smb_read_andx_get(smb_connect_p c, void **buf) {
	char *w;
	int len, off;
	w = PTR_PACKET_W(c->i);

	smb_log_struct(w, IREADX);

	len = GET_IREADX_DATA_COUNT(w);
	off = GET_IREADX_DATA_OFFSET(w);
	*buf = PTR_PACKET_MAGIC(c->i) + off;
	return len;
}

static size_t smb_read_raw_get(smb_connect_p c, void **buf) {
	int len;
	len = GET_PACKET_LENGTH(c->i);
	*buf = PTR_PACKET_MAGIC(c->i);
	return len;
}

static size_t smb_read_andx_recv(smb_connect_p c, void *buf, size_t count) {
	int len;
	void *src;
	if (smb_recv(c)) return -1;
	len = smb_read_andx_get(c, &src);
	if (len < 0) return -1;
	if (len > count) {
		errno = ENOMEM;
		return -1;
	}
	memcpy(buf, src, len);
	return len;
}

int smb_read_send(smb_connect_p c, int fid, size_t count, uint64_t offset) {
	if (c->capabilities & CAP_RAW_MODE) {
		return smb_read_raw_send(c, fid, count, offset);
	} else {
		return smb_read_andx_send(c, fid, count, offset);
	}
}

size_t smb_read_get(smb_connect_p c, void **buf) {
	if (c->capabilities & CAP_RAW_MODE) {
		return smb_read_raw_get(c, buf);
	} else {
		return smb_read_andx_get(c, buf);
	}
}

size_t smb_read_recv(smb_connect_p c, void *buf, size_t count) {
	if (c->capabilities & CAP_RAW_MODE) {
		return smb_recv_raw(c, buf, count);
	} else {
		return smb_read_andx_recv(c, buf, count);
	}
}

size_t smb_read(smb_connect_p c, int fid, void *buf, size_t count, uint64_t offset) {
	int res;
	if (c->capabilities & CAP_RAW_MODE) {
		if (smb_read_raw_send(c, fid, count, offset)) return -1;
		res = smb_recv_raw(c, buf, count);
		if (res != 0) return res;
	}
	if (smb_read_andx_send(c, fid, count, offset)) return -1;
	return smb_read_andx_recv(c, buf, count);
}

smb_connect_p smb_connect2(const char *server) {
	smb_connect_p c;
	c = smb_connect(server);
	if (!c) return NULL;
	if (smb_negotiate(c) || smb_sessionsetup(c)) {
		smb_log_error("connection to %s failed: %s\n", server, strerror(errno));
		smb_disconnect(c);
		return NULL;
	}
	return c;
}

smb_connect_p smb_connect3(const char *server, const char *share) {
	smb_connect_p c;
	c = smb_connect2(server);
	if (!c) return NULL;
	if ( smb_tree_connect(c, server, share) < 0) {
		smb_log_error("connection to \\\\%s\\%s failed: %s\n", server, share, strerror(errno));
		smb_disconnect(c);
		return NULL;
	}
	return c;
}

