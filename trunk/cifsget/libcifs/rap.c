#include "includes.h"

struct cifs_enum_s {
	cifs_connect_p c;
	cifs_trans_t t;	
	char *cur;
	int count;
	int type;
	int conv;
};

static char* cifs_rap_begin(cifs_connect_p c, int rap_code, const char *param_dest, const char* data_desc, int info_level) {
	char *p;
	cifs_trans_req(c, SMBtrans, "\\PIPE\\LANMAN", 0);
	p = PTR_OTRANS_PARAM(c->o);	
	WRITE_WORD(p, rap_code);
	WRITE_STRING(p, param_dest);
	WRITE_STRING(p, data_desc);
	WRITE_WORD(p, info_level);
	WRITE_WORD(p, CIFS_TRANS_MAX_DATA_COUNT);
	return p;
}

static void cifs_rap_end(cifs_connect_p c, char *p) {
	char *w, *pp, *o = c->o;
	END_PACKET_B(o, p);
	w = PTR_PACKET_W(o);
	pp = PTR_OTRANS_PARAM(o);
	SET_OTRANS_PARAM_COUNT(w, p - pp);
	SET_OTRANS_TOTAL_PARAM_COUNT(w, p - pp);
}

static cifs_enum_p cifs_rap_enum(cifs_connect_p c, int type) {
	cifs_enum_p e;
	
	NEW_STRUCT(e);
	if (!e)	goto err;	
	if (cifs_trans_alloc(&e->t)) goto err;
	
	e->c = c;
	
	if (cifs_trans_request(c, &e->t)) goto err;

	cifs_log_trans("rapenum", &e->t);
	cifs_log_struct(e->t.param, RAPENUM);

	if (GET_RAPENUM_STATUS(e->t.param)) {
		errno = EIO;
		goto err;
	}
	
	e->cur = e->t.data;
	e->count = GET_RAPENUM_ENTRY_COUNT(e->t.param);
	e->conv = GET_RAPENUM_CONVERT(e->t.param);
	e->type = type;
	
	return e;
	
err:
	cifs_trans_free(&e->t);
	FREE_STRUCT(e);
	return NULL;
}

cifs_enum_p cifs_enum_share(cifs_connect_p c) {
	cifs_rap_end(c, cifs_rap_begin(c, 0, "WrLeh", "B13BWz", 1));
	return cifs_rap_enum(c, CIFS_NODE_SHARE);
}


cifs_enum_p cifs_enum_server(cifs_connect_p c, const char *domain) {
	char *p;	
	p = cifs_rap_begin(c, 104, "WrLehDz", "B16BBDz", 1);
	WRITE_LONG(p, -1);
	WRITE_STRING(p, domain);
	cifs_rap_end(c, p);
	return cifs_rap_enum(c, CIFS_NODE_SERVER);
}


cifs_enum_p cifs_enum_domain(cifs_connect_p c) {
	char *p;	
	p = cifs_rap_begin(c, 104, "WrLehDz", "B16BBDz", 1);
	WRITE_LONG(p, 0x80000000);
	WRITE_STRING(p, "");
	cifs_rap_end(c, p);	
	return cifs_rap_enum(c, CIFS_NODE_DOMAIN);
}

int cifs_enum_count(cifs_enum_p e) {
	return e->count;
}

int cifs_enum_next(cifs_enum_p e, cifs_node_p n) {
	char *comm;
	if (!e->count) return -1;	
	ZERO_STRUCTP(n);
	n->type = e->type;
	switch (e->type) {
		case  CIFS_NODE_SHARE:
			cifs_cp_block(cifs_cp_oem_to_sys, n->name, sizeof(n->name), PTR_SHAREENUM_NAME(e->cur), LEN_SHAREENUM_NAME(e->cur));
			comm = e->t.data + (GET_SHAREENUM_COMMENT(e->cur) & 0x0000FFFF) - e->conv;
			cifs_cp_tobuf(cifs_cp_oem_to_sys, n->comment, sizeof(n->comment), comm);
			n->attributes = GET_SHAREENUM_TYPE(e->cur);
			e->cur += LEN_SHAREENUM(e->cur);
			break;
		case CIFS_NODE_DOMAIN:
		case CIFS_NODE_SERVER:
			cifs_cp_block(cifs_cp_oem_to_sys, n->name, sizeof(n->name), PTR_SERVERENUM_NAME(e->cur), LEN_SERVERENUM_NAME(e->cur));
			comm = e->t.data + (GET_SERVERENUM_COMMENT(e->cur) & 0x0000FFFF) - e->conv;
			cifs_cp_tobuf(cifs_cp_oem_to_sys, n->comment, sizeof(n->comment), comm);
			n->attributes = GET_SERVERENUM_TYPE(e->cur);
			e->cur += LEN_SERVERENUM(base);
			break;
	}
	e->count--;
	return 0;
}

void cifs_enum_close(cifs_enum_p e) {
	cifs_trans_free(&e->t);
	FREE_STRUCT(e);	
}

