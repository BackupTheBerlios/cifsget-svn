#include "includes.h"

struct cifs_enum_s {
	cifs_connect_p c;
	cifs_trans_p t;
    cifs_buf_p buf;
	int count;
	int type;
	int conv;
};

static void cifs_rap_begin(cifs_connect_p c, int rap_code, const char *param_dest, const char* data_desc, int info_level) {
	cifs_trans_req(c, SMBtrans, "\\PIPE\\LANMAN", 0);
    cifs_buf_p b = c->o->b;
    cifs_write_word(b, rap_code);
	cifs_write_strz(b, param_dest);
	cifs_write_strz(b, data_desc);
	cifs_write_word(b, info_level);
	cifs_write_word(b, CIFS_TRANS_MAX_DATA_COUNT);
}

static void cifs_rap_end(cifs_connect_p c) {
    c->o->w->transaction_req.param_count = cifs_packet_off_cur(c->o) - c->o->w->transaction_req.param_offset;
    c->o->w->transaction_req.total_param_count = c->o->w->transaction_req.param_count;
}

static cifs_enum_p cifs_rap_enum(cifs_connect_p c, int type) {
	cifs_enum_p e;
	
	NEW_STRUCT(e);
	if (!e)	goto err;	
    e->t = cifs_trans_new();
	if (e->t == NULL) goto err;
	
	e->c = c;

	if (cifs_tree_ipc(c)) goto err;
	if (cifs_trans_request(c, e->t)) goto err;
    cifs_tree_set(c, -1);

	cifs_log_trans("rapenum", e->t);

    CIFS_READ_STRUCT(e->t->param, cifs_rapenum_s, re);
	
	if (re->status) {
		errno = EIO;
		goto err;
	}
	
	e->buf = e->t->data;
	e->count = re->entry_count;
	e->conv = re->convert;
	e->type = type;
	
	return e;
	
err:
	cifs_trans_free(e->t);
	FREE_STRUCT(e);
	return NULL;
}

cifs_enum_p cifs_enum_share(cifs_connect_p c) {
    cifs_rap_begin(c, 0, "WrLeh", "B13BWz", 1);
    cifs_rap_end(c);
    return cifs_rap_enum(c, CIFS_NODE_SHARE);
}


cifs_enum_p cifs_enum_server(cifs_connect_p c, const char *domain) {
	cifs_rap_begin(c, 104, "WrLehDz", "B16BBDz", 1);
    cifs_write_long(c->o->b, -1);
	cifs_write_strz(c->o->b, domain);
	cifs_rap_end(c);
	return cifs_rap_enum(c, CIFS_NODE_SERVER);
}


cifs_enum_p cifs_enum_domain(cifs_connect_p c) {
	cifs_rap_begin(c, 104, "WrLehDz", "B16BBDz", 1);
    cifs_write_long(c->o->b, 0x80000000);
    cifs_write_byte(c->o->b, 0);
	cifs_rap_end(c);
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
	if (e->type ==  CIFS_NODE_SHARE) {
        CIFS_READ_STRUCT(e->buf, cifs_shareenum_s, se);
        cifs_cp_block(cifs_cp_oem_to_sys, n->name, sizeof(n->name), (char *)se->name, sizeof(se->name));
        comm = cifs_buf_ptr(e->t->data, (se->comment & 0x0000FFFF) - e->conv);
        cifs_cp_tobuf(cifs_cp_oem_to_sys, n->comment, sizeof(n->comment), comm);
        n->attributes = se->type;
    } else { // CIFS_NODE_DOMAIN CIFS_NODE_SERVER
        CIFS_READ_STRUCT(e->buf, cifs_serverenum_s, se);
        cifs_cp_block(cifs_cp_oem_to_sys, n->name, sizeof(n->name), (char *)se->name, sizeof(se->name));
        comm = cifs_buf_ptr(e->t->data, (se->comment & 0x0000FFFF) - e->conv);
        cifs_cp_tobuf(cifs_cp_oem_to_sys, n->comment, sizeof(n->comment), comm);
        n->attributes = se->type;
	}
	e->count--;
	return 0;
}

void cifs_enum_close(cifs_enum_p e) {
	cifs_trans_free(e->t);
	FREE_STRUCT(e);	
}

