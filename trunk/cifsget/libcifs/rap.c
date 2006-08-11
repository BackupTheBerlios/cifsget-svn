#include "includes.h"

char* smb_rap_begin(smb_connect_p c, int rap_code, const char *param_dest, const char* data_desc) {
	char *p;
	
	smb_trans_req(c, SMBtrans, "\\PIPE\\LANMAN", 0);

	p = PTR_OTRANS_PARAM(c->o);
	
	WRITE_WORD(p, rap_code);
	WRITE_STRING(p, param_dest);
	WRITE_STRING(p, data_desc);
	WRITE_WORD(p, 1); /* info_level */
	WRITE_WORD(p, SMB_TRANS_MAX_DATA_COUNT);
	
	return p;
}

void smb_rap_end(char *o, char *p) {
	char *w, *pp;
	END_PACKET_B(o, p);
	w = PTR_PACKET_W(o);
	pp = PTR_OTRANS_PARAM(o);
	SET_OTRANS_PARAM_COUNT(w, p - pp);
	SET_OTRANS_TOTAL_PARAM_COUNT(w, p - pp);
}

int smb_shareenum_req(smb_connect_p c) {
	char *p;
	p = smb_rap_begin(c, 0, "WrLeh", "B13BWz");
	smb_rap_end(c->o, p);
	return 0;
}

int smb_serverenum_req(smb_connect_p c, const char *workgroup) {
	char *p;
	p = smb_rap_begin(c, 104, "WrLehDz", "B16BBDz");
	WRITE_LONG(p, -1);
	WRITE_STRING(p, workgroup);
	smb_rap_end(c->o, p);
	return 0;
}

int smb_domainenum_req(smb_connect_p c) {
	char *p;
	p = smb_rap_begin(c, 104, "WrLehDz", "B16BBDz");
	WRITE_LONG(p, 0x80000000);
	WRITE_STRING(p, "");
	smb_rap_end(c->o, p);
	return 0;
}

int smb_share_enum(smb_connect_p c, smb_node_enum_p e) {
	ZERO_STRUCTP(e);
	
	smb_shareenum_req(c);

	if (smb_trans_alloc(&e->t)) return -1;
	
	if (smb_trans_request(c, &e->t)) {
		smb_trans_free(&e->t);
		return -1;
	}


	smb_log_trans("shareenum", &e->t);
	smb_log_struct(e->t.param, RAPENUM);

	
	e->cur = e->t.data;
	e->count = GET_RAPENUM_ENTRY_COUNT(e->t.param);
	e->conv = GET_RAPENUM_CONVERT(e->t.param);
	e->type = SMB_NODE_SHARE;
	
	return 0;
}


int smb_server_enum(smb_connect_p c, smb_node_enum_p e, const char *domain) {
	ZERO_STRUCTP(e);
	
	smb_serverenum_req(c, domain);
	
	if (smb_trans_alloc(&e->t)) return -1;

	if (smb_trans_request(c, &e->t)) {
		smb_trans_free(&e->t);
		return -1;
	}


	smb_log_trans("serverenum", &e->t);
	smb_log_struct(e->t.param, RAPENUM);

	e->cur = e->t.data;
	e->count = GET_RAPENUM_ENTRY_COUNT(e->t.param);
	e->conv = GET_RAPENUM_CONVERT(e->t.param);
	e->type = SMB_NODE_SERVER;
	
	if (!e->count) return 1;
	
	return 0;
}


int smb_domain_enum(smb_connect_p c, smb_node_enum_p e) {
	ZERO_STRUCTP(e);
	
	smb_domainenum_req(c);
	
	if (smb_trans_alloc(&e->t)) return -1;

	if (smb_trans_request(c, &e->t)) {
		smb_trans_free(&e->t);
		return -1;
	}

	smb_log_trans("domainenum", &e->t);
	smb_log_struct(e->t.param, RAPENUM);

	e->cur = e->t.data;
	e->count = GET_RAPENUM_ENTRY_COUNT(e->t.param);
	e->conv = GET_RAPENUM_CONVERT(e->t.param);
	e->type = SMB_NODE_DOMAIN;

	return 0;
}

int smb_node_next(smb_connect_p c, smb_node_enum_p e, smb_node_p n) {
	char *comm;
	if (!e->count) {
		smb_trans_free(&e->t);
		return 1;
	}
	ZERO_STRUCTP(n);
	n->type = e->type;
	if (e->type == SMB_NODE_SHARE) {
		smb_cp_block(smb_cp_oem_to_sys, n->name, sizeof(n->name), PTR_SHAREENUM_NAME(e->cur), LEN_SHAREENUM_NAME(e->cur));
		comm = e->t.data + (GET_SHAREENUM_COMMENT(e->cur) & 0x0000FFFF) - e->conv;
		smb_cp_tobuf(smb_cp_oem_to_sys, n->comment, sizeof(n->comment), comm);
		n->attributes = GET_SHAREENUM_TYPE(e->cur);
		e->cur += LEN_SHAREENUM(e->cur);
	} else {		
		smb_cp_block(smb_cp_oem_to_sys, n->name, sizeof(n->name), PTR_SERVERENUM_NAME(e->cur), LEN_SERVERENUM_NAME(e->cur));
		comm = e->t.data + (GET_SERVERENUM_COMMENT(e->cur) & 0x0000FFFF) - e->conv;
		smb_cp_tobuf(smb_cp_oem_to_sys, n->comment, sizeof(n->comment), comm);
		n->attributes = GET_SERVERENUM_TYPE(e->cur);
		e->cur += LEN_SERVERENUM(base);
	}
	e->count--;
	return 0;
}

