#include "includes.h"

cifs_node_p *cifs_scannode(cifs_connect_p c, int type, const char *domain) {
	cifs_trans_p t;
	int count;
    int conv;
    cifs_node_p *nodes = NULL;
    cifs_node_p n;
    char *comm;

    if (cifs_tree_ipc(c)) return NULL;
	cifs_trans_req(c, SMBtrans, "\\PIPE\\LANMAN", 0);
    cifs_buf_p b = c->o->b;
    switch (type) {
        case CIFS_NODE_SHARE:
            cifs_write_word(b, 0);
            cifs_write_strz(b, "WrLeh");
            cifs_write_strz(b, "B13BWz");
            cifs_write_word(b, 1);
            cifs_write_word(b, CIFS_TRANS_MAX_DATA_COUNT);            
            break;
        case CIFS_NODE_SERVER:
            cifs_write_word(b, 104);
            cifs_write_strz(b, "WrLehDz");
            cifs_write_strz(b, "B16BBDz");
            cifs_write_word(b, 1);
            cifs_write_word(b, CIFS_TRANS_MAX_DATA_COUNT);
            cifs_write_long(b, -1);
            cifs_write_strz(b, domain);
            break;
        case CIFS_NODE_DOMAIN:
            cifs_write_word(b, 104);
            cifs_write_strz(b, "WrLehDz");
            cifs_write_strz(b, "B16BBDz");
            cifs_write_word(b, 1);
            cifs_write_word(b, CIFS_TRANS_MAX_DATA_COUNT);
            cifs_write_long(b, 0x80000000);
            cifs_write_byte(b, 0);
            break;
    }
    c->o->w->transaction_req.param_count = cifs_packet_off_cur(c->o) - c->o->w->transaction_req.param_offset;
    c->o->w->transaction_req.total_param_count = c->o->w->transaction_req.param_count;
    t = cifs_trans_new();
	if (t == NULL) goto err;
	
    if (cifs_trans_request(c, t)) goto err;    
	cifs_log_trans("rapenum", t);
    
    struct cifs_rapenum_s *re = cifs_buf_cur(t->param);
	if (re->status) {
		errno = EIO;
		goto err;
	}
	b = t->data;
	count = re->entry_count;
	conv = re->convert;
    nodes = calloc(count+1, sizeof(cifs_node_p));
    if (nodes == NULL) goto err;

    for (int i = 0 ; i < count ; i++) {
        NEW_STRUCT(nodes[i]);
        n = nodes[i];
        n->type = type;
        if (type ==  CIFS_NODE_SHARE) {
            struct cifs_shareenum_s *se = cifs_buf_cur(b);
            cifs_buf_inc(b, sizeof(*se));
            cifs_cp_buf(cifs_cp_oem_to_sys, n->name, sizeof(n->name), (char *)se->name, sizeof(se->name));
            comm = cifs_buf_ptr(t->data, (se->comment & 0x0000FFFF) - conv);
            cifs_cp_buf(cifs_cp_oem_to_sys, n->comment, sizeof(n->comment), comm, strlen(comm));
            n->attributes = se->type;
        } else { // CIFS_NODE_DOMAIN CIFS_NODE_SERVER
            struct cifs_serverenum_s *se = cifs_buf_cur(b);
            cifs_buf_inc(b, sizeof(*se));
            cifs_cp_buf(cifs_cp_oem_to_sys, n->name, sizeof(n->name), (char *)se->name, sizeof(se->name));
            comm = cifs_buf_ptr(t->data, (se->comment & 0x0000FFFF) - conv);
            cifs_cp_buf(cifs_cp_oem_to_sys, n->comment, sizeof(n->comment), comm, strlen(comm));
            n->attributes = se->type;
        }
    }
    nodes[count] = NULL;
    cifs_tree_set(c, -1);
    cifs_trans_free(t);
	return nodes;
err:
    free(nodes);
    cifs_tree_set(c, -1);
	cifs_trans_free(t);
	return NULL;
}

