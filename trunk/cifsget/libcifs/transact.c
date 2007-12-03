#include "includes.h"

void cifs_log_trans(const char *name, cifs_trans_p t) {
	cifs_log_debug("trans %s setup %d param %d data %d\n", name, cifs_buf_size(t->setup), cifs_buf_size(t->param), cifs_buf_size(t->data));
    cifs_log_buf_debug(t->setup, "setup");
    cifs_log_buf_debug(t->param, "param");
    cifs_log_buf_noisy(t->data, "data");
}

void cifs_trans_req(cifs_connect_p c, int command, char *name, int setup_count, ...) {
    REQUEST_SETUP(command, transaction, setup_count*2);	
	va_list st;
    req->max_param_count = CIFS_TRANS_MAX_PARAM_COUNT;
    req->max_data_count = CIFS_TRANS_MAX_DATA_COUNT;
    req->max_setup_count = CIFS_TRANS_MAX_SETUP_COUNT;
    req->timeout = CIFS_TRANS_TIMEOUT;
    req->setup_count = setup_count;
	
    va_start(st, setup_count);
	for (int i = 0 ; i < setup_count ; i++) {
        req->setup[i] = va_arg(st, int);
	}
	va_end(st);

	if (name) {
		if (c->capabilities & CAP_UNICODE) {
            cifs_write_byte(o->b, 0);
            cifs_write_ucsz(o->b, name);
		} else {
            cifs_write_oemz(o->b, name);
		}
	}

    req->param_count = 0;
    req->total_param_count = 0;
    req->param_offset = cifs_packet_off_cur(o);

    req->data_count = 0;
    req->total_data_count = 0;
    req->data_offset = cifs_packet_off_cur(o);
}

cifs_trans_p cifs_trans_new(void) {
    cifs_trans_p t;
    NEW_STRUCT(t);
    if (t == NULL) {
        return NULL;
    }
    t->setup = cifs_buf_new(CIFS_TRANS_MAX_SETUP_COUNT);
    t->param = cifs_buf_new(CIFS_TRANS_MAX_PARAM_COUNT);
    t->data = cifs_buf_new(CIFS_TRANS_MAX_DATA_COUNT);
    if (t->setup == NULL || t->param == NULL || t->data == NULL) {
        cifs_trans_free(t);
        return NULL;
    }
	return t;
}

void cifs_trans_free(cifs_trans_p t) {
    if (t == NULL) return;
    cifs_buf_free(t->setup);
    cifs_buf_free(t->param);
    cifs_buf_free(t->data); 
    free(t);
}

int cifs_trans_recv(cifs_connect_p c, cifs_trans_p t) {
    int dis, off, cnt;
    WORDS_STRUCT(c->i, cifs_transaction_second_res_s, res);

    cifs_buf_resize(t->setup, -1);
    cifs_buf_resize(t->param, -1);
    cifs_buf_resize(t->data, -1);

    cifs_buf_set(t->setup, 0);
    cifs_buf_set(t->param, 0);
    cifs_buf_set(t->data, 0);

	if(cifs_recv(c)) return -1;

	do {
		if (c->i->h->cmd != SMBtrans && c->i->h->cmd != SMBtrans2) goto err;
    	if (cifs_packet_errno(c->i)) return -1;
        if (res->setup_count * 2 > cifs_buf_left(t->setup)
                || res->total_param_count > cifs_buf_size(t->param) 
                || res->total_data_count > cifs_buf_size(t->data)) goto err;
        
        cifs_buf_resize(t->setup, res->setup_count * 2);
        cifs_write_buf(t->setup, res->setup, res->setup_count * 2);
        cifs_buf_resize(t->param, res->total_param_count);
		cifs_buf_resize(t->data, res->total_data_count);

        if (res->param_count) {
            cnt = res->param_count;
			dis = res->param_displacement;
			off = res->param_offset;			
			if (cifs_packet_range(c->i, off, cnt) || cifs_buf_range(t->param, dis, cnt)) goto err;
            cifs_buf_set(t->param, dis);
            cifs_write_buf(t->param,  cifs_packet_ptr(c->i, off), cnt);
		}

		if (res->data_count) {
            cnt = res->data_count;
			dis = res->data_displacement;
			off = res->data_offset;			
			if (cifs_packet_range(c->i, off, cnt) || cifs_buf_range(t->data, dis, cnt)) goto err;
            cifs_buf_set(t->data, dis);
            cifs_write_buf(t->data,  cifs_packet_ptr(c->i, off), cnt);
		}		
		if (cifs_buf_left(t->param) == 0 && cifs_buf_left(t->data) == 0) break;
		
		if(cifs_recv(c)) return -1;
	} while(1);
    cifs_buf_set(t->setup, 0);
    cifs_buf_set(t->param, 0);
    cifs_buf_set(t->data, 0);
	return 0;
err:
    cifs_log_error("incorrect transaction\n");
    errno = EIO;
    return -1;
}


int cifs_trans_request(cifs_connect_p c, cifs_trans_p t) {
	if (cifs_send(c)) return -1;
	if (cifs_trans_recv(c, t)) return -1;
	return 0;
}

