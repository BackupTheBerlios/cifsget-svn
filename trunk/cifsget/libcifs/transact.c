#include "includes.h"

void cifs_trans_req(cifs_connect_p c, int command, char *name, int setup_count, ...) {
	char *w, *b, *o = c->o;	
	va_list st;
	SET_PACKET_COMMAND(o, command);
	w = PTR_PACKET_W(o);
	SET_OTRANS_MAX_PARAM_COUNT(w, CIFS_TRANS_MAX_PARAM_COUNT);
	SET_OTRANS_MAX_DATA_COUNT(w, CIFS_TRANS_MAX_DATA_COUNT);
	SET_OTRANS_MAX_SETUP_COUNT(w, CIFS_TRANS_MAX_SETUP_COUNT);
	SET_OTRANS_FLAGS(w, 0);
	SET_OTRANS_TIMEOUT(w, CIFS_TRANS_TIMEOUT);
	SET_OTRANS_RESERVED(w, 0);
	SET_OTRANS_SETUP_COUNT(w, setup_count);
	va_start(st, setup_count);
	char *s = PTR_OTRANS_SETUP(w);
	for (int i = 0 ; i < setup_count ; i++) {
		int x = va_arg(st, int);
		SET_WORD(s, i*2, x);
	}
	va_end(st);
	SETLEN_PACKET_W(o, LEN_OTRANS(w));

	b = PTR_PACKET_B(o);
	if (name) {
		if (c->capabilities & CAP_UNICODE) {
			WRITE_ALIGN(b,c->o,2);
			WRITE_STRING_UCS(b, c->o_end, name);
		} else {
			WRITE_STRING_OEM(b, c->o_end, name);
		}
	}
	
	SET_OTRANS_PARAM_COUNT(w, 0);
	SET_OTRANS_TOTAL_PARAM_COUNT(w, 0);
	SET_OTRANS_PARAM_OFFSET(w, b - PTR_PACKET_MAGIC(o));
	
	SET_OTRANS_DATA_COUNT(w, 0);
	SET_OTRANS_TOTAL_DATA_COUNT(w, 0);
	SET_OTRANS_DATA_OFFSET(w, b - PTR_PACKET_MAGIC(o));
}

int cifs_trans_alloc(cifs_trans_p t) {
	ZERO_STRUCTP(t);
	t->setup = malloc(CIFS_TRANS_MAX_SETUP_COUNT);
	t->param = malloc(CIFS_TRANS_MAX_PARAM_COUNT);
	t->data = malloc(CIFS_TRANS_MAX_DATA_COUNT);
	if (!t->setup || !t->param || !t->data) return -1;
	return 0;
}

void cifs_trans_free(cifs_trans_p t) {
	free(t->setup);
	free(t->param);
	free(t->data);
	ZERO_STRUCTP(t);
}

int cifs_trans_recv(cifs_connect_p c, cifs_trans_p t) {
	char *w;
	unsigned int cnt, dis, len, off;

	t->setup_total = CIFS_TRANS_MAX_SETUP_COUNT;
	t->param_total = CIFS_TRANS_MAX_PARAM_COUNT;
	t->data_total =  CIFS_TRANS_MAX_DATA_COUNT;

	t->setup_count = 0;
	t->param_count = 0;
	t->data_count = 0;

	if(cifs_recv(c)) return -1;

	do {
		if ((GET_PACKET_COMMAND(c->i) != SMBtrans) &&
				(GET_PACKET_COMMAND(c->i) != SMBtrans2)) {
#ifdef	CIFS_DUMP_FATAL
			cifs_log_msg("trans sync error %d %d\n", GET_PACKET_COMMAND(c->i), GET_PACKET_COMMAND(c->o));
			cifs_log_packet(c->i);
			cifs_log_packet(c->o);
#endif
			
			errno = EIO;
			return -1;
		}

		if (cifs_packet_fail(c->i)) {
			errno = cifs_packet_error(c->i);
			return -1;
		}

		len = LEN_PACKET(c->i) - 4;
		
		w = PTR_PACKET_W(c->i);
		
		cifs_log_struct(w, ITRANSS);

		cnt = GET_ITRANSS_SETUP_COUNT(w) * 2;
		if (cnt <= t->setup_total) {
			t->setup_total = cnt;
			t->setup_count = cnt;
			memcpy(t->setup, PTR_ITRANSS_SETUP(w), cnt);
		} else {
			errno = EIO;
			return -1;
		}
		
		cnt = GET_ITRANSS_TOTAL_PARAM_COUNT(w);
		if (cnt <= t->param_total) {
			t->param_total = cnt;
		} else {
			cifs_log_error("incorrect transaction\n");
			cifs_log_packet(c->i);
			cifs_log_struct(w, ITRANSS);

			errno = EIO;
			return -1;
		}

		cnt = GET_ITRANSS_TOTAL_DATA_COUNT(w);
		if (cnt <= t->data_total) {
			t->data_total = cnt;
		} else {
			cifs_log_error("incorrect transaction\n");
			cifs_log_packet(c->i);
			cifs_log_struct(w, ITRANSS);

			errno = EIO;
			return -1;
		}		

		cnt = GET_ITRANSS_PARAM_COUNT(w);		
		if (cnt) {
			dis = GET_ITRANSS_PARAM_DISPLACEMENT(w);
			off = GET_ITRANSS_PARAM_OFFSET(w);
			
			if (dis + cnt > t->param_total || off + cnt > len) {

				cifs_log_error("incorrect transaction\n");
				cifs_log_packet(c->i);
				cifs_log_struct(w, ITRANSS);

				errno = EIO;
				return -1;
			}
			
			memcpy(t->param + dis, PTR_PACKET_MAGIC(c->i) + off, cnt);
			t->param_count += cnt;
		}

		cnt = GET_ITRANSS_DATA_COUNT(w);
		if (cnt) {
			dis = GET_ITRANSS_DATA_DISPLACEMENT(w);
			off = GET_ITRANSS_DATA_OFFSET(w);
			
			if (dis + cnt > t->data_total || off + cnt > len) {

				cifs_log_error("incorrect transaction\n");
				cifs_log_packet(c->i);
				cifs_log_struct(w, ITRANSS);

				errno = EIO;
				return -1;
			}
			
			memcpy(t->data + dis, PTR_PACKET_MAGIC(c->i) + off, cnt);
			t->data_count += cnt;
		}
		
		if (t->param_count == t->param_total && t->data_count == t->data_total) break;
		
		if(cifs_recv_more(c)) return -1;
	} while(1);
	return 0;
}


int cifs_trans_request(cifs_connect_p c, cifs_trans_p t) {
	cifs_log_struct(PTR_PACKET_W(c->o), OTRANS);
	if (cifs_send(c)) return -1;
	if (cifs_trans_recv(c, t)) return -1;
	return 0;
}

