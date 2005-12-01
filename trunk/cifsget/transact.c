#include "includes.h"

void smb_trans_req(smb_connect_p c, int command, char *name, int setup_count, ...) {
	char *w, *b, *o = c->o;	
	va_list st;
	SET_PACKET_COMMAND(o, command);
	w = PTR_PACKET_W(o);
	SET_OTRANS_MAX_PARAM_COUNT(w, SMB_TRANS_MAX_PARAM_COUNT);
	SET_OTRANS_MAX_DATA_COUNT(w, SMB_TRANS_MAX_DATA_COUNT);
	SET_OTRANS_MAX_SETUP_COUNT(w, SMB_TRANS_MAX_SETUP_COUNT);
	SET_OTRANS_FLAGS(w, 0);
	SET_OTRANS_TIMEOUT(w, SMB_TRANS_TIMEOUT);
	SET_OTRANS_RESERVED(w, 0);
	SET_OTRANS_SETUP_COUNT(w, setup_count);
	va_start(st, setup_count);
	for (int i = 0 ; i < setup_count ; i++) {
		SET_WORD(PTR_OTRANS_SETUP(w), i*2, va_arg(st, int));
	}
	va_end(st);
	SETLEN_PACKET_W(o, LEN_OTRANS(w));

	b = PTR_PACKET_B(o);
	if (name) {
		PUSH_STRING(b, name);
	}
	
	SET_OTRANS_PARAM_COUNT(w, 0);
	SET_OTRANS_TOTAL_PARAM_COUNT(w, 0);
	SET_OTRANS_PARAM_OFFSET(w, b - PTR_PACKET_MAGIC(o));
	
	SET_OTRANS_DATA_COUNT(w, 0);
	SET_OTRANS_TOTAL_DATA_COUNT(w, 0);
	SET_OTRANS_DATA_OFFSET(w, b - PTR_PACKET_MAGIC(o));
}

int smb_trans_alloc(smb_trans_p t) {
	ZERO_STRUCTP(t);
	t->setup = malloc(SMB_TRANS_MAX_SETUP_COUNT);
	t->param = malloc(SMB_TRANS_MAX_PARAM_COUNT);
	t->data = malloc(SMB_TRANS_MAX_DATA_COUNT);
	if (!t->setup || !t->param || !t->data) return -1;
	return 0;
}

void smb_trans_free(smb_trans_p t) {
	free(t->setup);
	free(t->param);
	free(t->data);
	ZERO_STRUCTP(t);
}

int smb_trans_recv(smb_connect_p c, smb_trans_p t) {
	char *w;
	unsigned int cnt, dis, len, off;

	t->setup_total = SMB_TRANS_MAX_SETUP_COUNT;
	t->param_total = SMB_TRANS_MAX_PARAM_COUNT;
	t->data_total =  SMB_TRANS_MAX_DATA_COUNT;

	t->setup_count = 0;
	t->param_count = 0;
	t->data_count = 0;

	if(smb_recv(c)) return -1;

	do {
		if ((GET_PACKET_COMMAND(c->i) != SMBtrans) &&
				(GET_PACKET_COMMAND(c->i) != SMBtrans2)) {
#ifdef	SMB_DUMP_FATAL
			smb_dump_msg("trans sync error %d %d\n", GET_PACKET_COMMAND(c->i), GET_PACKET_COMMAND(c->o));
			smb_dump_packet("i", c->i);
			smb_dump_packet("o", c->o);
#endif
			
			errno = EIO;
			return -1;
		}

		if (GET_PACKET_STATUS(c->i) != 0) {
			errno = EIO;
			return -1;
		}

		len = LEN_PACKET(c->i) - 4;
		
		w = PTR_PACKET_W(c->i);
		
#ifdef DEBUG
		PRINT_STRUCT(w, ITRANSS);
#endif
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
#ifdef	SMB_DUMP_FATAL
			smb_dump_packet("incorrect transaction", c->i);
			PRINT_STRUCT(w, ITRANSS);
#endif			
			errno = EIO;
			return -1;
		}

		cnt = GET_ITRANSS_TOTAL_DATA_COUNT(w);
		if (cnt <= t->data_total) {
			t->data_total = cnt;
		} else {
#ifdef	SMB_DUMP_FATAL
			smb_dump_packet("incorrect transaction", c->i);
			PRINT_STRUCT(w, ITRANSS);
#endif			
			errno = EIO;
			return -1;
		}		

		cnt = GET_ITRANSS_PARAM_COUNT(w);		
		if (cnt) {
			dis = GET_ITRANSS_PARAM_DISPLACEMENT(w);
			off = GET_ITRANSS_PARAM_OFFSET(w);
			
			if (dis + cnt > t->param_total || off + cnt > len) {
#ifdef	SMB_DUMP_FATAL
				smb_dump_packet("incorrect transaction", c->i);
				PRINT_STRUCT(w, ITRANSS);
#endif
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
#ifdef	SMB_DUMP_FATAL
				smb_dump_packet("incorrect transaction", c->i);
				PRINT_STRUCT(w, ITRANSS);
#endif
				errno = EIO;
				return -1;
			}
			
			memcpy(t->data + dis, PTR_PACKET_MAGIC(c->i) + off, cnt);
			t->data_count += cnt;
		}
		
		if (t->param_count == t->param_total && t->data_count == t->data_total) break;
		
		if(smb_recv_more(c)) return -1;
	} while(1);
	return 0;
}


int smb_trans_request(smb_connect_p c, smb_trans_p t) {
	if (smb_send(c)) return -1;
	if (smb_trans_recv(c, t)) return -1;
	return 0;
}

