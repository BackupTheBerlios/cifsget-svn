#include "includes.h"

int smb_download_mirror(smb_mirror_p src, const char *dst) {
	smb_mirror_p m;
	int work, maxfd, ret, len, tot;
	fd_set fds;
	void *data;
	smb_flow_p flow;

	work = 0;
	for (m = src ; m ; m = m->next) {
		m->conn = smb_connect3(m->uri.host, m->uri.share);
		if (!m->conn) {
			perror(m->uri.host);
			continue;
		}	
		
		if (smb_info(m->conn, m->uri.path, &m->info)) goto err;
		m->fid = smb_open(m->conn, m->uri.path, OPEN_FLAGS_OPEN_READ);
		if (m->fid < 0) goto err;
		m->fd = open(m->uri.file, O_CREAT | O_WRONLY | O_LARGEFILE, 0664);
		if (smb_read_send(m->conn, m->fid, SMB_MAX_RAW, 0)) goto err;
		work++;
		smb_flow_reset(&m->flow);
		continue;
err:		
		smb_disconnect(m->conn);
		m->conn = NULL;
		perror(m->uri.host);
	}
	
	flow = smb_flow_new();
	
	while (work) {
		FD_ZERO(&fds);
		maxfd = 0;
		for (m = src ; m ; m = m->next) if (m->conn) {
			FD_SET(m->conn->sock, &fds);
			if (m->conn->sock > maxfd) maxfd = m->conn->sock;
		}
		ret = select(maxfd+1, &fds, NULL, NULL, NULL);
		tot = 0;
		for (m = src ; m ; m = m->next) if (m->conn) {
			if (FD_ISSET(m->conn->sock, &fds) && !smb_recv_async(m->conn)) {
				len = smb_read_get(m->conn, &data);
				tot += len;
				smb_flow(&m->flow, len);
				write(m->fd, data, len);
				m->offset += len;
				if (m->offset < m->info.file_size) {
					smb_read_send(m->conn, m->fid, SMB_MAX_RAW, m->offset);
				} else {
					close(m->fd);
					smb_disconnect(m->conn);
					m->conn = NULL;
					work--;
				}
			}			
		}
		if (smb_flow(flow, tot)) {
			for (m = src ; m ; m = m->next)printf("%6s/s ", human_file_size(m->flow.speed));
			printf("%6s/s\r", human_file_size(flow->speed));
			fflush(stdout);
		}
	}
	return 0;
}