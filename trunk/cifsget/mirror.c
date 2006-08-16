#include "includes.h"

int cifs_download_mirror(cifs_mirror_p src, const char *dst) {
	cifs_mirror_p m;
	int work, maxfd, ret, len, tot;
	fd_set fds;
	void *data;
	cifs_flow_p flow;

	work = 0;
	for (m = src ; m ; m = m->next) {
		m->conn = cifs_connect_uri(&m->uri);
		if (!m->conn) {
			perror(m->uri.name);
			continue;
		}	
		
		if (cifs_info(m->conn, m->uri.path, &m->info)) goto err;
		m->fid = cifs_open(m->conn, m->uri.path, OPEN_FLAGS_OPEN_READ);
		if (m->fid < 0) goto err;
		m->fd = open(m->uri.file, O_CREAT | O_WRONLY | O_LARGEFILE, 0664);
		if (cifs_read_send(m->conn, m->fid, SMB_MAX_RAW, 0)) goto err;
		work++;
		cifs_flow_reset(&m->flow);
		continue;
err:		
		cifs_disconnect(m->conn);
		m->conn = NULL;
		perror(m->uri.name);
	}
	
	flow = cifs_flow_new();
	
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
			if (FD_ISSET(m->conn->sock, &fds) && !cifs_recv_async(m->conn)) {
				len = cifs_read_get(m->conn, &data);
				tot += len;
				cifs_flow(&m->flow, len);
				write(m->fd, data, len);
				m->offset += len;
				if (m->offset < m->info.file_size) {
					cifs_read_send(m->conn, m->fid, SMB_MAX_RAW, m->offset);
				} else {
					close(m->fd);
					cifs_disconnect(m->conn);
					m->conn = NULL;
					work--;
				}
			}			
		}
		if (cifs_flow(flow, tot)) {
			for (m = src ; m ; m = m->next)printf("%6s/s ", human_file_size(m->flow.speed));
			printf("%6s/s\r", human_file_size(flow->speed));
			fflush(stdout);
		}
	}
	return 0;
}
