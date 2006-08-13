#ifndef HUMAN_H
#define HUMAN_H

const char *smb_hsize(uint64_t size, char *buf);

uint64_t smb_decode_hsize(const char *s);

const char *smb_htime(time_t time);

#endif

