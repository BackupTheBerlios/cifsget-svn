#ifndef HUMAN_H
#define HUMAN_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

const char *cifs_hsize(uint64_t size, char *buf);

uint64_t cifs_decode_hsize(const char *s);

const char *cifs_htime(time_t time);

#endif

