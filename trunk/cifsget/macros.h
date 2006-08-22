#ifndef MACROS_H
#define MACROS_H

#include <stdlib.h>
#include <string.h>

#define ZERO_STRUCT(x)  memset((char *)&(x), 0, sizeof(x))
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char*)(x), 0, sizeof(*(x))); } while (0)
#define NEW_STRUCT(x) x = calloc(1, sizeof(*(x)))
#define FREE_STRUCT(x) do { free(x); x = NULL; } while(0)

#endif
