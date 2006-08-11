#ifndef LIBCIFS_INCLUDES_H
#define LIBCIFS_INCLUDES_H

#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <getopt.h>

#ifdef WINDOWS

#include <winsock.h>

#else

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif


#include <sys/types.h>
#include <errno.h>
#include <ctype.h>

#include <dirent.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>


#include "byteorder.h"
#include "smb.h"
#include "trans2.h"

#include "atom.h"
#include "struct.h"

#include "uri.h"

#include "transport.h"
#include "proto.h"
#include "transact.h"
#include "find.h"
#include "rap.h"

#include "debug.h"
#include "codepage.h"
//#include "flow.h"
//#include "mirror.h"
//#include "human.h"

#endif /* LIBCIFS_INCLUDES_H */

