#ifndef CONFIG_H
#define CONFIG_H

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 22

#define SMB_MAX_PATH 260

#define SMB_TRANS_TIMEOUT 1000

#define SMB_TRANS_MAX_SETUP_COUNT 255
#define SMB_TRANS_MAX_PARAM_COUNT 1024
#define SMB_TRANS_MAX_DATA_COUNT (60*1024)

#define SMB_MAX_BUFFER 65535

#define SMB_MAX_RAW (60*1024)

#define SMB_UTF8_CODEPAGE	"UTF8"
#define SMB_LOCAL_CODEPAGE	"CP1251"
#define SMB_DOS_CODEPAGE	"866"

#ifdef DEBUG
#define SMB_DUMP_PACKET
#else
#define NDEBUG
#endif

#define SMB_DUMP_FATAL

#endif /* CONFIG_H */
