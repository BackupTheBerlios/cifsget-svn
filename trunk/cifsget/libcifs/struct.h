#ifndef STRUCT2_H
#define STRUCT2_H

#define PACKED __attribute__((__packed__))

struct cifs_nbt_header_s {
	uint8_t type;
	uint8_t flags;
	uint8_t length[2];
} PACKED;

struct cifs_nbt_session_s {
    struct cifs_nbt_header_s nbt;
	uint8_t dst[34];
	uint8_t src[34];
} PACKED;

struct cifs_header_s {
    struct cifs_nbt_header_s nbt;
    char        magic[4];
    uint8_t     cmd;
    uint8_t     error_class;
    uint8_t     reserved;
    uint16_t    error;
    uint8_t     flags;
    uint16_t    flags2;
    uint16_t    pid_high;
    uint64_t    signature;
    uint16_t    unused;
    uint16_t    tid;
    uint16_t    pid;
    uint16_t    uid;
    uint16_t    mid;
    uint8_t	    wc;
    uint16_t    w[1];
} PACKED;
typedef struct cifs_header_s *cifs_header_p;

/* WORDS STRUCTS */

struct cifs_negotiate_res_s {
    uint16_t    dialect_index;
    uint8_t     security_mode;
    uint16_t    max_mpx_count;
    uint16_t    max_number_vcs;
    uint32_t    max_buffer_size;
    uint32_t    max_raw_size;
    uint32_t    session_key;
    uint32_t    capabilities;
    int64_t     time;
    int16_t     zone;
    uint8_t     encryption_key_length;
} PACKED;

struct cifs_andx_s {
        uint8_t cmd;
        uint8_t reserved;
        uint16_t offset;
} PACKED;

struct cifs_session_setup_req_s {
    struct cifs_andx_s andx;
    uint16_t max_buffer_size;
    uint16_t max_mpx_count;
    uint16_t vc_number;
    uint32_t session_key;
    uint16_t ipwdlen;
    uint16_t pwdlen;
    uint32_t reserved;
    uint32_t capabilities;
} PACKED;

struct cifs_session_setup_res_s {
    struct cifs_andx_s andx;
    uint16_t action;
} PACKED;

struct cifs_tree_connect_req_s {
    struct cifs_andx_s andx;
    uint16_t flags;
    uint16_t pwdlen;
} PACKED;

struct cifs_tree_connect_res_s {
    struct cifs_andx_s andx;
    uint16_t optional_support;
} PACKED;

struct cifs_transaction_req_s {
	uint16_t total_param_count;
	uint16_t total_data_count;
	uint16_t max_param_count;
	uint16_t max_data_count;
	uint16_t max_setup_count;
	uint16_t flags;
	uint32_t timeout;
	uint16_t reserved;
	uint16_t param_count;
	uint16_t param_offset;
	uint16_t data_count;
	uint16_t data_offset;
	uint16_t setup_count;
	uint16_t setup[0];
} PACKED;

struct cifs_transaction_second_req_s {
 	uint16_t total_param_count;
 	uint16_t total_data_count;
 	uint16_t param_count;
 	uint16_t param_offset;
 	uint16_t param_displacement;
 	uint16_t data_count;
 	uint16_t data_offset;
 	uint16_t data_displacement;
 	uint16_t fid;
} PACKED;

struct cifs_transaction_second_res_s {
    uint16_t total_param_count;
	uint16_t total_data_count;
	uint16_t reserved;
	uint16_t param_count;
	uint16_t param_offset;
	uint16_t param_displacement;
	uint16_t data_count;
	uint16_t data_offset;
	uint16_t data_displacement;
	uint16_t setup_count;
	uint16_t setup[0];
} PACKED;

struct cifs_nt_transaction_req_s {
	uint8_t max_setup_count;
	uint16_t reserved;
	uint32_t total_param_count;
	uint32_t total_data_count;
	uint32_t max_param_count;
	uint32_t max_data_count;
	uint32_t param_count;
	uint32_t param_offset;
 	uint32_t data_count;
 	uint32_t data_offset;
 	uint8_t  setup_count;
 	uint16_t function;
 	uint8_t  buffer;
 	uint16_t setup;
} PACKED;

struct 	cifs_readx_req_s {
	struct cifs_andx_s andx;
    uint16_t fid;
    uint32_t offset;
    uint16_t max_count;
    uint16_t min_count;
    uint32_t reserved;
    uint16_t remaining;
    uint32_t offset_high;
} PACKED;

struct 	cifs_readx_res_s {
  	struct cifs_andx_s andx;
	uint16_t remaining;
	uint16_t datacompactionmode;
	uint16_t reserved;
	uint16_t data_count;
	uint16_t data_offset;
	uint16_t reserved1;
	uint16_t reserved2;
	uint16_t reserved3;
	uint16_t reserved4;
	uint16_t reserved5;
} PACKED;

struct cifs_readraw_req_s {
	uint16_t fid;
	uint32_t offset;
	uint16_t max_count;
	uint16_t min_count;
	uint32_t timeout;
	uint16_t reserved;
	uint32_t offset_high;
} PACKED;

struct  cifs_writex_req_s {
    struct cifs_andx_s andx;
    uint16_t fid;
	uint32_t offset;
    uint32_t reserved;
    uint16_t write_mode;
    uint16_t remaining;
    uint16_t data_length_high;
    uint16_t data_length;
    uint16_t data_offset;
    uint32_t offset_high;
} PACKED;

struct cifs_writex_res_s {
    struct cifs_andx_s andx;
    uint16_t count;
    uint16_t remaining;
    uint32_t reserved;
} PACKED;

union cifs_words_u {
        uint16_t w[1];
        struct cifs_andx_s andx;

        struct cifs_negotiate_res_s negotiate_res;

        struct cifs_session_setup_req_s session_setup_req;
        struct cifs_session_setup_res_s session_setup_res;

        struct cifs_tree_connect_req_s tree_connect_req;
        struct cifs_tree_connect_res_s tree_connect_res;

        struct cifs_transaction_req_s transaction_req;
        struct cifs_nt_transaction_req_s nt_transaction_req;

        struct cifs_transaction_second_req_s transaction_second_req;
        struct cifs_transaction_second_res_s transaction_second_res;

        struct 	cifs_readx_res_s readx_res;
        struct 	cifs_readx_req_s readx_req;

        struct 	cifs_writex_res_s writex_res;
        struct 	cifs_writex_req_s writex_req;
} PACKED;
typedef union cifs_words_u *cifs_words_p;

/* TRANSACTIONS STRUCTS */

struct	cifs_find_first_req_s {
	uint16_t search_attributes;
	uint16_t search_count;
	uint16_t flags;
	uint16_t information_level;
	uint32_t search_storage_type;
    char    mask[0];
} PACKED;

struct	cifs_find_first_res_s {
 	uint16_t sid;
 	uint16_t search_count;
 	uint16_t end_of_search;
 	uint16_t ea_error_offset;
 	uint16_t last_name_offset;
} PACKED;


struct cifs_find_next_req_s {
	uint16_t sid;
	uint16_t search_count;
	uint16_t information_level;
	uint32_t resume_key;
	uint16_t flags;
	char mask[0];
} PACKED;

struct cifs_find_next_res_s {
    uint16_t search_count;
	uint16_t end_of_search;
	uint16_t ea_error_offset;
	uint16_t last_name_offset;
} PACKED;


struct  cifs_dirinfo_s {
	uint32_t next_entry_offset;
	uint32_t file_index;
	int64_t creation_time;
	int64_t access_time;
	int64_t write_time;
	int64_t change_time;
	uint64_t file_size;
	uint64_t allocation_size;
	uint32_t attributes;
	uint32_t name_len;
	char name[0];
} PACKED;


struct cifs_rapenum_s {
	uint16_t status;
	uint16_t convert;
	uint16_t entry_count;
	uint16_t avail_count;
} PACKED;

struct cifs_shareenum_s {
	uint8_t name[13];
	uint8_t pad;
	uint16_t type;
	uint32_t comment;
} PACKED;

struct cifs_serverenum_s {
	uint8_t name[16];
	uint8_t major;
	uint8_t minor;
	uint32_t type;
	uint32_t comment;
} PACKED;

#endif
