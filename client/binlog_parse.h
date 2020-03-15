#ifndef _BINLOG_PARSE_H__
#define _BINLOG_PARSE_H__

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "table_id.h"
#include "binlog_event.h"
#include <string>
#include <vector>
#include <list>

using namespace binary_log;
using namespace std;

 
/* 4 bytes which all binlogs should begin with */
#define BINLOG_MAGIC        "\xfe\x62\x69\x6e"

typedef list<uint64_t> event_pos_type;

/*basic display struct*/
struct binlog_event_statics_struct
{
  Log_event_type event_type;
  uint32_t event_counts;
  event_pos_type event_pos;
};
typedef binlog_event_statics_struct binlog_event_statics_t;


/*
  The number of types we handle in Format_description_event (UNKNOWN_EVENT
  is not to be handled, it does not exist in binlogs, it does not have a
  format).
*/
static const int LOG_EVENT_TYPES= (ENUM_END_EVENT - 1);

/**
   The lengths for the fixed data part of each event.
   This is an enum that provides post-header lengths for all events.
*/

/**
   The lengths for the fixed data part of each event.
   This is an enum that provides post-header lengths for all events.
*/
enum enum_post_header_length{
  // where 3.23, 4.x and 5.0 agree
  QUERY_HEADER_MINIMAL_LEN= (4 + 4 + 1 + 2),
  // where 5.0 differs: 2 for length of N-bytes vars.
  QUERY_HEADER_LEN=(QUERY_HEADER_MINIMAL_LEN + 2),
  STOP_HEADER_LEN= 0,
  LOAD_HEADER_LEN= (4 + 4 + 4 + 1 +1 + 4),
  START_V3_HEADER_LEN= (2 + ST_SERVER_VER_LEN + 4),
  // this is FROZEN (the Rotate post-header is frozen)
  ROTATE_HEADER_LEN= 8,
  INTVAR_HEADER_LEN= 0,
  CREATE_FILE_HEADER_LEN= 4,
  APPEND_BLOCK_HEADER_LEN= 4,
  EXEC_LOAD_HEADER_LEN= 4,
  DELETE_FILE_HEADER_LEN= 4,
  NEW_LOAD_HEADER_LEN= LOAD_HEADER_LEN,
  RAND_HEADER_LEN= 0,
  USER_VAR_HEADER_LEN= 0,
  FORMAT_DESCRIPTION_HEADER_LEN= (START_V3_HEADER_LEN + 1 + LOG_EVENT_TYPES),
  XID_HEADER_LEN= 0,
  BEGIN_LOAD_QUERY_HEADER_LEN= APPEND_BLOCK_HEADER_LEN,
  ROWS_HEADER_LEN_V1= 8,
  TABLE_MAP_HEADER_LEN= 8,
  EXECUTE_LOAD_QUERY_EXTRA_HEADER_LEN= (4 + 4 + 4 + 1),
  EXECUTE_LOAD_QUERY_HEADER_LEN= (QUERY_HEADER_LEN +\
                                  EXECUTE_LOAD_QUERY_EXTRA_HEADER_LEN),
  INCIDENT_HEADER_LEN= 2,
  HEARTBEAT_HEADER_LEN= 0,
  IGNORABLE_HEADER_LEN= 0,
  ROWS_HEADER_LEN_V2= 10,
  TRANSACTION_CONTEXT_HEADER_LEN= 18,
  VIEW_CHANGE_HEADER_LEN= 52,
  XA_PREPARE_HEADER_LEN= 0
}; // end enum_post_header_length

struct binlog_prs_event_head_struct
{
  //for v1/v3/v4
  struct timeval when;
  Log_event_type event_type;
  unsigned int unmasked_server_id;
  size_t event_len;

  //for v3/v4
  unsigned long long log_pos;
  uint16_t flags;
};
typedef struct binlog_prs_event_head_struct binlog_prs_event_head_t;

int 
binlog_prs_parse_head(const char *buf_, uint16_t version, binlog_prs_event_head_t *head);

// FORMAT_DESCRIPTION EVENT
//FORMAT_DESCRIPTION_EVENT
struct binlog_prs_fmt_desc_event_struct
{
  binlog_prs_event_head_t head;

  //infomation derived from START_EVENT_V3
  //ST_BINLOG_VER_OFFSET
  uint16_t binlog_version;
  //ST_SERVER_VER_OFFSET
  char server_version[ST_SERVER_VER_LEN];
  //ST_CREATED_OFFSET
  time_t created;

  //
  //ST_COMMON_HEADER_LEN_OFFSET
  uint8_t common_header_len;

  /*
   The list of post-headers' lengths followed
   by the checksum alg decription byte
  */
  std::vector<uint8_t> post_header_len;
  //checksum alg
  enum_binlog_checksum_alg checksum_alg;

  //runtime info
  uint8_t number_of_event_types;
};
typedef struct binlog_prs_fmt_desc_event_struct binlog_prs_fmt_desc_event_t;

void binlog_prs_fmt_desc_event_t_init(binlog_prs_fmt_desc_event_t *fmt_desc_event);

int
binlog_prs_parse_fmt_desc_event(const char *buf_, uint32_t event_len,
                                binlog_prs_fmt_desc_event_t *fmt_desc_event);

//GTID EVENT
struct gtid_info
{
  int32_t  rpl_gtid_sidno;
  int64_t  rpl_gtid_gno;
};

struct Uuid
{

   /// Set to all zeros.
  void clear() { memset(bytes, 0, BYTE_LENGTH); }
   /// Copies the given 16-byte data to this UUID.
  void copy_from(const unsigned char *data)
  {
    memcpy(bytes, data, BYTE_LENGTH);
  }
  /// Copies the given UUID object to this UUID.
  void copy_from(const Uuid &data) { copy_from((unsigned char *)data.bytes); }
  /// Copies the given UUID object to this UUID.
  void copy_to(unsigned char *data) const { memcpy(data, bytes,
                                           BYTE_LENGTH); }
  /// Returns true if this UUID is equal the given UUID.
  bool equals(const Uuid &other) const
  { return memcmp(bytes, other.bytes, BYTE_LENGTH) == 0; }
  /**
    Return true if parse() would return succeed, but don't actually
    store the result anywhere.
  */
  static bool is_valid(const char *string);

  /**
    Stores the UUID represented by a string on the form
    XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX in this object.

     @return  0   success.
             >0   failure
  */
  int parse(const char *string);
  /** The number of bytes in the data of a Uuid. */
  static const size_t BYTE_LENGTH= 16;
  /** The data for this Uuid. */
  unsigned char bytes[BYTE_LENGTH];
  /**
    Generates a 36+1 character long representation of this UUID object
    in the given string buffer.

    @retval 36 - the length of the resulting string.
  */
  size_t to_string(char *buf) const;
  /// Convert the given binary buffer to a UUID
  static size_t to_string(const unsigned char* bytes_arg, char *buf);
  void print() const
  {
    char buf[TEXT_LENGTH + 1];
    to_string(buf);
    printf("%s\n", buf);
  }
  /// The number of bytes in the textual representation of a Uuid.
  static const size_t TEXT_LENGTH= 36;
  /// The number of bits in the data of a Uuid.
  static const size_t BIT_LENGTH= 128;
  static const int NUMBER_OF_SECTIONS= 5;
  static const int bytes_per_section[NUMBER_OF_SECTIONS];
  static const int hex_to_byte[256];
};

struct binlog_prs_gtid_event_struct
{
  binlog_prs_event_head_t head;

  bool may_have_sbr_stmts;
  Uuid Uuid_parent_struct;
  gtid_info gtid_info_struct;

  long long int last_committed;
  long long int sequence_number;

  //type anony or gtid
};
typedef struct binlog_prs_gtid_event_struct binlog_prs_gtid_event_t;

void binlog_prs_gtid_event_t_init(binlog_prs_gtid_event_t *gitd_event);


int
binlog_prs_parse_gtid(const char *buf_, uint32_t event_len,
                      uint16_t version, uint8_t common_header_len,
                      uint8_t post_header_len,
                      binlog_prs_gtid_event_t *gtid_event);



//QUERY EVENT


enum Query_event_post_header_offset{
  Q_THREAD_ID_OFFSET= 0,
  Q_EXEC_TIME_OFFSET= 4,
  Q_DB_LEN_OFFSET= 8,
  Q_ERR_CODE_OFFSET= 9,
  Q_STATUS_VARS_LEN_OFFSET= 11,
  Q_DATA_OFFSET= QUERY_HEADER_LEN
};
/* these are codes, not offsets; not more than 256 values (1 byte). */
enum Query_event_status_vars
{
  Q_FLAGS2_CODE= 0,
  Q_SQL_MODE_CODE,
  /*
    Q_CATALOG_CODE is catalog with end zero stored; it is used only by MySQL
    5.0.x where 0<=x<=3. We have to keep it to be able to replicate these
    old masters.
  */
  Q_CATALOG_CODE,
  Q_AUTO_INCREMENT,
  Q_CHARSET_CODE,
  Q_TIME_ZONE_CODE,
  /*
    Q_CATALOG_NZ_CODE is catalog withOUT end zero stored; it is used by MySQL
    5.0.x where x>=4. Saves one byte in every Query_event in binlog,
    compared to Q_CATALOG_CODE. The reason we didn't simply re-use
    Q_CATALOG_CODE is that then a 5.0.3 slave of this 5.0.x (x>=4)
    master would crash (segfault etc) because it would expect a 0 when there
    is none.
  */
  Q_CATALOG_NZ_CODE,
  Q_LC_TIME_NAMES_CODE,
  Q_CHARSET_DATABASE_CODE,
  Q_TABLE_MAP_FOR_UPDATE_CODE,
  Q_MASTER_DATA_WRITTEN_CODE,
  Q_INVOKER,
  /*
    Q_UPDATED_DB_NAMES status variable collects information of accessed
    databases i.e. the total number and the names to be propagated to the
    slave in order to facilitate the parallel applying of the Query events.
  */
  Q_UPDATED_DB_NAMES,
  Q_MICROSECONDS,
  /*
    A old (unused now) code for Query_log_event status similar to G_COMMIT_TS.
  */
  Q_COMMIT_TS,
  /*
    A code for Query_log_event status, similar to G_COMMIT_TS2.
  */
  Q_COMMIT_TS2,
  /*
    The master connection @@session.explicit_defaults_for_timestamp which
    is recorded for queries, CREATE and ALTER table that is defined with
    a TIMESTAMP column, that are dependent on that feature.
    For pre-WL6292 master's the associated with this code value is zero.
  */
  Q_EXPLICIT_DEFAULTS_FOR_TIMESTAMP
};
enum enum_ternary {
  TERNARY_UNSET,
  TERNARY_OFF,
  TERNARY_ON
};
//query event
struct binlog_prs_query_event_struct
{
  binlog_prs_event_head_t head;

  //Run-Time struct info
  uint64_t query_data_written;
  unsigned long data_len;

  //query field info
  uint32_t thread_id;
  uint32_t query_exec_time;
  size_t db_len;
  uint16_t error_code;
  uint16_t status_vars_len;

  uint32_t flags2;
  uint64_t sql_mode;

  size_t catalog_len;                    // <= 255 char; 0 means uninited
  //const char *catalog;
  std::string catalog;

  uint16_t auto_increment_increment, auto_increment_offset;

  char charset[6];

  size_t time_zone_len; /* 0 means uninited */
  //const char *time_zone_str;
  std::string time_zone_str;

  uint16_t lc_time_names_number; /* 0 means en_US */

  uint16_t charset_database_number;

  uint64_t table_map_for_update;

  size_t master_data_written;

  size_t user_len;
  //const char *user;
  std::string user;
  //const char *host;
  std::string host;
  size_t host_len;

  unsigned char mts_accessed_dbs;
  char mts_accessed_db_names[MAX_DBS_IN_EVENT_MTS][NAME_LEN];
  enum_ternary explicit_defaults_ts;
  size_t q_len;
  //const char *query;
  std::string query;
  //const char *db;
  std::string db;
};
typedef struct binlog_prs_query_event_struct binlog_prs_query_event_t;

void binlog_prs_query_event_t_init(binlog_prs_query_event_t *query_event);

int
binlog_prs_parse_query(const char *buf_, uint32_t event_len,
                       uint16_t version, uint8_t common_header_len,
                       uint8_t post_header_len,
                       binlog_prs_query_event_t *query_event);


//TABLE MAP EVENT
typedef uint16_t flag_set;
struct binlog_prs_table_map_event_struct
{
  binlog_prs_event_head_t head;

  Table_id m_table_id;

  flag_set m_flags;

  size_t m_data_size;
  //const unsigned char *m_db;
  std::string m_db;
  size_t m_dblen;
  //const unsigned char *m_tab;
  std::string m_tab;
  size_t m_tbllen;

  unsigned long m_colcnt;
  std::vector<unsigned char> m_coltype;

  unsigned long m_field_metadata_size;
  std::vector<unsigned char> m_field_metadata;        /** field metadata */
  std::vector<unsigned char> m_null_bits;

};
typedef struct binlog_prs_table_map_event_struct binlog_prs_table_map_event_t;

void binlog_parse_table_map_event_t_init(binlog_prs_table_map_event_t *table_map_event);

int
binlog_parse_table_map(const char *buf_, uint32_t event_len,
                       uint16_t version, uint8_t common_header_len,
                       uint8_t post_header_len,
                       binlog_prs_table_map_event_t *table_map_event);

//ROWS EVENT

struct binlog_prs_row_event_struct
{
  binlog_prs_event_head_t head;
  binary_log::Log_event_type m_type;
  uint64_t m_table_id;
  uint16_t m_flags;           /** Flags for row-level events */
  unsigned long m_width;
  uint32_t n_bits_len;
  uint16_t var_header_len;
  std::vector<unsigned char> m_extra_row_data;
  std::vector<uint8_t> columns_before_image;
  std::vector<uint8_t> columns_after_image;
  std::vector<uint8_t> row;

};
typedef struct binlog_prs_row_event_struct binlog_prs_row_event_t;
void binlog_prs_row_event_t_init(binlog_prs_row_event_t *row_event);

// WRITE ROWS EVENT
int
binlog_prs_parse_write_rows(const char *buf_, uint32_t event_len,
                            uint16_t version, uint8_t common_header_len,
                            uint8_t post_header_len,
                            binary_log::Log_event_type type,
                            binlog_prs_row_event_t *row_event);

// UPDATE ROWS EVENT
int
binlog_prs_parse_update_rows(const char *buf_, uint32_t event_len,
                             uint16_t version, uint8_t common_header_len,
                             uint8_t post_header_len,
                             binary_log::Log_event_type type,
                             binlog_prs_row_event_t *row_event);

// DELETE ROWS EVENT
int
binlog_prs_parse_delete_rows(const char *buf_, uint32_t event_len,
                             uint16_t version, uint8_t common_header_len,
                             uint8_t post_header_len,
                             binary_log::Log_event_type type,
                             binlog_prs_row_event_t *row_event);


//XID EVENT
struct binlog_prs_xid_event_struct
{
  binlog_prs_event_head_t head;
  uint64_t xid;
};
typedef binlog_prs_xid_event_struct binlog_prs_xid_event_t;

void binlog_prs_xid_event_t_init(binlog_prs_xid_event_t *xid_event);

int binlog_prs_parse_xid(const char *buf_, uint32_t event_len,
                         uint16_t version, uint8_t common_header_len,
                         uint8_t post_header_len,
                         binlog_prs_xid_event_t *xid_event);

#endif //_BINLOG_PARSE_H__
