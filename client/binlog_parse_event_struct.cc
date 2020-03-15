#include "binlog_parse.h"


const unsigned char prs_checksum_version_split[3]= {5, 6, 1};
const unsigned long prs_checksum_version_product=
(prs_checksum_version_split[0] * 256 + prs_checksum_version_split[1]) * 256 +
prs_checksum_version_split[2];

enum_binlog_checksum_alg
prs_get_checksum_alg(const char *buf, unsigned long len)
{
  BAPI_ASSERT(buf[EVENT_TYPE_OFFSET] == FORMAT_DESCRIPTION_EVENT);

  char version[ST_SERVER_VER_LEN];
  memcpy(version, buf +
      buf[LOG_EVENT_MINIMAL_HEADER_LEN + ST_COMMON_HEADER_LEN_OFFSET]
      + ST_SERVER_VER_OFFSET, ST_SERVER_VER_LEN);
  version[ST_SERVER_VER_LEN - 1] = 0;

  unsigned char version_split[3];
  enum_binlog_checksum_alg ret;
  do_server_version_split(version, version_split);
  if (version_product(version_split) < prs_checksum_version_product)
    ret = BINLOG_CHECKSUM_ALG_UNDEF;
  else
    ret = static_cast<enum_binlog_checksum_alg>(*(buf + len -
        BINLOG_CHECKSUM_LEN -
        BINLOG_CHECKSUM_ALG_DESC_LEN));
  BAPI_ASSERT(ret == BINLOG_CHECKSUM_ALG_OFF ||
      ret == BINLOG_CHECKSUM_ALG_UNDEF ||
      ret == BINLOG_CHECKSUM_ALG_CRC32);
  return ret;
}

int
binlog_prs_parse_head(const char *buf_, uint16_t version, binlog_prs_event_head_t *head)
{
  const char *buf = buf_;

  //timestamp
  uint32_t tmp_sec =0 ;
  memcpy(&tmp_sec, buf, sizeof(tmp_sec));
  head->when.tv_sec = le32toh(tmp_sec);
  head->when.tv_usec = 0;

  //event type
  head->event_type = static_cast<Log_event_type>(buf[EVENT_TYPE_OFFSET]);

  //server id
  unsigned int unmasked_server_id;
  memcpy(&unmasked_server_id,
         buf + SERVER_ID_OFFSET, sizeof(unmasked_server_id));
  head->unmasked_server_id = le32toh(unmasked_server_id);

  //event len
  size_t event_len = 0;
  memcpy(&event_len, buf + EVENT_LEN_OFFSET, 4);
  head->event_len = le64toh(event_len);

  //next position
  unsigned long long log_pos =0;
  memcpy(&log_pos, buf + LOG_POS_OFFSET, 4);
  head->log_pos = le64toh(log_pos);

  //flag
  uint16_t flags = 0;
  memcpy(&flags, buf + FLAGS_OFFSET, sizeof(flags));
  head->flags = le16toh(flags);

  BAPI_ASSERT(head->event_type < ENUM_END_EVENT
                  || head->flags & LOG_EVENT_IGNORABLE_F);

  //LOG_EVENT_HEADER_LEN
  return LOG_EVENT_HEADER_LEN;
}

//FORMAT_DESCRIPTION_EVENT

void binlog_prs_fmt_desc_event_t_init(binlog_prs_fmt_desc_event_t 
                                      *fmt_desc_event)
{
  memset(fmt_desc_event, 0, sizeof(binlog_prs_event_head_t));
  fmt_desc_event->binlog_version = 0;
  fmt_desc_event->server_version[0] = '\0';
  //ST_CREATED_OFFSET
  memset(&(fmt_desc_event->created), 0, sizeof(fmt_desc_event->created));
  fmt_desc_event->common_header_len = 0;
  fmt_desc_event->post_header_len.clear();
  fmt_desc_event->checksum_alg = BINLOG_CHECKSUM_ALG_OFF;
  fmt_desc_event->number_of_event_types = 0;
}

int
binlog_prs_parse_fmt_desc_event(const char *buf_, uint32_t event_len,
                                binlog_prs_fmt_desc_event_t *fmt_desc_event)
{
  enum_binlog_checksum_alg  alg;
  alg = prs_get_checksum_alg(buf_, event_len);
  if (alg == binary_log::BINLOG_CHECKSUM_ALG_CRC32)
    event_len= event_len - BINLOG_CHECKSUM_LEN;
  //FORMAT_DESCRIPTION_EVENT introduce in 5.0.0 as part of version 4
  int r = binlog_prs_parse_head(buf_, 4, &fmt_desc_event->head);
  if (r < 0)
    return -1;

  //START_EVENT_V3 part
  const char *buf = buf_ + LOG_EVENT_MINIMAL_HEADER_LEN;
  //binlog version
  uint16_t binlog_version;
  memcpy(&binlog_version, buf + ST_BINLOG_VER_OFFSET, 2);
  fmt_desc_event->binlog_version = le16toh(binlog_version);
  //server version
  memcpy(fmt_desc_event->server_version,
         buf + ST_SERVER_VER_OFFSET, ST_SERVER_VER_LEN);
  fmt_desc_event->server_version[ST_SERVER_VER_LEN - 1] = 0;
  if (!(fmt_desc_event->server_version[0] != 0)) //sanity check
    return -1;  //in panic
  //created
  time_t created = 0;
  memcpy(&created, buf + ST_CREATED_OFFSET, 4);
  fmt_desc_event->created = le64toh(created);

  //FORMAT_DESCRIPTION_EVENT
  //common head length
  uint8_t common_header_len;
  common_header_len = buf[ST_COMMON_HEADER_LEN_OFFSET];
  if (common_header_len < OLD_HEADER_LEN) //sanity check
    return -1;
  fmt_desc_event->common_header_len = common_header_len;
  //runtime info
  fmt_desc_event->number_of_event_types =
  event_len - (LOG_EVENT_MINIMAL_HEADER_LEN + ST_COMMON_HEADER_LEN_OFFSET + 1);

  const uint8_t *ubuf = reinterpret_cast<const uint8_t *>(buf);
  fmt_desc_event->
  post_header_len.insert(fmt_desc_event->post_header_len.begin(),
                         ubuf + ST_COMMON_HEADER_LEN_OFFSET + 1,
                         (ubuf + ST_COMMON_HEADER_LEN_OFFSET + 1 +
                          fmt_desc_event->number_of_event_types));

  //server_version_split.check this variable usage
  unsigned char version_split[ST_SERVER_VER_SPLIT_LEN];
  //calc_server_version_split();
  do_server_version_split(fmt_desc_event->server_version, version_split);

  unsigned long ver_calc;
  ver_calc = version_product(version_split);
  if (ver_calc >= prs_checksum_version_product)
  {
    fmt_desc_event->number_of_event_types -= BINLOG_CHECKSUM_ALG_DESC_LEN;
    // const char *post_header = buf_ + ST_COMMON_HEADER_LEN_OFFSET + 1;
    fmt_desc_event->checksum_alg = (enum_binlog_checksum_alg)
    fmt_desc_event->post_header_len[fmt_desc_event->number_of_event_types];
  }
  else
  {
    fmt_desc_event->checksum_alg = BINLOG_CHECKSUM_ALG_UNDEF;
  }
  assert(fmt_desc_event->post_header_len.empty() != true);
  return 0; 
}

//GTID EVENT
void binlog_prs_gtid_event_t_init(binlog_prs_gtid_event_t *gtid_event)
{
  memset(gtid_event, 0, sizeof(binlog_prs_gtid_event_t));
}

static const char FLAG_MAY_HAVE_SBR= 1;
//copied from "class Gtid_event"
static const int ENCODED_FLAG_LENGTH = 1;
static const int ENCODED_SID_LENGTH = 16;// Uuid::BYTE_LENGTH;
static const int ENCODED_GNO_LENGTH = 8;

static const int LOGICAL_TIMESTAMP_TYPECODE_LENGTH = 1;
static const int LOGICAL_TIMESTAMP_LENGTH = 16;
static const int LOGICAL_TIMESTAMP_TYPECODE = 2;

int
binlog_prs_parse_gtid(const char *buf_, uint32_t event_len,
                      uint16_t version, uint8_t common_header_len,
                      uint8_t post_header_len,
                      binlog_prs_gtid_event_t *gtid_event)
{
  int r = binlog_prs_parse_head(buf_, version, &gtid_event->head);
  if (r < 0)     //sanity check
    return -1;

  char const *ptr_buffer = buf_ + LOG_EVENT_MINIMAL_HEADER_LEN;

  //gtid flags
  unsigned char gtid_flags = *ptr_buffer;
  gtid_event->may_have_sbr_stmts = gtid_flags & FLAG_MAY_HAVE_SBR;
  ptr_buffer += ENCODED_FLAG_LENGTH;

  //ENCODED SID
  memcpy(gtid_event->Uuid_parent_struct.bytes,
         (const unsigned char *) ptr_buffer, gtid_event->Uuid_parent_struct.BYTE_LENGTH);
  ptr_buffer += ENCODED_SID_LENGTH;

  //ENCODED GNO
  gtid_event->gtid_info_struct.rpl_gtid_sidno = -1;
  int64_t rpl_gtid_gno;
  memcpy(&rpl_gtid_gno, ptr_buffer, sizeof(rpl_gtid_gno));
  gtid_event->gtid_info_struct.rpl_gtid_gno = le64toh(rpl_gtid_gno);
  ptr_buffer += ENCODED_GNO_LENGTH;

  //
  /*
    Fetch the logical clocks. Check the length before reading, to
    avoid out of buffer reads.
  */
  if (ptr_buffer + LOGICAL_TIMESTAMP_TYPECODE_LENGTH +
      LOGICAL_TIMESTAMP_LENGTH <= buf_ + event_len &&
      *ptr_buffer == LOGICAL_TIMESTAMP_TYPECODE)
  {
    long long int last_committed;
    long long int sequence_number;

    ptr_buffer += LOGICAL_TIMESTAMP_TYPECODE_LENGTH;
    memcpy(&last_committed, ptr_buffer, sizeof(last_committed));
    gtid_event->last_committed = (int64_t) le64toh(last_committed);
    memcpy(&sequence_number, ptr_buffer + 8, sizeof(sequence_number));
    gtid_event->sequence_number = (int64_t) le64toh(sequence_number);
    ptr_buffer += LOGICAL_TIMESTAMP_LENGTH;
  }

  return 0;
}


// QUERY EVENT


void binlog_prs_query_event_t_init(binlog_prs_query_event_t *query_event)
{
  memset(query_event, 0, sizeof(binlog_prs_event_head_t));
  query_event->query_data_written = 0;
  query_event->data_len = 0;
  query_event->thread_id = 0;
  query_event->query_exec_time = 0;
  query_event->db_len = 0;
  query_event->error_code = 0;
  query_event->status_vars_len = 0;
  query_event->flags2 = 0;
  query_event->sql_mode = 0;
  query_event->catalog_len = 0;
  query_event->auto_increment_increment = 0;
  query_event->auto_increment_offset = 0;
  query_event->time_zone_len = 0;
  query_event->lc_time_names_number = 0;
  query_event->charset_database_number = 0;
  query_event->table_map_for_update = 0;
  query_event->master_data_written = 0;
  query_event->user_len = 0;
  query_event->host_len = 0;
  query_event->mts_accessed_dbs = 0;
  query_event->q_len = 0;

}

int
binlog_prs_parse_query(const char *buf_, uint32_t event_len,
                       uint16_t version, uint8_t common_header_len,
                       uint8_t post_header_len,
                       binlog_prs_query_event_t *query_event)
{
  int r = binlog_prs_parse_head(buf_, version, &query_event->head);
  if (r < 0)     //sanity check
    return -1;
  
  if (event_len < (common_header_len + post_header_len))  //sanity check
    return -1;
  
  const char *buf = buf_ + LOG_EVENT_MINIMAL_HEADER_LEN;

  query_event->query_data_written = 0;
  query_event->data_len = event_len - (common_header_len + post_header_len);

  uint32_t thread_id;
  memcpy(&thread_id, buf + Q_THREAD_ID_OFFSET, sizeof(thread_id));
  query_event->thread_id = thread_id = le32toh(thread_id);
  uint32_t query_exec_time;
  memcpy(&query_exec_time, buf + Q_EXEC_TIME_OFFSET, sizeof(query_exec_time));
  query_event->query_exec_time = le32toh(query_exec_time);
  query_event->db_len = (unsigned char) buf[Q_DB_LEN_OFFSET];

  uint16_t error_code;
  memcpy(&error_code, buf + Q_ERR_CODE_OFFSET, sizeof(error_code));
  query_event->error_code = le16toh(error_code);

  uint32_t tmp;
  tmp = post_header_len - QUERY_HEADER_MINIMAL_LEN;
  if (tmp)
  {
    uint16_t status_vars_len;
    memcpy(&status_vars_len, buf + Q_STATUS_VARS_LEN_OFFSET,
           sizeof(status_vars_len));
    query_event->status_vars_len = le16toh(status_vars_len);
    /*
      Check if status variable length is corrupt and will lead to very
      wrong data. We could be even more strict and require data_len to
      be even bigger, but this will suffice to catch most corruption
      errors that can lead to a crash.
    */
    //sanity check
    if (status_vars_len >
        std::min<unsigned long>(query_event->data_len, MAX_SIZE_LOG_EVENT_STATUS))
      return -1;

    query_event->data_len -= query_event->status_vars_len;
    tmp -= 2;
  }
  else
  {
    BAPI_ASSERT(version < 4);
    //TODO : deal previos version event data
    //master_data_written= header()->data_written;
  }

  Log_event_header::Byte *start;
  Log_event_header::Byte *end;
  start = (Log_event_header::Byte * )(buf + post_header_len);
  end = (Log_event_header::Byte * )(start + query_event->status_vars_len);

  // ##################has problem

  //if (start || end)
  //  return -1;
  //#################################
  for (const Log_event_header::Byte *pos = start; pos < end;)
  {
    switch (*pos++)
    {
      case Q_FLAGS2_CODE:
      {
        BAPI_ASSERT((pos) + (4) <= (end));
        uint32_t flags2;
        memcpy(&flags2, pos, sizeof(flags2));
        query_event->flags2 = le32toh(flags2);
        pos += 4;
        break;
      }
      case Q_SQL_MODE_CODE:
      {
        BAPI_ASSERT((pos) + (8) <= (end));
        uint64_t sql_mode;
        memcpy(&sql_mode, pos, sizeof(sql_mode));
        query_event->sql_mode = le64toh(sql_mode);
        pos += 8;
        break;
      }
      case Q_CATALOG_NZ_CODE:
      {
        if ((query_event->catalog_len = *pos))
          query_event->catalog = std::string((char *)(pos + 1), query_event->catalog_len);
        BAPI_ASSERT((pos) + (query_event->catalog_len + 1) <= (end));
        pos += query_event->catalog_len + 1;
        break;
      }
      case Q_AUTO_INCREMENT:
      {
        BAPI_ASSERT((pos) + (4) <= (end));
        uint16_t auto_increment_increment;
        memcpy(&auto_increment_increment, pos, sizeof(auto_increment_increment));
        query_event->auto_increment_increment = le16toh(auto_increment_increment);
        uint16_t auto_increment_offset;
        memcpy(&auto_increment_offset, pos + 2, sizeof(auto_increment_offset));
        query_event->auto_increment_offset = le16toh(auto_increment_offset);
        pos += 4;
        break;
      }
      case Q_CHARSET_CODE:
      {
        BAPI_ASSERT((pos) + (6) <= (end));
        memcpy(query_event->charset, pos, 6);
        pos += 6;
        break;
      }
      case Q_TIME_ZONE_CODE:
      {
        if ((query_event->time_zone_len = *pos))
          query_event->time_zone_str = 
          std::string((const char *)
                      (pos + 1), query_event->time_zone_len);
        pos += query_event->time_zone_len + 1;
        break;
      }
      case Q_CATALOG_CODE: /* for 5.0.x where 0<=x<=3 masters */
      {
        //catalog length
        BAPI_ASSERT((pos) + (1) <= (end));
        query_event->catalog_len = 0;
        if ((query_event->catalog_len = *pos))
          query_event->catalog = std::string((const char *) (pos + 1));
        pos += 1;
        //catalog
        BAPI_ASSERT((pos) + (query_event->catalog_len + 1) <= (end));
        pos += query_event->catalog_len + 1; // leap over end 0
        break;
      }
      case Q_LC_TIME_NAMES_CODE:
      {
        BAPI_ASSERT((pos) + (2) <= (end));
        uint16_t lc_time_names_number; /* 0 means en_US */
        memcpy(&lc_time_names_number, pos, sizeof(lc_time_names_number));
        query_event->lc_time_names_number = le16toh(lc_time_names_number);
        pos += 2;
        break;
      }
      case Q_CHARSET_DATABASE_CODE:
      {
        BAPI_ASSERT((pos) + (2) <= (end));
        uint16_t charset_database_number;
        memcpy(&charset_database_number, pos, sizeof(charset_database_number));
        query_event->charset_database_number = le16toh(charset_database_number);
        pos += 2;
        break;
      }
      case Q_TABLE_MAP_FOR_UPDATE_CODE:
      {
        BAPI_ASSERT((pos) + (8) <= (end));
        uint64_t table_map_for_update;
        memcpy(&table_map_for_update, pos, sizeof(table_map_for_update));
        query_event->table_map_for_update = le64toh(table_map_for_update);
        pos += 8;
        break;
      }
      case Q_MASTER_DATA_WRITTEN_CODE:
      {
        BAPI_ASSERT((pos) + (4) <= (end));
        size_t master_data_written;
        memcpy(&master_data_written, pos, sizeof(master_data_written));
        query_event->master_data_written =
            le32toh(static_cast<uint32_t>(master_data_written));
        //header()->data_written= master_data_written;
        pos += 4;
        break;
      }
      case Q_MICROSECONDS:
      {
        BAPI_ASSERT((pos) + (3) <= (end));
        uint32_t temp_usec = 0;
        memcpy(&temp_usec, pos, 3);
        query_event->head.when.tv_usec = le32toh(temp_usec);
        pos += 3;
        break;
      }
      case Q_INVOKER:
      {
        //user
        BAPI_ASSERT((pos) + (1) <= (end));
        query_event->user_len = *pos;
        pos++;
        BAPI_ASSERT((pos) + (query_event->user_len) <= (end));
        if (query_event->user_len == 0)
          query_event->user = "";
        else
          query_event->user = std::string((const char *) pos,
                                          query_event->user_len);
        pos += query_event->user_len;

        //host
        BAPI_ASSERT((pos) + (1) <= (end));
        query_event->host_len = *pos;
        pos++;
        BAPI_ASSERT((pos) + (query_event->host_len) <= (end));
        if (query_event->host_len == 0)
          query_event->host = "";
        else
          query_event->host = std::string((const char *) pos,
                                          query_event->host_len);
        pos += query_event->host_len;
        break;
      }
      case Q_UPDATED_DB_NAMES:
      {
        unsigned char i = 0;
#ifndef DBUG_OFF
        bool is_corruption_injected = false;
#endif

        BAPI_ASSERT((pos) + (1) <= (end));
        query_event->mts_accessed_dbs = *pos;
        pos++;
        /*
           Notice, the following check is positive also in case of
           the master's MAX_DBS_IN_EVENT_MTS > the slave's one and the event
           contains e.g the master's MAX_DBS_IN_EVENT_MTS db:s.
        */
        if (query_event->mts_accessed_dbs > MAX_DBS_IN_EVENT_MTS)
        {
          query_event->mts_accessed_dbs = OVER_MAX_DBS_IN_EVENT_MTS;
          break;
        }

        BAPI_ASSERT(query_event->mts_accessed_dbs != 0);
        for (i = 0; i < query_event->mts_accessed_dbs && pos < end; i++)
        {

#ifndef DBUG_OFF
          /*
            This is specific to mysql test run on the server
            for the keyword "query_log_event_mts_corrupt_db_names"
          */
          /*
          if (binary_log_debug::debug_query_mts_corrupt_db_names)
          {
            if (query_event->mts_accessed_dbs == 2)
            {
              BAPI_ASSERT(pos[sizeof("d?") - 1] == 0);
              ((char *) pos)[sizeof("d?") - 1] = 'a';
              is_corruption_injected = true;
            }
          }
          */
#endif
          strncpy(query_event->mts_accessed_db_names[i], (char *) pos,
                  std::min<unsigned long>(NAME_LEN, end - pos));
          query_event->mts_accessed_db_names[i][NAME_LEN - 1] = 0;
          pos += 1 + strlen((const char *) pos);
        }
        if (i != query_event->mts_accessed_dbs
#ifndef DBUG_OFF
            || is_corruption_injected
#endif
            )
          BAPI_ASSERT(false);
        break;
      }
      case Q_EXPLICIT_DEFAULTS_FOR_TIMESTAMP:
      {
        BAPI_ASSERT((pos) + (1) <= (end));
        query_event->explicit_defaults_ts = *pos == 0 ?
                                            TERNARY_OFF : TERNARY_ON;
        pos++;
        break;
      }
      default:
        BAPI_ASSERT(false);
    }
  }

  if (query_event->catalog_len)         // If catalog is given
    query_event->query_data_written += query_event->catalog_len + 1;
  if (query_event->time_zone_len)
    query_event->query_data_written += query_event->time_zone_len + 1;
  if (query_event->user_len > 0)
    query_event->query_data_written += query_event->user_len + 1;
  if (query_event->host_len > 0)
    query_event->query_data_written += query_event->host_len + 1;

  query_event->query_data_written += query_event->data_len + 1;
  query_event->db = std::string((const char *) end);
  query_event->q_len = query_event->data_len - query_event->db_len - 1;
  query_event->query = std::string((const char *)
                                   (end + query_event->db_len + 1),
                                   query_event->q_len);

  /*sanity check*/
  unsigned int check_length;
  check_length = (event_len - (((end + query_event->db_len + 1) - start) +
                               (post_header_len + common_header_len)));
  if (query_event->q_len != check_length)
  {
    return -1;
  }

  return 0;
}

//TABLE MAP EVENT

void binlog_parse_table_map_event_t_init(binlog_prs_table_map_event_t *table_map_event)
{
  memset(table_map_event, 0, sizeof(binlog_prs_event_head_t));
  table_map_event->m_dblen = 0;
  table_map_event->m_tbllen = 0;
  table_map_event->m_colcnt = 0;
  table_map_event->m_field_metadata_size = 0;
}

enum Table_map_event_offset {
  /** TM = "Table Map" */
  TM_MAPID_OFFSET= 0,
  TM_FLAGS_OFFSET= 6
};

static /**
  Get the length of next field.
  Change parameter to point at fieldstart.

  @param  packet pointer to a buffer containing the field in a row.
  @return pos    length of the next field
*/
unsigned long prs_get_field_length(unsigned char **packet)
{
  unsigned char *pos= *packet;
  uint32_t temp= 0;
  if (*pos < 251)
  {
    (*packet)++;
    return  *pos;
  }
  if (*pos == 251)
  {
    (*packet)++;
    return ((unsigned long) ~0);//NULL_LENGTH;
  }
  if (*pos == 252)
  {
    (*packet)+= 3;
    memcpy(&temp, pos + 1, 2);
    temp= le32toh(temp);
    return (unsigned long)temp;
  }
  if (*pos == 253)
  {
    (*packet)+= 4;
    memcpy(&temp, pos + 1, 3);
    temp= le32toh(temp);
    return (unsigned long)temp;
  }
  (*packet)+= 9;                                 /* Must be 254 when here */
  memcpy(&temp, pos + 1, 4);
  temp= le32toh(temp);
  return (unsigned long)temp;
}

int
binlog_prs_parse_table_map(const char *buf_, uint32_t event_len,
                           uint16_t version, uint8_t common_header_len,
                           uint8_t post_header_len,
                           binlog_prs_table_map_event_t *table_map_event)
{
  int r = binlog_prs_parse_head(buf_, version, &table_map_event->head);
  if (r < 0)     //sanity check
    return -1;

  //unsigned int bytes_read = 0;

  //size_t   m_data_size;                         /** event data size */
  //m_data_size = event_len - common_header_len;

  table_map_event->m_data_size = event_len - common_header_len;

  const char *post_start = buf_ + LOG_EVENT_MINIMAL_HEADER_LEN;

  post_start += TM_MAPID_OFFSET;

  if (post_header_len == 6)
  {
    /* Master is of an intermediate source tree before 5.1.4. Id is 4 bytes */
    uint64_t table_id = 0;
    memcpy(&table_id, post_start, 4);
    table_map_event->m_table_id = le64toh(table_id);
    post_start += 4;
  }
  else
  {
    BAPI_ASSERT(post_header_len == TABLE_MAP_HEADER_LEN);
    uint64_t table_id = 0;
    memcpy(&table_id, post_start, 6);
    table_map_event->m_table_id = le64toh(table_id);
    post_start += TM_FLAGS_OFFSET;
  }

  //flags
  flag_set m_flags;
  memcpy(&m_flags, post_start, sizeof(m_flags));
  table_map_event->m_flags = le16toh(m_flags);

  /* Read the variable part of the event */
  const char *const vpart = buf_ + LOG_EVENT_MINIMAL_HEADER_LEN + post_header_len;

  /* Extract the length of the various parts from the buffer */
  unsigned char const *const ptr_dblen = (unsigned char const *) vpart + 0;
  table_map_event->m_dblen = *(unsigned char *) ptr_dblen;

  /* Length of database name + counter + terminating null */
  unsigned char const *const ptr_tbllen =
      ptr_dblen + table_map_event->m_dblen + 2;
  table_map_event->m_tbllen = *(unsigned char *) ptr_tbllen;


  /* Length of table name + counter + terminating null */
  unsigned char const *const ptr_colcnt =
      ptr_tbllen + table_map_event->m_tbllen + 2;
  unsigned char *ptr_after_colcnt = (unsigned char *) ptr_colcnt;
  table_map_event->m_colcnt = prs_get_field_length(&ptr_after_colcnt);

  unsigned int bytes_read = 0;
  bytes_read = (unsigned int) ((ptr_after_colcnt + common_header_len) -
      (unsigned char *) (buf_ + LOG_EVENT_MINIMAL_HEADER_LEN));

  /* sanity check */
  if (event_len <= bytes_read ||
      event_len - bytes_read < table_map_event->m_colcnt)
      return -1;

  //database,table,column info
  table_map_event->m_db = string((const char*)ptr_dblen + 1, table_map_event->m_dblen);
  table_map_event->m_tab = string((const char*)ptr_tbllen + 1,table_map_event->m_tbllen);
  table_map_event->
      m_coltype.insert(table_map_event->m_coltype.begin(),
                       ptr_after_colcnt,
                       ptr_after_colcnt + table_map_event->m_colcnt);

  ptr_after_colcnt = ptr_after_colcnt + table_map_event->m_colcnt;
  bytes_read = (unsigned int) (ptr_after_colcnt + common_header_len -
      (unsigned char *) (buf_ + LOG_EVENT_MINIMAL_HEADER_LEN));


  //null meta
  if (bytes_read < event_len)
  {
    table_map_event->m_field_metadata_size = prs_get_field_length(&ptr_after_colcnt);
    //sanity check
    if (table_map_event->m_field_metadata_size > (table_map_event->m_colcnt * 2))
      return -1;
    unsigned int num_null_bytes = (table_map_event->m_colcnt + 7) / 8;

    table_map_event->
        m_field_metadata.insert(table_map_event->m_field_metadata.begin(),
                                ptr_after_colcnt,
                                ptr_after_colcnt + table_map_event->m_field_metadata_size);
    ptr_after_colcnt = (unsigned char *) ptr_after_colcnt +
        table_map_event->m_field_metadata_size;

    table_map_event->
        m_null_bits.insert(table_map_event->m_null_bits.begin(),
                           ptr_after_colcnt,
                           ptr_after_colcnt + num_null_bytes);
  }
  return 0;
}


/**
   1 byte length, 1 byte format
   Length is total length in bytes, including 2 byte header
   Length values 0 and 1 are currently invalid and reserved.
*/
#define EXTRA_ROW_INFO_LEN_OFFSET 0
#define EXTRA_ROW_INFO_FORMAT_OFFSET 1
#define EXTRA_ROW_INFO_HDR_BYTES 2
#define EXTRA_ROW_INFO_MAX_PAYLOAD (255 - EXTRA_ROW_INFO_HDR_BYTES)

#define ROWS_MAPID_OFFSET    0
#define ROWS_FLAGS_OFFSET    6
#define ROWS_VHLEN_OFFSET    8
#define ROWS_V_TAG_LEN       1
#define ROWS_V_EXTRAINFO_TAG 0


// ROW EVENT

void binlog_prs_row_event_t_init(binlog_prs_row_event_t *row_event)
{
  memset(row_event, 0, sizeof(binlog_prs_event_head_t));
  row_event->m_type = (binary_log::Log_event_type)0;
  row_event->m_table_id = 0;
  row_event->m_flags = 0;           /** Flags for row-level events */
  row_event->m_width = 0;
  row_event->n_bits_len = 0;
  row_event->var_header_len = 0;
  row_event->m_extra_row_data.clear();
  row_event->columns_before_image.clear();
  row_event->columns_after_image.clear();
  row_event->row.clear();
};

static int binlog_prs_parse_row(const char *buf_, uint32_t event_len,
                         uint16_t version, uint8_t common_header_len,
                         uint8_t post_header_len,
                         binary_log::Log_event_type type,
                         binlog_prs_row_event_t *row_event)
{
  int r = binlog_prs_parse_head(buf_, version, &row_event->head);
  if (r < 0)     //sanity check
    return -1;

  row_event->m_type = type;

  const char *post_start = buf_ + common_header_len;
  const char *buf = buf_ + common_header_len;
  post_start += ROWS_MAPID_OFFSET;

  //table id
  uint64_t table_id = 0;
  if (post_header_len == 6)
  {
    /* Master is of an intermediate source tree before 5.1.4. Id is 4 bytes */
    memcpy(&table_id, post_start, 4);
    row_event->m_table_id = le64toh(table_id);
    post_start += 4;
  }
  else
  {
    memcpy(&table_id, post_start, 6);
    row_event->m_table_id = le64toh(table_id);
    post_start += ROWS_FLAGS_OFFSET;
  }


  memcpy(&row_event->m_flags, post_start, sizeof(row_event->m_flags));
  row_event->m_flags = le16toh(row_event->m_flags);
  post_start += 2;

  uint16_t var_header_len= 0;
  if (post_header_len == Binary_log_event::ROWS_HEADER_LEN_V2)
  {
    /*
      Have variable length header, check length,
      which includes length bytes
    */
    memcpy(&var_header_len, post_start, sizeof(var_header_len));
    var_header_len= le16toh(var_header_len);
    /* Check length and also avoid out of buffer read */
    if (var_header_len < 2 ||
        event_len < static_cast<unsigned int>(var_header_len +
            (post_start - buf)))
      return -1;

    var_header_len-= 2;

    /* Iterate over var-len header, extracting 'chunks' */
    const char* start= post_start + 2;
    const char* end= start + var_header_len;
    for (const char* pos= start; pos < end;)
    {
      switch(*pos++)
      {
        case ROWS_V_EXTRAINFO_TAG:
        {
          /* Have an 'extra info' section, read it in */
          if ((end - pos) < EXTRA_ROW_INFO_HDR_BYTES)
            return -1;

          uint8_t infoLen= pos[EXTRA_ROW_INFO_LEN_OFFSET];
          if ((end - pos) < infoLen)
            return -1;

          /* Just store/use the first tag of this type, skip others */
          if (row_event->m_extra_row_data.empty())
          {
            row_event->m_extra_row_data.insert(row_event->m_extra_row_data.begin(), pos, pos + infoLen);
          }
          pos+= infoLen;
          break;
        }
        default:
          /* Unknown code, we will not understand anything further here */
          pos= end; /* Break loop */
      }
    }
  }

  unsigned char const *const var_start= (const unsigned char *)buf +
      post_header_len + var_header_len;
  unsigned char const *const ptr_width= var_start;
  unsigned char *ptr_after_width= (unsigned char*) ptr_width;
  row_event->m_width = prs_get_field_length(&ptr_after_width);
  row_event->n_bits_len = (row_event->m_width + 7) / 8;
  if (ptr_after_width + row_event->n_bits_len > (const unsigned char *)(buf +
      event_len - post_header_len))
      return -1;
  row_event->columns_before_image.reserve((row_event->m_width + 7) / 8);
  unsigned char *ch;
  ch = ptr_after_width;
  for(unsigned long i= 0; i < (row_event->m_width + 7) / 8; i++)
  {
    row_event->columns_before_image.push_back(*ch);
    ch++;
  }
  ptr_after_width += (row_event->m_width + 7) / 8;

  row_event->columns_after_image = row_event->columns_before_image;
  if ((type == UPDATE_ROWS_EVENT) ||
      (type == UPDATE_ROWS_EVENT_V1))
  {
    row_event->columns_after_image.reserve((row_event->m_width + 7) / 8);
    row_event->columns_after_image.clear();
    ch= ptr_after_width;
    for(unsigned long i= 0; i < (row_event->m_width + 7) / 8; i++)
    {
      row_event->columns_after_image.push_back(*ch);
      ch++;
    }
    ptr_after_width+= (row_event->m_width + 7) / 8;
  }

  const unsigned char* ptr_rows_data= (unsigned char*) ptr_after_width;

  size_t const read_size= ptr_rows_data + common_header_len -
      (const unsigned char *) buf;
  if (read_size > event_len)
    return -1;
  size_t const data_size= event_len - read_size;

  try
  {
    row_event->row.assign(ptr_rows_data, ptr_rows_data + data_size + 1);
  }
  catch (const std::bad_alloc &e)
  {
    row_event->row.clear();
  }
  BAPI_ASSERT(row_event->row.size() == data_size + 1);
  return 0;
}


// WRITE ROW EVENT

int
binlog_prs_parse_write_rows(const char *buf_, uint32_t event_len,
                            uint16_t version, uint8_t common_header_len,
                            uint8_t post_header_len,
                            binary_log::Log_event_type type,
                            binlog_prs_row_event_t *row_event)
{
  binlog_prs_parse_row(buf_, event_len,
                       version, common_header_len,
                       post_header_len,
                       type, row_event);
  return 0;
}

// UPDATE ROW EVENT

int
binlog_prs_parse_update_rows(const char *buf_, uint32_t event_len,
                            uint16_t version, uint8_t common_header_len,
                            uint8_t post_header_len,
                            binary_log::Log_event_type type,
                            binlog_prs_row_event_t *row_event)
{
  binlog_prs_parse_row(buf_, event_len,
                       version, common_header_len,
                       post_header_len,
                       type, row_event);
  return 0;
}

//DELETE ROW EVENT

int
binlog_prs_parse_delete_rows(const char *buf_, uint32_t event_len,
                            uint16_t version, uint8_t common_header_len,
                            uint8_t post_header_len,
                            binary_log::Log_event_type type,
                            binlog_prs_row_event_t *row_event)
{
  binlog_prs_parse_row(buf_, event_len,
                       version, common_header_len,
                       post_header_len,
                       type, row_event);
  return 0;
}


//XID EVENT
void binlog_prs_xid_event_t_init(binlog_prs_xid_event_t *xid_event)
{
  memset(xid_event, 0, sizeof(binlog_prs_event_head_t));
  xid_event->xid = 0;
}

int binlog_prs_parse_xid(const char *buf_, uint32_t event_len,
                         uint16_t version, uint8_t common_header_len,
                         uint8_t post_header_len,
                         binlog_prs_xid_event_t *xid_event)
{
  int r = binlog_prs_parse_head(buf_, version, &xid_event->head);
  if (r < 0)     //sanity check
  {
    return -1;
  }

  const char *buf = buf_ + common_header_len + post_header_len;
  memcpy(&xid_event->xid, buf, 8);
  
  return 0;
}
