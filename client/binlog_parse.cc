#include <iostream>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <iomanip>

//#include "psi_memory.h"
#include "binlog_event.h"
#include "mysql.h"
#include "mysqld_error.h"
//#include "errmsg.h"
//#include "log_event.h"
#include "binlog_parse.h"


using namespace std;
using namespace binary_log;

typedef unsigned char uchar;

static string get_type_str(Log_event_type type)
{
  switch(type) {
  case binary_log::START_EVENT_V3:  return "Start_v3";
  case binary_log::STOP_EVENT:   return "Stop";
  case binary_log::QUERY_EVENT:  return "Query";
  case binary_log::ROTATE_EVENT: return "Rotate";
  case binary_log::INTVAR_EVENT: return "Intvar";
  case binary_log::LOAD_EVENT:   return "Load";
  case binary_log::NEW_LOAD_EVENT:   return "New_load";
  case binary_log::CREATE_FILE_EVENT: return "Create_file";
  case binary_log::APPEND_BLOCK_EVENT: return "Append_block";
  case binary_log::DELETE_FILE_EVENT: return "Delete_file";
  case binary_log::EXEC_LOAD_EVENT: return "Exec_load";
  case binary_log::RAND_EVENT: return "RAND";
  case binary_log::XID_EVENT: return "Xid";
  case binary_log::USER_VAR_EVENT: return "User var";
  case binary_log::FORMAT_DESCRIPTION_EVENT: return "Format_desc";
  case binary_log::TABLE_MAP_EVENT: return "Table_map";
  case binary_log::PRE_GA_WRITE_ROWS_EVENT: return "Write_rows_event_old";
  case binary_log::PRE_GA_UPDATE_ROWS_EVENT: return "Update_rows_event_old";
  case binary_log::PRE_GA_DELETE_ROWS_EVENT: return "Delete_rows_event_old";
  case binary_log::WRITE_ROWS_EVENT_V1: return "Write_rows_v1";
  case binary_log::UPDATE_ROWS_EVENT_V1: return "Update_rows_v1";
  case binary_log::DELETE_ROWS_EVENT_V1: return "Delete_rows_v1";
  case binary_log::BEGIN_LOAD_QUERY_EVENT: return "Begin_load_query";
  case binary_log::EXECUTE_LOAD_QUERY_EVENT: return "Execute_load_query";
  case binary_log::INCIDENT_EVENT: return "Incident";
  case binary_log::IGNORABLE_LOG_EVENT: return "Ignorable";
  case binary_log::ROWS_QUERY_LOG_EVENT: return "Rows_query";
  case binary_log::WRITE_ROWS_EVENT: return "Write_rows";
  case binary_log::UPDATE_ROWS_EVENT: return "Update_rows";
  case binary_log::DELETE_ROWS_EVENT: return "Delete_rows";
  case binary_log::GTID_LOG_EVENT: return "Gtid";
  case binary_log::ANONYMOUS_GTID_LOG_EVENT: return "Anonymous_Gtid";
  case binary_log::PREVIOUS_GTIDS_LOG_EVENT: return "Previous_gtids";
  case binary_log::HEARTBEAT_LOG_EVENT: return "Heartbeat";
  case binary_log::TRANSACTION_CONTEXT_EVENT: return "Transaction_context";
  case binary_log::VIEW_CHANGE_EVENT: return "View_change";
  case binary_log::XA_PREPARE_LOG_EVENT: return "XA_prepare";
  default: return "Unknown";                            /* impossible */
  }
}

int print_hello()
{
  cout << "I am print hello!" << endl;
  return 0;
}

int print_error(int err_code, const char *err_msg)
{
  cout << "error code: " << err_code << endl;
  cout << "error msg: " << err_msg << endl;
  return 0;
}
static int check_file_exist(const char *file_name)
{
  int check_mode = 0;
  return (access(file_name, check_mode));
}
#define READ_FILE_BUFFER_SIZE (1024 * 1024 * 8)
/*
 //getting from mysql source code
 if (memcmp(header, BINLOG_MAGIC, sizeof(header)))
  {
    error("File is not a binary log file.");
    DBUG_RETURN(ERROR_STOP);
  }

*/

int check_binlog_file(const char *buf_)
{
  const char *buf = buf_;
  int r = 0;
  uchar header[BIN_LOG_HEADER_SIZE] = {0};
  memcpy(header, buf, sizeof(header));
  if (memcmp(header, BINLOG_MAGIC, sizeof(header)))
  {
    const char *err_msg = "File is not a binary log file.";
    int err_code = -1;
    print_error(err_code,  err_msg);
    r = -1;
  }
  return r;
}



int binlog_event_statistics_init(binlog_event_statics_t *event_statics)
{
  event_statics->event_type = UNKNOWN_EVENT;
  event_statics->event_counts = 0;
  event_statics->event_pos.clear();
  return 0;
}

#define EVENT_TYPE_COUNTS (39)

binlog_event_statics_t statics_matrix[EVENT_TYPE_COUNTS];

int statics_matrix_init()
{
  int i = 0;
  for (; i < EVENT_TYPE_COUNTS; i++)
  {
    statics_matrix[i].event_type = (Log_event_type)i;
    statics_matrix[i].event_counts = 0;
  }
  return 0;
}

static int print_events_statics_header()
{
  cout << "----------------------------------------------"
  "-----------------------------------------------------" << endl;
  cout << "|  " << setiosflags(ios::left) << setw(28) 
       << "event_type" << setw(2) << "|  " << setw(14) 
       << "event_counts " << setw(2) << "| " << setw(48)
       << "all event pos " << setw(2) << "| " << endl;
  cout << "----------------------------------------------"
  "-----------------------------------------------------" << endl;
  return 0;
}

// static int print_events_statics_footer()
// {
//   cout << "--------------------------------------------------------" << endl;
//   return 0;
// }
static const int MAX_SHOW_POS_LEN = 48;
int display_events_statics()
{
  string show_pos_detail = "";
  print_events_statics_header();
  int i = 0;
  for (; i < EVENT_TYPE_COUNTS; i++)
  {
    if (statics_matrix[i].event_counts != 0)
    {
      show_pos_detail = "";
      char tmp_pos[32] = {0};     
      event_pos_type::iterator iter = statics_matrix[i].event_pos.begin();
      assert(iter != statics_matrix[i].event_pos.end());
      while(iter != statics_matrix[i].event_pos.end())
      {
        sprintf(tmp_pos,"%ld,", *iter);
        if (show_pos_detail.length() + strlen(tmp_pos) > MAX_SHOW_POS_LEN)
        {
          break;
        }
        show_pos_detail += tmp_pos;
        iter++;
      }
      show_pos_detail = show_pos_detail.substr(0, show_pos_detail.length() -1 );
      cout << "|  " << setiosflags(ios::left) << setw(28) 
           << get_type_str(statics_matrix[i].event_type) 
           << setw(2) << "|  " << setw(14)
           << statics_matrix[i].event_counts << setw(2) << "| " << setw(48) 
           << show_pos_detail << setw(2) << "| " << endl;
      cout << "----------------------------------------------"
      "-----------------------------------------------------" << endl;
    }
  }
  return 0;
}

int
main(int argc, char *argv[])
{
  if (argc != 2)
  {
    return -1;
  }
  statics_matrix_init();
  uint8_t *read_buffer = NULL;
  const uint8_t *buf = NULL;
  while(read_buffer == NULL)
  {
    read_buffer = (uint8_t *)malloc(READ_FILE_BUFFER_SIZE);
  }
  memset((void *)read_buffer, 0, READ_FILE_BUFFER_SIZE);
  
  const char *file_name = argv[1];
  if (check_file_exist(file_name) < 0)
  {
    cout << "Error, file " << file_name << "doesn't exist!" << endl;
    return 0;
  }
  int fd = 0;
  fd = open(file_name, O_RDONLY, 0644);
  if (fd < 0)
  {
    print_error(errno, strerror(errno));
    return -1;
  }
  int read_ret = 0;
  read_ret = read(fd, read_buffer, READ_FILE_BUFFER_SIZE);
  if (read_ret < 0)
  {
    print_error(errno, strerror(errno));
    return -1;
  }
  int r = check_binlog_file((const char *)read_buffer);
  if (r < 0)
  {
    return r;
  }
  buf = read_buffer + BIN_LOG_HEADER_SIZE;
  const uint8_t *end = read_buffer + read_ret;
  binlog_prs_event_head_t event_head;
  const int binlog_version = 4;
  uint64_t fil_event_pos = 0;
  fil_event_pos += BIN_LOG_HEADER_SIZE;
  while(buf < end)
  {
    memset(&event_head, 0, sizeof(event_head));
    binlog_prs_parse_head((const char *)buf, binlog_version , &event_head);
    statics_matrix[(int)event_head.event_type].event_counts++;
    statics_matrix[(int)event_head.event_type].event_pos.push_back(fil_event_pos);
    buf += event_head.event_len;   
    fil_event_pos += event_head.event_len;   
  }
  display_events_statics();
  close(fd);
  
  return 0;
}



/*
int main()
{
  print_hello();
  return 0;
}
*/
