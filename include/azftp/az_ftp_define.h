#ifndef __AZ_FTP_DEFINE_H_INCLUDE__
#define __AZ_FTP_DEFINE_H_INCLUDE__

#include<azctools/az_memp.h>
#ifndef AZ_NETWORK_ENABLED
#define AZ_NETWORK_ENABLED
#endif
#include<azctools/az_tools.h>
#include<azctools/az_list.h>
#include<azctools/az_taskp.h>
#include<azctools/az_log.h>

#ifndef CONFIG_LINE_SIZE
#define CONFIG_LINE_SIZE 1024
#endif
#ifndef CONFIG_KEY_LEN
#define CONFIG_KEY_LEN 32
#endif
#ifndef CONFIG_VALUE_LEN
#define CONFIG_VALUE_LEN 128
#endif

#ifndef AZ_FTP_PATH_MAX_LEN
#define AZ_FTP_PATH_MAX_LEN 1024
#endif
#ifndef AZ_FTP_USER_LEN
#define AZ_FTP_USER_LEN 16
#endif
#ifndef AZ_FTP_PWD_LEN
#define AZ_FTP_PWD_LEN 32
#endif

#ifndef _AZ_FTP_CMD_
typedef enum az_ftp_cmd_e
{
    FTP_CMD_UNKNOWN = 0,
    //访问控制命令
    FTP_CMD_USER,
    FTP_CMD_PASS,
    FTP_CMD_ACCT,
    FTP_CMD_CWD,
    FTP_CMD_CDUP,
    FTP_CMD_SMNT,
    FTP_CMD_REIN,
    FTP_CMD_QUIT,
    //传输参数命令
    FTP_CMD_PORT,
    FTP_CMD_PASV,
    FTP_CMD_TYPE,
    FTP_CMD_STRU,
    FTP_CMD_MODE,
    //服务命令
    FTP_CMD_RETR,
    FTP_CMD_STOR,
    FTP_CMD_STOU,
    FTP_CMD_APPE,
    FTP_CMD_ALLO,
    FTP_CMD_REST,
    FTP_CMD_RNFR,
    FTP_CMD_RNTO,
    FTP_CMD_ABOR,
    FTP_CMD_DELE,
    FTP_CMD_RMD,
    FTP_CMD_MKD,
    FTP_CMD_PWD,
    FTP_CMD_LIST,
    FTP_CMD_NLST,
    FTP_CMD_SITE,
    FTP_CMD_SYST,
    FTP_CMD_STAT,
    FTP_CMD_HELP,
    FTP_CMD_NOOP,

    FTP_CMD_COUNT
}az_ftp_cmd;
#define _AZ_FTP_CMD_ 1
#endif

#ifndef _AZ_FTP_LOGIN_STATUS_
typedef enum az_ftp_login_status_e
{
    AZ_FTP_NOLOGIN = 0,
    AZ_FTP_DEALLOGIN,
    AZ_FTP_OKLOGIN,
}az_ftp_login_status;
#define _AZ_FTP_LOGIN_STATUS_ 1
#endif

#ifndef _AZ_FTP_CLIENT_STATUS_
typedef enum az_ftp_client_status_e
{
    AZ_FTP_CLIENT_LINKERR = -2,
    AZ_FTP_CLIENT_ERR = -1,
    AZ_FTP_CLIENT_INIT = 0,
    AZ_FTP_CLIENT_RUN,
    AZ_FTP_CLIENT_CLOSE,
    AZ_FTP_CLIENT_SERCLOSE
}az_ftp_client_status;
#define _AZ_FTP_CLIENT_STATUS_ 1
#endif

#ifndef _AZ_FTP_DTP_MODE_
typedef enum az_ftp_dtp_mode_e
{
    DTP_ACTIVE_MODE = 0,
    DTP_PASSIVE_MODE
}az_ftp_dtp_mode;
#define _AZ_FTP_DTP_MODE_ 1
#endif

#ifndef _AZ_FTP_TRANS_MODE_
typedef enum az_ftp_trans_mode_e
{
    TRANS_STREAM_MODE = 0,
    TRANS_BLOCK_MODE,
    TRANS_COMPRESS_MODE
}az_ftp_trans_mode;
#define _AZ_FTP_TRANS_MODE_ 1
#endif

#ifndef _AZ_FTP_DATA_TYPE_
typedef enum az_ftp_data_type_e
{
    AZ_DATA_ASCII = 0,
    AZ_DATA_EBCDIC,
    AZ_DATA_IMAGE,
    AZ_DATA_LOCAL,
    AZ_DATA_TYPE_COUNT
}az_ftp_data_type;
#define _AZ_FTP_DATA_TYPE_ 1
#endif

#ifndef _AZ_FTP_FORMAT_
typedef enum az_ftp_format_e
{
    AZ_FORMAT_NOPRINT = 0,
    AZ_FORMAT_TELNET,
    AZ_FORMAT_CONTROL,
    AZ_FORMAT_TYPE_COUNT
}az_ftp_format;
#define _AZ_FTP_FORMAT_ 1
#endif

#ifndef _AZ_TRANS_STATE_
typedef enum az_trans_state_e
{
    AZ_TRANS_INIT = 0,
    AZ_TRANS_WAITE,
    AZ_TRANS_RUNNING,
    AZ_TRANS_END,
    AZ_TRANS_ABORT,
    AZ_TRANS_ERR
}az_trans_state;
#define _AZ_TRANS_STATE_ 1
#endif

#ifndef _AZ_TRANS_TYPE_
typedef enum az_trans_type_e
{
    AZ_FTP_UPLOAD = 0,
    AZ_FTP_DOWNLOAD
}az_trans_type;
#define _AZ_TRANS_TYPE_ 1
#endif

#ifndef _AZ_FILE_SESSION_
typedef struct az_file_session_s
{
    az_trans_type trans_type;
    az_atomic_t trans_state;

    char remote_path[AZ_FTP_PATH_MAX_LEN];
    char local_path[AZ_FTP_PATH_MAX_LEN];
    off_t offset;
    off_t file_size;
    az_atomic64_t up_down_len;
    az_atomic64_t speed;
}az_file_session_t, * az_file_session;
#define _AZ_FILE_SESSION_ 1
#endif

#endif // !__AZ_FTP_DEFINE_H_INCLUDE__
