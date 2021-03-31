#ifndef __AZ_FTP_SERVER_H_INCLUDE__
#define __AZ_FTP_SERVER_H_INCLUDE__

#ifdef LIBAZFTPSER_EXPORTS
#   ifndef AZ_LIB_EXPORTS
#       define AZ_LIB_EXPORTS 1
#   endif
#endif

#include<azctools/az_platform.h>

#ifndef LIBAZFTPSER_EXPORTS
#   ifdef __az_msc__
#       ifndef AZ_LOAD_FTPSER_LIB
#           pragma message("# QwQ #  az_ftp_server.h: load libazftpser.lib")
#           pragma comment(lib, "libazftpser.lib")
#           define AZ_LOAD_FTPSER_LIB 1
#       endif
#   endif
#endif

#include<azftp/az_ftp_define.h>

#ifndef AZ_FTP_PATH_MAX_LEN
#define AZ_FTP_PATH_MAX_LEN 1024
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

typedef struct az_ftp_config_s
{
    bool daemonize;
    bool simplify;
    char listen_ip[AZ_IPV6_ADDRESS_STRING_LEN];
    int listen_port;
    char base_dir[AZ_FTP_PATH_MAX_LEN];
    char auth_dir[AZ_FTP_PATH_MAX_LEN];
    int max_client;

    bool log_flag;
    az_log_cnf_t log_cnf;
}az_ftp_config_t, *az_ftp_config;

typedef struct az_ftp_server_s az_ftp_server_t, *az_ftp_server;
#ifndef _CMD_CB_FUNC_
typedef int(*cmd_cb)(az_ftp_cmd cmd, char *argv);
#define _CMD_CB_FUNC_ 1
#endif

AZ_BEGIN_DECLS

AZ_API az_ret az_ftp_load_cnf(char *path, az_ftp_config cnf);

AZ_API az_ftp_server az_ftp_server_init(az_ftp_config cnf);
AZ_API az_ret az_ftp_server_run(az_ftp_server ctx);
AZ_API bool az_ftp_server_stat(az_ftp_server ctx);
AZ_API void az_ftp_server_destory(az_ftp_server *ctx);

AZ_API az_ret az_ftp_server_set_unsupcmd(az_ftp_server ctx, az_ftp_cmd cmd_type);
AZ_API az_ret az_ftp_server_set_callback(az_ftp_server ctx, az_ftp_cmd cmd_type, cmd_cb cb);

AZ_END_DECLS

#endif