#ifndef __AZ_FTP_INCLUDE_H_INCLUDE__
#define __AZ_FTP_INCLUDE_H_INCLUDE__

#include<azftp/az_ftp_define.h>
#include<az_ftp_message.h>

typedef struct az_client_info_s
{
    char *ser_ip;
    int ser_port;
    char *user;
    char *pwd;
    char *current_dir;
    az_ftp_dtp_mode dtp_mode;
    az_ftp_trans_mode trans_mode;
}az_client_info_t, *az_client_info;

//#ifndef _AZ_FTP_CLIENT_T_
//typedef struct az_ftp_client_s az_ftp_client_t, *az_ftp_client;
//#define _AZ_FTP_CLIENT_T_
//#endif

//az_ret az_cli_send_cmd(az_ftp_client cli, az_ftp_cmd type, const char *argv);
//az_ftp_msg az_cli_waite_reply(az_ftp_client cli);

#endif