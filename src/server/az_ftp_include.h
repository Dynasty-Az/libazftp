#ifndef __AZ_FTP_INCLUDE_H_INCLUDE__
#define __AZ_FTP_INCLUDE_H_INCLUDE__

#include<azftp/az_ftp_define.h>
#include<az_ftp_message.h>

typedef struct az_ftp_client_s
{
    void *ser_ctx;
    char user[AZ_FTP_USER_LEN];
    char pwd[AZ_FTP_PWD_LEN];

    az_atomic_t stat;
    az_ftp_login_status log_stat;
    az_net client_fd;
    az_netinfo_ipv4_t netinfo;
    az_memp mp;
    az_taskp tp;
    //az_thread main;
    int ser_recv_epfd;
    bool simplify;

    char auth_dir[AZ_FTP_PATH_MAX_LEN];
    char home_dir[AZ_FTP_PATH_MAX_LEN];
    int dir_deep;
    char work_dir[AZ_FTP_PATH_MAX_LEN];
    az_ftp_data_type data_type;
    az_ftp_format data_format;
    int local_len;

    bool restart;
    off_t offset;

    bool rename;
    char rename_dir[AZ_FTP_PATH_MAX_LEN];

    az_list cmd_list;
    az_list reply_list;
    az_list session_list;
    az_atomic_t s_id;

    az_ftp_dtp_mode dtp_mode;
    az_ftp_trans_mode trans_mode;
    az_net pasv_fd;
    char dtp_ip[AZ_IPV6_ADDRESS_STRING_LEN];
    int dtp_port;

    char recv_buf[2 * 1024 * 1024];
    int data_len;
}az_ftp_client_t, *az_ftp_client;

typedef struct az_ftp_session_s
{
    size_t s_id;
    az_atomic_t run;
    //az_memp mp;
    //az_list reply_list;
    //az_list session_list;
    az_ftp_client cli_ctx;

    char file_name[AZ_FTP_PATH_MAX_LEN];
    off_t offset;
    bool appe;
    bool stou;

    az_ftp_dtp_mode dtp_mode;
    az_ftp_trans_mode trans_mode;
    az_net data_fd;
    char dtp_ip[AZ_IPV6_ADDRESS_STRING_LEN];
    int dtp_port;

    az_atomic_t abort;
}az_ftp_session_t, *az_ftp_session;

int az_ftp_response(az_ftp_client client, int code, const char *res);

#endif