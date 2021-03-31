#ifndef __AZ_FTP_CLIENT_CTRL_H_INCLUDE__
#define __AZ_FTP_CLIENT_CTRL_H_INCLUDE__

#include"az_ftp_include.h"

typedef struct az_clictrl_event_s
{
    az_ftp_cmd cmd;
    int code;
    int msg_len;
    char *msg;
}az_clictrl_event_t, *az_clictrl_ev;

typedef struct az_ftp_clictrl_s az_ftp_clictrl_t, *az_ftp_clictrl;

az_ftp_clictrl az_clictrl_create(az_memp pool, const char *ser_ip, int ser_port, bool log_flag);

void az_clictrl_netinfo(az_ftp_clictrl pi, az_netinfo_ipv4 netinfo);
const char* az_clictrl_serhello(az_ftp_clictrl pi);
az_ret az_clictrl_exec(az_ftp_clictrl pi, az_ftp_cmd cmd, const char *argv);
az_clictrl_ev az_clictrl_waite(az_ftp_clictrl pi, az_ftp_cmd cmd, bool temporary);
void az_clictrl_evfree(az_ftp_clictrl pi, az_clictrl_ev *reply);
az_ftp_client_status az_clictrl_state(az_ftp_clictrl pi);

void az_clictrl_destory(az_ftp_clictrl *pi);

#endif