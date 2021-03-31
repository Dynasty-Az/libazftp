#ifndef __AZ_FTP_SERVER_PI_H_INCLUDE__
#define __AZ_FTP_SERVER_PI_H_INCLUDE__

#include"az_ftp_include.h"

#ifndef _CMD_CB_FUNC_
typedef int(*cmd_cb)(az_ftp_cmd cmd, char *argv);
#define _CMD_CB_FUNC_ 1
#endif

void az_ftp_cmdexec(az_ftp_client client, az_ftp_msg cmd);
int az_ftp_set_uncmd(az_ftp_cmd cmd_type);
int az_ftp_set_cmdcb(az_ftp_cmd cmd_type, cmd_cb cb);

#endif