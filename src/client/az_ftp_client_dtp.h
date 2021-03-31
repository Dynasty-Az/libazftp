#ifndef __AZ_FTP_CLIENT_DTP_H_INCLUDE__
#define __AZ_FTP_CLIENT_DTP_H_INCLUDE__

#include"az_ftp_include.h"
#include"az_ftp_client_ctrl.h"

az_ret az_dtp_list(az_memp pool, az_ftp_clictrl ctrl, az_ftp_dtp_mode dtp_mode, const char *path, char **data, bool ex);
az_ret az_dtp_trans(az_taskp tp, az_client_info_t info, az_file_session trans_info, bool log_flag);

#endif