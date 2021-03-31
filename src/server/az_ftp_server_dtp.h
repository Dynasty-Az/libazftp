#ifndef __AZ_FTP_SERVER_DTP_H_INCLUDE__
#define __AZ_FTP_SERVER_DTP_H_INCLUDE__

#include"az_ftp_include.h"

void az_ftp_list_task(az_ftp_session session);
void az_ftp_nlist_task(az_ftp_session session);
void az_ftp_upload_task(az_ftp_session session);
void az_ftp_download_task(az_ftp_session session);
//void az_ftp_appeload_task(az_ftp_session session);

void az_ftp_dtp_finish(az_ftp_session session);

#endif