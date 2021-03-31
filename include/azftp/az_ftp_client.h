#ifndef __AZ_FTP_CLIENT_H_INCLUDE__
#define __AZ_FTP_CLIENT_H_INCLUDE__

#ifdef LIBAZFTPCLI_EXPORTS
#   ifndef AZ_LIB_EXPORTS
#       define AZ_LIB_EXPORTS 1
#   endif
#endif

#include<azctools/az_platform.h>

#ifndef LIBAZFTPCLI_EXPORTS
#   ifdef __az_msc__
#       ifndef AZ_LOAD_FTPCLI_LIB
#           pragma message("# QwQ #  az_ftp_client.h: load libazftpcli.lib")
#           pragma comment(lib, "libazftpcli.lib")
#           define AZ_LOAD_FTPCLI_LIB 1
#       endif
#   endif
#endif

#include<azftp/az_ftp_define.h>

#ifndef _AZ_FTP_CLIENT_T_
typedef struct az_ftp_client_s az_ftp_client_t, *az_ftp_client;
#define _AZ_FTP_CLIENT_T_
#endif

AZ_BEGIN_DECLS

AZ_API az_ftp_client az_ftp_client_open(const char *ser_ip, int ser_port, int max_th, bool log_flag);
AZ_API az_ftp_client_status az_ftp_client_stat(az_ftp_client client);
AZ_API const char* az_ftp_client_serhello(az_ftp_client client);

AZ_API az_ret az_ftp_client_login(az_ftp_client client, const char *user_name, const char *password, const char *acct);
AZ_API az_ret az_ftp_client_logout(az_ftp_client client);
AZ_API az_ret az_ftp_client_cwd(az_ftp_client client, const char *path);
AZ_API az_ret az_ftp_client_cdup(az_ftp_client client);

AZ_API az_ret az_ftp_client_set_dtp_mode(az_ftp_client client, az_ftp_dtp_mode type);

AZ_API az_ret az_ftp_client_download(az_ftp_client client, const char *remote_path, const char *local_path, off_t offset);
AZ_API az_ret az_ftp_client_upload(az_ftp_client client, const char *local_path, const char *remote_path, off_t offset);
AZ_API az_ret az_ftp_client_rename(az_ftp_client client, const char *old_name, const char *new_name);
AZ_API az_ret az_ftp_client_delete(az_ftp_client client, const char *file_name);
AZ_API az_ret az_ftp_client_rmd(az_ftp_client client, const char *dir);
AZ_API az_ret az_ftp_client_mkdir(az_ftp_client client, const char *dir_path);
AZ_API const char* az_ftp_client_pwd(az_ftp_client client);
AZ_API az_ret az_ftp_client_list(az_memp pool, az_ftp_client client, const char *path, char **list);
AZ_API az_ret az_ftp_client_nlist(az_memp pool, az_ftp_client client, const char *path, char **list);
AZ_API az_ret az_ftp_client_noop(az_ftp_client client);

AZ_API size_t az_ftp_client_trans_size(az_ftp_client client);
AZ_API az_file_session az_ftp_client_trans_get(az_ftp_client client);
AZ_API az_file_session az_ftp_client_trans_get_index(az_ftp_client client, size_t index);
AZ_API az_ret az_ftp_client_trans_del(az_ftp_client client, az_file_session* sess);

AZ_API void az_ftp_client_close(az_ftp_client *cli);

AZ_END_DECLS

#endif