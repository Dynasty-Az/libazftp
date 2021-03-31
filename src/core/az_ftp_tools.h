#ifndef __AZ_FTP_TOOLS_H_INCLUDE__
#define __AZ_FTP_TOOLS_H_INCLUDE__

#include<azftp/az_ftp_define.h>

typedef struct az_dir_info_s
{
    bool is_dir;
    char path[AZ_FTP_PATH_MAX_LEN];
    int deep;
    char name[AZ_FTP_PATH_MAX_LEN];
    off_t file_size;
}az_dir_info_t, *az_dir_info;

int az_ergodic_lodir(az_list dir_stack, const char *prefix_path, int *dir_deep, char *file_path, bool *is_dir, off_t *file_size);

#endif