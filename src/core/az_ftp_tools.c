#include"az_ftp_tools.h"

int az_ergodic_lodir(az_list dir_stack, const char *prefix_path, int *dir_deep, char *file_path, bool *is_dir, off_t *file_size)
{
    int ret = 0;
    az_dir_info_t node = { 0 };
    struct dirent *direntp = NULL;

    if (dir_stack == NULL)
        return AZ_ERROR;
    if (dir_deep == NULL)
        return AZ_ERROR;
    if ((prefix_path == NULL || *prefix_path == '\0') && (file_path == NULL || is_dir == NULL))
        return AZ_ERROR;

    if (prefix_path != NULL && *prefix_path != '\0')
    {
        int flag = 0;
        DIR *dir_ptr = NULL;
        struct stat stat_info;

        if (stat(prefix_path, &stat_info) != 0 && !(S_IFDIR & stat_info.st_mode))
            return AZ_ERROR;

        dir_ptr = opendir(prefix_path);
        if (dir_ptr == NULL)
            return AZ_ERROR;

        az_strncpy(node.path, AZ_FTP_PATH_MAX_LEN, prefix_path, az_strlen(prefix_path));
        if (node.path[az_strlen(node.path) - 1] == '/')
            node.path[az_strlen(node.path) - 1] = '\0';
        node.deep = ++(*dir_deep);
        while ((direntp = readdir(dir_ptr)) != NULL)
        {
            char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };

            if (az_strcmp(direntp->d_name, ".") == 0 || az_strcmp(direntp->d_name, "..") == 0)
                continue;

            az_strncpy(node.name, AZ_FTP_PATH_MAX_LEN, direntp->d_name, az_strlen(direntp->d_name));
            if (direntp->d_type == DT_DIR)
                node.is_dir = true;
            else
                node.is_dir = false;

            az_strcatstr(tmp_dir, AZ_FTP_PATH_MAX_LEN, node.path);
            az_strcatchr(tmp_dir, AZ_FTP_PATH_MAX_LEN, '/');
            az_strcatstr(tmp_dir, AZ_FTP_PATH_MAX_LEN, node.name);
            flag = stat(tmp_dir, &stat_info);
            if (flag == 0)
                node.file_size = stat_info.st_size;

            az_list_insert(dir_stack, AZ_LIST_HEAD, 0, &node, sizeof(az_dir_info_t));
            ret++;
        }
        if (ret == 0)
            (*dir_deep)--;
        closedir(dir_ptr);
    }
    else
    {
        if (az_list_pop(dir_stack, AZ_LIST_HEAD, &node, NULL) != AZ_OK)
            return AZ_ERROR;
        if (file_size != NULL)
            *file_size = node.file_size;
        *is_dir = node.is_dir;
        *dir_deep = node.deep;
        if (*node.path != '\0')
        {
            az_strncpy(file_path, AZ_FTP_PATH_MAX_LEN, node.path, az_strlen(node.path));
            az_strcatchr(file_path, AZ_FTP_PATH_MAX_LEN, '/');
        }
        else
            *file_path = '\0';
        az_strcatstr(file_path, AZ_FTP_PATH_MAX_LEN, node.name);
    }

    return ret;
}

