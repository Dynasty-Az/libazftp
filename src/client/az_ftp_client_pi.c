#include<azftp/az_ftp_client.h>
#include"az_ftp_include.h"
#include"az_ftp_client_dtp.h"
#include<az_ftp_tools.h>

struct az_ftp_client_s
{
    //az_atomic_t state;
    az_ftp_login_status login_state;
    az_memp mp;
    az_taskp tp;
    az_ftp_clictrl ctrl_ctx;
    bool log_flag;

    char ser_ip[AZ_IPV4_ADDRESS_STRING_LEN];
    int ser_port;

    char *user_name;
    char *pwd;
    char *acct;
    char dir_current[AZ_FTP_PATH_MAX_LEN];

    az_list trans_list;

    az_ftp_dtp_mode dtp_mode;
    az_ftp_trans_mode trans_mode;
    az_ftp_data_type data_type;
    az_ftp_format format_type;
    //az_net dtp_fd;
    //char dtp_ip[AZ_IPV4_ADDRESS_STRING_LEN];
    //int dtp_port;
};

static az_ret _az_create_trans(az_ftp_client client, az_trans_type type, const char *remote_path, const char *local_path, off_t offset, bool is_dir, char *list_data);
static inline bool _az_remote_is_dir(const char *data);
static az_ret _az_rmkdir_loop(az_ftp_client client, const char *remote_path);
static az_file_session _az_create_session(az_ftp_client client, az_trans_type type, const char* remote_path, const char* local_path, off_t offset, off_t file_size, bool supplement);
static void _az_destory_session(az_ftp_client client, az_file_session* sess);
//static az_ret _az_create_download_session(az_ftp_client client, const char *remote_path, const char *local_path, off_t offset, char *list_data);
//static az_ret _az_create_upload_session(az_ftp_client client, const char *remote_path, const char *local_path, off_t offset);
static az_ret _az_ergodic_rmdir(az_list dir_stack, char *list_data, char *file_path, bool *is_dir, off_t *file_size);
static az_ret _az_ftp_client_pwd(az_ftp_client client);

az_ftp_client az_ftp_client_open(const char *ser_ip, int ser_port, int max_th, bool log_flag)
{
    az_ret flag = 0;
    az_memp mp = NULL;
    az_ftp_client tmp = NULL;

    if (ser_ip == NULL || *ser_ip == '\0' || az_check_ipv4(ser_ip) != AZ_OK)
    {
        az_writelog(AZ_LOG_ERROR, "111111111111111111111");
        return NULL;
    }
    if (ser_port <= 0)
        ser_port = 21;
    if (max_th <= 0)
        max_th = 1;

    mp = az_memp_create(AZ_MEM_POOL_DEFAULT_SIZE, true);
    if (mp == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "az ftp client: create memory pool failed");
        return NULL;
    }
    tmp = (az_ftp_client)az_mpcalloc(mp, sizeof(az_ftp_client_t));
    if (tmp == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "az ftp client: alloc memory failed");
        goto ERR;
    }

    tmp->mp = mp;
    tmp->log_flag = log_flag;
    az_strncpy(tmp->ser_ip, AZ_IPV4_ADDRESS_STRING_LEN, ser_ip, az_strlen(ser_ip));
    tmp->ser_port = ser_port;
    tmp->tp = az_taskp_create(1, max_th, 0, 0);
    if (tmp->tp == NULL)
    {
        if (tmp->log_flag)
            az_writelog(AZ_LOG_ERROR, "az ftp client: create task pool failed");
        goto ERR;
    }
    tmp->trans_list = az_list_init(AZ_DEF_QUEUE_LIST, 0, sizeof(az_file_session_t), 100, true);
    if (tmp->trans_list == NULL)
    {
        if (tmp->log_flag)
            az_writelog(AZ_LOG_ERROR, "az ftp client: create mini client list failed");
        goto ERR;
    }

    tmp->ctrl_ctx = az_clictrl_create(tmp->mp, ser_ip, ser_port, tmp->log_flag);
    if(tmp->ctrl_ctx==NULL)
    {
        if (tmp->log_flag)
            az_writelog(AZ_LOG_ERROR, "az ftp client: connect server [%s:%d] failed", ser_ip, ser_port);
        goto ERR;
    }

    tmp->login_state = AZ_FTP_NOLOGIN;
    tmp->dtp_mode = DTP_ACTIVE_MODE;
    tmp->trans_mode = TRANS_STREAM_MODE;
    tmp->data_type = AZ_DATA_ASCII;
    tmp->format_type = AZ_FORMAT_NOPRINT;

    return tmp;
ERR:
    if (tmp != NULL)
    {
        if (tmp->ctrl_ctx != NULL)
            az_clictrl_destory(&tmp->ctrl_ctx);
        if (tmp->tp != NULL)
            az_taskp_destory(&tmp->tp);
        if (tmp->trans_list != NULL)
            az_list_destory(&tmp->trans_list);
    }
    if (mp != NULL)
        az_memp_destory(mp);
    return NULL;
}

az_ftp_client_status az_ftp_client_stat(az_ftp_client client)
{
    if (client == NULL)
        return AZ_FTP_CLIENT_ERR;
    return az_clictrl_state(client->ctrl_ctx);
}

const char* az_ftp_client_serhello(az_ftp_client client)
{
    if (client == NULL)
        return NULL;
    return az_clictrl_serhello(client->ctrl_ctx);
}

void az_ftp_client_close(az_ftp_client *cli)
{
    if (*cli == NULL)
        return;

    if (az_clictrl_state((*cli)->ctrl_ctx) == AZ_FTP_CLIENT_RUN)
    {
        //停止正在传输的文件
        if (az_list_size((*cli)->trans_list) > 0)
        {
        }
        //退出登录
        if ((*cli)->login_state == AZ_FTP_OKLOGIN)
            az_ftp_client_logout((*cli));
    }

    az_taskp_destory(&(*cli)->tp);
    az_list_destory(&(*cli)->trans_list);
    az_clictrl_destory(&(*cli)->ctrl_ctx);
    az_memp_destory((*cli)->mp);
    *cli = NULL;
}

az_ret az_ftp_client_login(az_ftp_client client, const char *user_name, const char *password, const char *acct)
{
    char *user = NULL;
    char *pwd = NULL;
    char *act = NULL;
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN)
        return AZ_ERROR;

    if (user_name != NULL && *user_name != '\0')
    {
        user = (char *)az_mpcalloc(client->mp, az_strlen(user_name) + 1);
        if (user == NULL)
            goto ERR;
        az_strncpy(user, az_strlen(user_name) + 1, user_name, az_strlen(user_name));
    }
    if (password != NULL && *password != '\0')
    {
        pwd = (char *)az_mpcalloc(client->mp, az_strlen(password) + 1);
        if (pwd == NULL)
            goto ERR;
        az_strncpy(pwd, az_strlen(password) + 1, password, az_strlen(password));
    }
    if (acct != NULL && *acct != '\0')
    {
        act = (char *)az_mpcalloc(client->mp, az_strlen(acct) + 1);
        if (act == NULL)
            goto ERR;
        az_strncpy(act, az_strlen(acct) + 1, acct, az_strlen(acct));
    }

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_USER, user) != AZ_OK)
        goto ERR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_USER, false);
    if (ev == NULL)
        goto ERR;
    if (ev->code == AZ_FTP_NEED_PASS)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);

        if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_PASS, pwd) != AZ_OK)
            goto ERR;
        ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_PASS, false);
        if (ev == NULL)
            goto ERR;
    }
    //if (ev->code == AZ_FTP_NEED_ACCT_LOGIN)
    //{
    //}
    if (ev->code == AZ_FTP_LOGIN_OK)
        az_clictrl_evfree(client->ctrl_ctx, &ev);
    else
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        goto ERR;
    }

    if (client->user_name != NULL)
        az_mpfree(client->mp, (void **)&client->user_name);
    if (client->pwd != NULL)
        az_mpfree(client->mp, (void **)&client->pwd);
    if (client->acct != NULL)
        az_mpfree(client->mp, (void **)&client->acct);
    client->user_name = user;
    client->pwd = pwd;
    client->acct = act;
    client->login_state = AZ_FTP_OKLOGIN;
    _az_ftp_client_pwd(client);
    return AZ_OK;
ERR:
    if (user != NULL)
        az_mpfree(client->mp, (void **)&user);
    if (pwd != NULL)
        az_mpfree(client->mp, (void **)&pwd);
    if (act != NULL)
        az_mpfree(client->mp, (void **)&act);

    return AZ_ERROR;
}

az_ret az_ftp_client_logout(az_ftp_client client)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_QUIT, NULL) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_QUIT, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_LOGOUT_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }

    az_clictrl_evfree(client->ctrl_ctx, &ev);
    if (client->user_name != NULL)
        az_mpfree(client->mp, (void **)&client->user_name);
    if (client->pwd != NULL)
        az_mpfree(client->mp, (void **)&client->pwd);
    if (client->acct != NULL)
        az_mpfree(client->mp, (void **)&client->acct);
    client->login_state = AZ_FTP_NOLOGIN;

    return AZ_OK;
}

az_ret az_ftp_client_cwd(az_ftp_client client, const char *path)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;
    if (path == NULL || *path == '\0')
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_CWD, path) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_CWD, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_REQ_FILE_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    if (_az_ftp_client_pwd(client) != AZ_OK)
        goto ERR;

    return AZ_OK;
ERR:
    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_CWD, client->dir_current) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_CWD, false);
    if (ev == NULL)
        return AZ_ERROR;
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    return AZ_ERROR;
}

az_ret az_ftp_client_cdup(az_ftp_client client)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_CDUP, NULL) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_CDUP, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_CMD_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(client->ctrl_ctx, &ev);
    
    if (_az_ftp_client_pwd(client) != AZ_OK)
        goto ERR;

    return AZ_OK;
ERR:
    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_CWD, client->dir_current) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_CWD, false);
    if (ev == NULL)
        return AZ_ERROR;
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    return AZ_ERROR;
}

az_ret az_ftp_client_set_dtp_mode(az_ftp_client client, az_ftp_dtp_mode type)
{
    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN)
        return AZ_ERROR;

    client->dtp_mode = type;
    return AZ_OK;
}

//local_path如果不存在就创建目录，如果存在必须是目录
az_ret az_ftp_client_download(az_ftp_client client, const char *remote_path, const char *local_path, off_t offset)
{
    az_ret flag = AZ_OK;
    bool is_dir = false;
    char *list_data_tmp = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN)
        return AZ_ERROR;
    if (remote_path == NULL || *remote_path == '\0')
        return AZ_ERROR;
    if (local_path != NULL && *local_path != '\0')
    {
        struct stat statbuf;

        if (stat(local_path, &statbuf) != 0)
        {
            if (az_mkloop_dir(local_path) != AZ_OK)
                return AZ_ERROR;
        }
        else if (!(S_IFDIR & statbuf.st_mode))
            return AZ_ERROR;
    }
    else
        local_path = "./";
    if (offset < 0)
        offset = 0;
    //获取路径或文件信息
    if (az_ftp_client_list(client->mp, client, remote_path, &list_data_tmp) != AZ_OK || list_data_tmp == NULL)
        return AZ_ERROR;
    is_dir = _az_remote_is_dir(list_data_tmp);
    if (is_dir)
        offset = 0;

    flag = _az_create_trans(client, AZ_FTP_DOWNLOAD, remote_path, local_path, offset, is_dir, list_data_tmp);
    az_mpfree(client->mp, (void **)&list_data_tmp);

    return flag;
}

//local_path只能是本地已存在的文件或路径，remote_path只能是远端已存在的路径
az_ret az_ftp_client_upload(az_ftp_client client, const char *local_path, const char *remote_path, off_t offset)
{
    bool is_dir = false;
    struct stat statbuf;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN)
        return AZ_ERROR;
    if (local_path == NULL || *local_path == '\0')
        return AZ_ERROR;
    if (offset < 0)
        offset = 0;

    if (stat(local_path, &statbuf) != 0)
        return AZ_ERROR;
    if ((S_IFDIR & statbuf.st_mode))
        is_dir = true;
    if (is_dir)
        offset = 0;

    //循环创建远程目录
    if (_az_rmkdir_loop(client, remote_path) != AZ_OK)
        return AZ_ERROR;

    return _az_create_trans(client, AZ_FTP_UPLOAD, remote_path, local_path, offset, is_dir, NULL);
}

az_ret az_ftp_client_rename(az_ftp_client client, const char *old_name, const char *new_name)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;
    if (old_name == NULL || *old_name == '\0' || new_name == NULL || *new_name == '\0')
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_RNFR, old_name) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_RNFR, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_NEED_FURTHER)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_RNTO, new_name) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_RNTO, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_REQ_FILE_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    return AZ_OK;
}

az_ret az_ftp_client_delete(az_ftp_client client, const char *file_name)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;
    if (file_name == NULL || *file_name == '\0')
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_DELE, file_name) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_DELE, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_REQ_FILE_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    return AZ_OK;
}

az_ret az_ftp_client_rmd(az_ftp_client client, const char *dir)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;
    if (dir == NULL || *dir == '\0')
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_RMD, dir) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_RMD, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_REQ_FILE_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    return AZ_OK;
}

az_ret az_ftp_client_mkdir(az_ftp_client client, const char *dir_path)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;
    if (dir_path == NULL || *dir_path == '\0')
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_MKD, dir_path) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_MKD, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_CREATE_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    return AZ_OK;
}

const char* az_ftp_client_pwd(az_ftp_client client)
{
    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return NULL;

    return (const char *)client->dir_current;
}

static az_ret _az_ftp_client_pwd(az_ftp_client client)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_PWD, NULL) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_PWD, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_CREATE_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    if (ev->msg == NULL)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }

    if (*ev->msg != '"' || az_strschr(ev->msg + 1, '"', false) == NULL)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }

    az_strncpy(client->dir_current, AZ_FTP_PATH_MAX_LEN, ev->msg + 1, az_strschr(ev->msg + 1, '"', false) - ev->msg - 1);
    if (az_strlen(client->dir_current) > 1)
        if (client->dir_current[az_strlen(client->dir_current) - 1] == '/')
            client->dir_current[az_strlen(client->dir_current) - 1] = '\0';

    az_clictrl_evfree(client->ctrl_ctx, &ev);
    return AZ_OK;
}

az_ret az_ftp_client_list(az_memp pool, az_ftp_client client, const char *path, char **list)
{
    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;
    //解析每行文件列表
    //sscanf(aaa,"%[^'\t'| ]%*['\t'| ]%[^'\t'| ]%*['\t'| ]%[^'\t'| ]%*['\t'| ]%lld%*['\t'| ]%[^'\t'| ]%*['\t'| ]%[^'\t'| ]%*['\t'| ]%[^'\t'| ]%*['\t'| ]%[^'\r'|'\n']",auth,user,group,&size_d,mouth,day,time,name);
    return az_dtp_list(pool, client->ctrl_ctx, client->dtp_mode, path, list, true);
}

az_ret az_ftp_client_nlist(az_memp pool, az_ftp_client client, const char *path, char **list)
{
    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN || client->login_state != AZ_FTP_OKLOGIN)
        return AZ_ERROR;

    return az_dtp_list(pool, client->ctrl_ctx, client->dtp_mode, path, list, false);
}

az_ret az_ftp_client_noop(az_ftp_client client)
{
    az_clictrl_ev ev = NULL;

    if (client == NULL || az_clictrl_state(client->ctrl_ctx) != AZ_FTP_CLIENT_RUN)
        return AZ_ERROR;

    if (az_clictrl_exec(client->ctrl_ctx, FTP_CMD_NOOP, NULL) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(client->ctrl_ctx, FTP_CMD_NOOP, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_CMD_OK)
    {
        az_clictrl_evfree(client->ctrl_ctx, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(client->ctrl_ctx, &ev);

    return AZ_OK;
}

size_t az_ftp_client_trans_size(az_ftp_client client)
{
    if (client == NULL)
        return 0;
    return az_list_size(client->trans_list);
}

az_file_session az_ftp_client_trans_get(az_ftp_client client)
{
    if (client == NULL)
        return NULL;

    return az_list_getnd(client->trans_list, AZ_LIST_HEAD, NULL);
}

az_file_session az_ftp_client_trans_get_index(az_ftp_client client, size_t index)
{
    if (client == NULL)
        return NULL;
    return az_list_getnd_index(client->trans_list, AZ_LIST_HEAD, index, NULL);
}

az_ret az_ftp_client_trans_del(az_ftp_client client, az_file_session* sess)
{
    if (client == NULL || sess == NULL || *sess == NULL)
        return AZ_ERROR;
    if (az_atomic_read(&(*sess)->trans_state) != AZ_TRANS_END && az_atomic_read(&(*sess)->trans_state) != AZ_TRANS_ABORT && az_atomic_read(&(*sess)->trans_state) != AZ_TRANS_ERR)
        return AZ_ERROR;

    return az_list_delnd(client->trans_list, (void**)sess);
}

static az_ret _az_create_trans(az_ftp_client client, az_trans_type type, const char *remote_path, const char *local_path, off_t offset, bool is_dir, char *list_data)
{
    off_t file_size = 0;
    az_file_session sess = NULL;
    az_client_info_t info = { 0 };

    info.ser_ip = client->ser_ip;
    info.ser_port = client->ser_port;
    info.user = client->user_name;
    info.pwd = client->pwd;
    info.current_dir = client->dir_current;
    info.trans_mode = client->trans_mode;
    info.dtp_mode = client->dtp_mode;

    switch (type)
    {
    case AZ_FTP_DOWNLOAD:
        if (is_dir)
        {
            int loop = 0;
            az_list dir_stack = NULL;
            char *tmp_list_data = list_data;
            char dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
            char path[AZ_FTP_PATH_MAX_LEN] = { 0 };
            char lo_path[AZ_FTP_PATH_MAX_LEN] = { 0 };

            for (loop = az_strlen(remote_path) - 1; loop > 0; loop--)
            {
                if (remote_path[loop] == '/')
                    break;
            }
            if (loop != 0)
                loop++;
            az_strncpy(dir, AZ_FTP_PATH_MAX_LEN, &remote_path[loop], az_strlen(&remote_path[loop]));

            dir_stack = az_list_init(AZ_STACK_LIST, 0, sizeof(az_dir_info_t), 50, false);
            if (dir_stack == NULL)
                return AZ_ERROR;

            if (_az_ergodic_rmdir(dir_stack, tmp_list_data, (char*)remote_path, &is_dir, &file_size) != AZ_OK)
            {
                az_list_destory(&dir_stack);
                return AZ_ERROR;
            }
            while (az_list_size(dir_stack) > 0)
            {
                char* tmp = NULL;

                az_strncpy(lo_path, AZ_FTP_PATH_MAX_LEN, local_path, az_strlen(local_path));
                if (lo_path[az_strlen(lo_path) - 1] == '/')
                    lo_path[az_strlen(lo_path) - 1] = '\0';

                if (_az_ergodic_rmdir(dir_stack, NULL, path, &is_dir, &file_size) != AZ_OK)
                {
                    az_list_destory(&dir_stack);
                    return AZ_ERROR;
                }
                tmp = az_strsstr(path, dir);
                if (is_dir)
                {
                    az_strcatchr(lo_path, AZ_FTP_PATH_MAX_LEN, '/');
                    az_strcatstr(lo_path, AZ_FTP_PATH_MAX_LEN, tmp);
                    az_mkloop_dir(lo_path);

                    if (az_ftp_client_list(client->mp, client, path, &tmp_list_data) != AZ_OK)
                    {
                        az_list_destory(&dir_stack);
                        return AZ_ERROR;
                    }
                    if (_az_ergodic_rmdir(dir_stack, tmp_list_data, path, NULL, NULL) != AZ_OK)
                    {
                        az_list_destory(&dir_stack);
                        az_mpfree(client->mp, (void **)&tmp_list_data);
                        return AZ_ERROR;
                    }
                    az_mpfree(client->mp, (void **)&tmp_list_data);
                }
                else
                {
                    az_strcatchr(lo_path, AZ_FTP_PATH_MAX_LEN, '/');
                    az_strcatstr(lo_path, AZ_FTP_PATH_MAX_LEN, tmp);

                    sess = _az_create_session(client, type, path, lo_path, 0, file_size, false);
                    if (sess == NULL)
                    {
                        az_list_destory(&dir_stack);
                        return AZ_ERROR;
                    }
                    if (az_dtp_trans(client->tp, info, sess, client->log_flag) != AZ_OK)
                    {
                        _az_destory_session(client, &sess);
                        az_list_destory(&dir_stack);
                        return AZ_ERROR;
                    }
                }
            }

            az_list_destory(&dir_stack);
        }
        else
        {
            int ret = sscanf(list_data, "%*[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%ld", &file_size);

            sess = _az_create_session(client, type, remote_path, local_path, offset, file_size, true);
            if (sess == NULL)
                return AZ_ERROR;
            if (az_dtp_trans(client->tp, info, sess, client->log_flag) != AZ_OK)
            {
                _az_destory_session(client, &sess);
                return AZ_ERROR;
            }
        }
        break;
    case AZ_FTP_UPLOAD:
        if (is_dir)
        {
            int loop = 0;
            az_list dir_stack = NULL;
            int deep = 0;
            char *tmp_list_data = list_data;
            char dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
            char path[AZ_FTP_PATH_MAX_LEN] = { 0 };
            char rm_path[AZ_FTP_PATH_MAX_LEN] = { 0 };

            for (loop = az_strlen(local_path) - 1; loop > 0; loop--)
            {
                if (local_path[loop] == '/')
                    break;
            }
            if (loop != 0)
                loop++;
            az_strncpy(dir, AZ_FTP_PATH_MAX_LEN, &local_path[loop], az_strlen(&local_path[loop]));
            if (dir[az_strlen(dir) - 1] == '/')
                dir[az_strlen(dir) - 1] = '\0';

            az_strncpy(rm_path, AZ_FTP_PATH_MAX_LEN, remote_path, az_strlen(remote_path));
            if (rm_path[az_strlen(rm_path) - 1] != '/')
                az_strcatchr(rm_path, AZ_FTP_PATH_MAX_LEN, '/');
            az_strcatstr(rm_path, AZ_FTP_PATH_MAX_LEN, dir);
            if (az_ftp_client_mkdir(client, rm_path) != AZ_OK)
                return AZ_ERROR;

            dir_stack = az_list_init(AZ_STACK_LIST, 0, sizeof(az_dir_info_t), 50, false);
            if (dir_stack == NULL)
                return AZ_ERROR;

            if (az_ergodic_lodir(dir_stack, local_path, &deep, NULL, NULL, NULL) < 0)
            {
                az_list_destory(&dir_stack);
                return AZ_ERROR;
            }

            while (az_list_size(dir_stack) > 0)
            {
                char *tmp = NULL;

                az_strncpy(rm_path, AZ_FTP_PATH_MAX_LEN, remote_path, az_strlen(remote_path));
                if (rm_path[az_strlen(rm_path) - 1] == '/')
                    rm_path[az_strlen(rm_path) - 1] = '\0';

                if (az_ergodic_lodir(dir_stack, NULL, &deep, path, &is_dir, &file_size) < 0)
                {
                    az_list_destory(&dir_stack);
                    return AZ_ERROR;
                }
                tmp = az_strsstr(path, dir);
                if (is_dir)
                {
                    az_strcatchr(rm_path, AZ_FTP_PATH_MAX_LEN, '/');
                    az_strcatstr(rm_path, AZ_FTP_PATH_MAX_LEN, tmp);

                    if (az_ftp_client_mkdir(client, rm_path) != AZ_OK)
                    {
                        az_list_destory(&dir_stack);
                        return AZ_ERROR;
                    }

                    if (az_ergodic_lodir(dir_stack, path, &deep, NULL, NULL, NULL) < 0)
                    {
                        az_list_destory(&dir_stack);
                        return AZ_ERROR;
                    }
                }
                else
                {
                    az_strcatchr(rm_path, AZ_FTP_PATH_MAX_LEN, '/');
                    az_strcatstr(rm_path, AZ_FTP_PATH_MAX_LEN, tmp);

                    sess = _az_create_session(client, type, rm_path, path, 0, file_size, false);
                    if (sess == NULL)
                    {
                        az_list_destory(&dir_stack);
                        return AZ_ERROR;
                    }
                    if (az_dtp_trans(client->tp, info, sess, client->log_flag) != AZ_OK)
                    {
                        _az_destory_session(client, &sess);
                        az_list_destory(&dir_stack);
                        return AZ_ERROR;
                    }
                }
            }

            az_list_destory(&dir_stack);
        }
        else
        {
            struct stat statbuf;

            if (stat(local_path, &statbuf) != 0)
                return AZ_ERROR;
            file_size = statbuf.st_size;

            sess = _az_create_session(client, type, remote_path, local_path, offset, file_size, true);
            if (sess == NULL)
                return AZ_ERROR;
            if (az_dtp_trans(client->tp, info, sess, client->log_flag) != AZ_OK)
            {
                _az_destory_session(client, &sess);
                return AZ_ERROR;
            }
        }
        break;
    default:
        return AZ_ERROR;
        break;
    }

    return AZ_OK;
}

static inline bool _az_remote_is_dir(const char *data)
{
    char *flag = NULL;

    flag = az_strsstr(data, "\r\n");
    if (flag != NULL)
    {
        flag += 2;
        flag = az_strsstr(flag, "\r\n");
        if (flag != NULL)
            return true;
        else
        {
            char auth[10] = { 0 };
            sscanf(data, "%[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*ld%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*[^'\r'|'\n']", auth);
            if (*auth == 'd')
                return true;
        }
    }

    return false;
}

static az_ret _az_rmkdir_loop(az_ftp_client client, const char *remote_path)
{
    char *end = NULL;
    char tmp_path[AZ_FTP_PATH_MAX_LEN] = { 0 };
    az_clictrl_ev ev = NULL;

    if (remote_path == NULL || *remote_path == '\0')
        return AZ_ERROR;

    az_strncpy(tmp_path, AZ_FTP_PATH_MAX_LEN, remote_path, az_strlen(remote_path));
    for (end = tmp_path; *end != '\0'; end++)
    {
        end = az_strschr(end, '/', false);
        if (end == NULL)
            end = &tmp_path[az_strlen(tmp_path) - 1];
        else
            *end = '\0';

        if (az_ftp_client_mkdir(client, tmp_path) != AZ_OK)
            return AZ_ERROR;

        if (*end == '\0')
            *end = '/';
    }

    return AZ_OK;
}

static az_file_session _az_create_session(az_ftp_client client, az_trans_type type, const char *remote_path, const char *local_path, off_t offset, off_t file_size, bool supplement)
{
    int loop = 0;
    az_file_session tmp = NULL;

    tmp = az_list_allocnd(client->trans_list, sizeof(az_file_session_t));
    if (tmp == NULL)
        return NULL;

    tmp->trans_type = type;
    az_atomic_set(&tmp->trans_state, AZ_TRANS_INIT);
    az_strncpy(tmp->remote_path, AZ_FTP_PATH_MAX_LEN, remote_path, az_strlen(remote_path));
    az_strncpy(tmp->local_path, AZ_FTP_PATH_MAX_LEN, local_path, az_strlen(local_path));
    if (type == AZ_FTP_DOWNLOAD && supplement)
    {
        for (loop = az_strlen(remote_path) - 1; loop >= 0; loop--)
        {
            if (remote_path[loop] == '/')
                break;
        }
        loop++;
        if (tmp->local_path[az_strlen(tmp->local_path) - 1] != '/')
            az_strcatchr(tmp->local_path, AZ_FTP_PATH_MAX_LEN, '/');
        az_strcatstr(tmp->local_path, AZ_FTP_PATH_MAX_LEN, &remote_path[loop]);
    }
    else if(type == AZ_FTP_UPLOAD && supplement)
    {
        for (loop = az_strlen(local_path) - 1; loop >= 0; loop--)
        {
            if (local_path[loop] == '/')
                break;
        }
        loop++;
        if (tmp->remote_path[az_strlen(tmp->remote_path) - 1] != '/')
            az_strcatchr(tmp->remote_path, AZ_FTP_PATH_MAX_LEN, '/');
        az_strcatstr(tmp->remote_path, AZ_FTP_PATH_MAX_LEN, &local_path[loop]);
    }
    tmp->file_size = file_size;
    tmp->offset = offset;
    az_atomic64_set(&tmp->up_down_len, 0);

    az_list_insertnd(client->trans_list, AZ_LIST_HEAD, az_list_size(client->trans_list), tmp);

    return tmp;
}

static void _az_destory_session(az_ftp_client client, az_file_session* sess)
{
    az_list_delnd(client->trans_list, (void**)sess);
}

static az_ret _az_ergodic_rmdir(az_list dir_stack, char *list_data, char *file_path, bool *is_dir, off_t *file_size)
{
    az_dir_info_t node = { 0 };

    if (dir_stack == NULL)
        return AZ_ERROR;
    if (list_data == NULL && (file_path == NULL || is_dir == NULL || file_size == NULL))
        return AZ_ERROR;

    if (list_data != NULL && *list_data != '\0')
    {
        char *start = NULL;
        char *end = NULL;

        az_strncpy(node.path, AZ_FTP_PATH_MAX_LEN, file_path, az_strlen(file_path));
        if (node.path[az_strlen(node.path) - 1] == '/')
            node.path[az_strlen(node.path) - 1] = '\0';
        for (start = list_data; *start != '\0'; start = end + 2)
        {
            char auth[10] = { 0 };

            end = az_strsstr(start, "\r\n");
            if (end == NULL)
                return AZ_ERROR;

            *end = '\0';
            sscanf(start, "%[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%ld%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%*[^'\t'| ]%*['\t'| ]%[^'\r'|'\n']", auth, &node.file_size, node.name);
            if (*auth == 'd')
                node.is_dir = true;
            else
                node.is_dir = false;
            *end = '\r';

            if (az_strcmp(node.name, ".") != 0 && az_strcmp(node.name, "..") != 0)
                az_list_insert(dir_stack, AZ_LIST_HEAD, 0, &node, sizeof(az_dir_info_t));
        }
    }
    else
    {
        if (az_list_pop(dir_stack, AZ_LIST_HEAD, &node, NULL) != AZ_OK)
            return AZ_ERROR;
        *file_size = node.file_size;
        *is_dir = node.is_dir;
        if (*node.path != '\0')
        {
            az_strncpy(file_path, AZ_FTP_PATH_MAX_LEN, node.path, az_strlen(node.path));
            az_strcatchr(file_path, AZ_FTP_PATH_MAX_LEN, '/');
        }
        else
            *file_path = '\0';
        az_strcatstr(file_path, AZ_FTP_PATH_MAX_LEN, node.name);
    }

    return AZ_OK;
}
