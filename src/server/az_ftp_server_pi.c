#include"az_ftp_server_pi.h"
#include"az_ftp_server_dtp.h"
#include<az_ftp_tools.h>

typedef void(*cmd_handler)(az_ftp_client client, az_ftp_msg cmd);

typedef struct az_ftp_cmd_handle_s
{
    const char *cmd;
    az_ftp_cmd index;
    cmd_handler hdl;
    cmd_cb cb;
} az_ftp_cmd_handle_t, *az_ftp_cmd_handle;

typedef enum az_dtp_session_type_e
{
    AZ_UPLOAD_DTP = 0,
    AZ_DOWNLOAD_DTP,
    AZ_APPELOAD_DTP,
    AZ_STOULOAD_DTP,
    AZ_LIST_DTP,
    AZ_NLIST_DTP
}az_dtp_type;

static int __az_ftp_change_workdir(const char *change, int *dir_deep, char *work_dir, bool is_exit, bool is_dir);
static char* __az_rand_str(char *str, int len);
static char ___az_rand_char_letter(void);
static void _az_ftp_cmd_unknown(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_user(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_pass(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_cwd(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_cdup(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_rein(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_quit(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_port(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_pasv(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_type(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_mode(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_retr(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_stor(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_stou(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_appe(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_rest(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_rnfr(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_rnto(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_abor(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_dele(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_rmd(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_mkd(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_pwd(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_list(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_nlst(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_syst(az_ftp_client client, az_ftp_msg cmd);
static void _az_ftp_cmd_noop(az_ftp_client client, az_ftp_msg cmd);

static int __az_create_dtp_session(az_ftp_client client, az_dtp_type type, char *file_name);
static az_ret __az_loop_rmdir(const char *path);

static az_ftp_cmd_handle_t ctrl_cmds[] = {
    { "", FTP_CMD_UNKNOWN, _az_ftp_cmd_unknown, NULL },
    { "USER", FTP_CMD_USER, _az_ftp_cmd_user, NULL },
    { "PASS", FTP_CMD_PASS, _az_ftp_cmd_pass, NULL },
    { "ACCT", FTP_CMD_ACCT, NULL, NULL },
    { "CWD", FTP_CMD_CWD, _az_ftp_cmd_cwd, NULL },
    { "CDUP", FTP_CMD_CDUP, _az_ftp_cmd_cdup, NULL },
    { "SMNT", FTP_CMD_SMNT, NULL, NULL },
    { "REIN", FTP_CMD_REIN, _az_ftp_cmd_rein, NULL },
    { "QUIT", FTP_CMD_QUIT, _az_ftp_cmd_quit, NULL },
    { "PORT", FTP_CMD_PORT, _az_ftp_cmd_port, NULL },
    { "PASV", FTP_CMD_PASV, _az_ftp_cmd_pasv, NULL },
    { "TYPE", FTP_CMD_TYPE, _az_ftp_cmd_type, NULL },
    { "STRU", FTP_CMD_STRU, NULL, NULL },
    { "MODE", FTP_CMD_MODE, _az_ftp_cmd_mode, NULL },
    { "RETR", FTP_CMD_RETR, _az_ftp_cmd_retr, NULL },
    { "STOR", FTP_CMD_STOR, _az_ftp_cmd_stor, NULL },
    { "STOU", FTP_CMD_STOU, _az_ftp_cmd_stou, NULL },
    { "APPE", FTP_CMD_APPE, _az_ftp_cmd_appe, NULL },
    { "ALLO", FTP_CMD_ALLO, NULL, NULL },
    { "REST", FTP_CMD_REST, _az_ftp_cmd_rest, NULL },
    { "RNFR", FTP_CMD_RNFR, _az_ftp_cmd_rnfr, NULL },
    { "RNTO", FTP_CMD_RNTO, _az_ftp_cmd_rnto, NULL },
    { "ABOR", FTP_CMD_ABOR, _az_ftp_cmd_abor, NULL },
    { "DELE", FTP_CMD_DELE, _az_ftp_cmd_dele, NULL },
    { "RMD", FTP_CMD_RMD, _az_ftp_cmd_rmd, NULL },
    { "MKD", FTP_CMD_MKD, _az_ftp_cmd_mkd, NULL },
    { "PWD", FTP_CMD_PWD, _az_ftp_cmd_pwd, NULL },
    { "LIST", FTP_CMD_LIST, _az_ftp_cmd_list, NULL },
    { "NLST", FTP_CMD_NLST, _az_ftp_cmd_nlst, NULL },
    { "SITE", FTP_CMD_SITE, NULL, NULL },
    { "SYST", FTP_CMD_SYST, _az_ftp_cmd_syst, NULL },
    { "STAT", FTP_CMD_STAT, NULL, NULL },
    { "HELP", FTP_CMD_HELP, NULL, NULL },
    { "NOOP", FTP_CMD_NOOP, _az_ftp_cmd_noop, NULL }
};

void az_ftp_cmdexec(az_ftp_client client, az_ftp_msg cmd)
{
    char text[1024] = { 0 };
    if (client == NULL || cmd == NULL)
        return;

    if (!msg_is_cmd(cmd))
        return;

    if (cmd->cmd_index<FTP_CMD_UNKNOWN || cmd->cmd_index>FTP_CMD_NOOP)
        return;

    snprintf(text, 1024, "%s", az_ftp_msg_to_str(cmd));
    text[az_strlen(text) - 2] = '\0';
    az_writelog(AZ_LOG_DEBUG, "client [%s:%d] exec cmd :%s", client->netinfo.remote_ip, client->netinfo.remote_port, text);

    if (ctrl_cmds[cmd->cmd_index].hdl == NULL)
        az_ftp_response(client, AZ_FTP_CMD_SPFUS, NULL);
    else
        ctrl_cmds[cmd->cmd_index].hdl(client, cmd);
}

int az_ftp_set_uncmd(az_ftp_cmd cmd_type)
{
    if (cmd_type < FTP_CMD_UNKNOWN || cmd_type >= FTP_CMD_COUNT)
        return AZ_ERROR;
    ctrl_cmds[cmd_type].hdl = NULL;
    return AZ_OK;
}

int az_ftp_set_cmdcb(az_ftp_cmd cmd_type, cmd_cb cb)
{
    if (cmd_type < FTP_CMD_UNKNOWN || cmd_type >= FTP_CMD_COUNT || cb == NULL)
        return AZ_ERROR;

    if (ctrl_cmds[cmd_type].hdl == NULL)
        return AZ_ERROR;

    ctrl_cmds[cmd_type].cb = cb;
    return AZ_OK;
}

static void _az_ftp_cmd_unknown(az_ftp_client client, az_ftp_msg cmd)
{
    if (client == NULL || cmd == NULL)
        return;

    az_ftp_response(client, AZ_FTP_CMD_NOT_IMPT, NULL);
}

static int __az_ftp_check_user(az_ftp_client client, const char *user)
{
    FILE *fp = NULL;
    bool flag = false;
    char *bufflag = NULL;
    char line[CONFIG_LINE_SIZE] = { 0 };
    char name[AZ_FTP_USER_LEN] = { 0 };
    char pwd[AZ_FTP_PWD_LEN] = { 0 };
    int ret = 0;

    fp = fopen(client->auth_dir, "r"); //打开认证文件（记录用户名和密码）
    if (fp == NULL)
        return AZ_ERROR;

    if (feof(fp) != 0)
    {
        fclose(fp);
        return AZ_ERROR;
    }

    while (!feof(fp))
    {
        Az_Memzero(line, CONFIG_LINE_SIZE);
        Az_Memzero(name, AZ_FTP_USER_LEN);
        Az_Memzero(pwd, AZ_FTP_PWD_LEN);

        bufflag = fgets(line, CONFIG_LINE_SIZE, fp);
        if (bufflag != NULL&&*bufflag != '#')
        {
            ret = sscanf(line, "%[^:]%*[:]%[^'\t'|'\r'|'\n'| |#]", name, pwd);
            if (az_strcmp(user, name) == 0)
            {
                az_strncpy(client->user, AZ_FTP_USER_LEN, name, az_strlen(name));
                az_strncpy(client->pwd, AZ_FTP_PWD_LEN, pwd, az_strlen(pwd));
                flag = true;
                break;
            }
        }
    }
    fclose(fp);

    if (flag)
        return AZ_OK;

    return AZ_ERROR;
}

static int __az_ftp_check_pwd(az_ftp_client client, const char *pwd)
{
    if (*client->pwd == '\0')
        return AZ_OK;

    if (az_strcmp(client->pwd, pwd) == 0)
        return AZ_OK;

    return AZ_ERROR;
}

static void _az_ftp_cmd_user(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    //az_ftp_msg reply = NULL;

    if (client == NULL || cmd == NULL)
        return;

    if (az_ftp_msg_get_argc(cmd) != 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    if (client->log_stat == AZ_FTP_OKLOGIN)
    {
        if (az_strcmp(az_ftp_msg_get_argv(cmd, 1), client->user) == 0)
            az_ftp_response(client, AZ_FTP_LOGIN_OK, NULL);
        else
            az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
    }
    else
    {
        flag = __az_ftp_check_user(client, az_ftp_msg_get_argv(cmd, 1));
        if (flag == AZ_OK)
        {
            if (*client->pwd == '\0')
            {
                client->log_stat = AZ_FTP_OKLOGIN;
                az_ftp_response(client, AZ_FTP_LOGIN_OK, NULL);
            }
            else
            {
                client->log_stat = AZ_FTP_DEALLOGIN;
                az_ftp_response(client, AZ_FTP_NEED_PASS, NULL);
            }
        }
        else
            az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
    }
}

static void _az_ftp_cmd_pass(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat == AZ_FTP_NOLOGIN)
        az_ftp_response(client, AZ_FTP_CMD_BAD_SEQ, NULL);
    else if (client->log_stat == AZ_FTP_DEALLOGIN)
    {
        if (az_ftp_msg_get_argc(cmd) != 1)
            az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        else
        {
            flag = __az_ftp_check_pwd(client, az_ftp_msg_get_argv(cmd, 1));
            if (flag == AZ_OK)
            {
                client->log_stat = AZ_FTP_OKLOGIN;
                az_ftp_response(client, AZ_FTP_LOGIN_OK, NULL);
            }
            else
                az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        }
    }
    else
    {

    }
}

static void _az_ftp_cmd_cwd(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int loop = 0;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char text[1024] = { 0 };

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    az_writelog(AZ_LOG_DEBUG, "before cwd dir-deep [%d] work-dir [%s]", client->dir_deep, client->work_dir);
    flag = __az_ftp_change_workdir(ch_dir, &client->dir_deep, client->work_dir, true, true);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    snprintf(text, 1024, "\"/%s\" ok.", client->work_dir);

    az_ftp_response(client, AZ_FTP_REQ_FILE_OK, text);
}

static void _az_ftp_cmd_cdup(az_ftp_client client, az_ftp_msg cmd)
{
    int loop = 0;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    if (client->dir_deep - 1 < 0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }
    else if (client->dir_deep - 1 == 0)
    {
        client->dir_deep = 0;
        *client->work_dir = '\0';
    }
    else
    {
        for (loop = az_strlen(client->work_dir) - 1; loop >= 0; loop--)
        {
            if (client->work_dir[loop] == '/')
                break;
        }
        client->work_dir[loop] = '\0';
        client->dir_deep--;
    }

    az_ftp_response(client, AZ_FTP_CMD_OK, NULL);
}

static void _az_ftp_cmd_rein(az_ftp_client client, az_ftp_msg cmd)
{
    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    Az_Memzero(client->user, AZ_FTP_USER_LEN);
    Az_Memzero(client->pwd, AZ_FTP_PWD_LEN);
    Az_Memzero(client->work_dir, AZ_FTP_PATH_MAX_LEN);
    client->dtp_mode = DTP_ACTIVE_MODE;
    az_strncpy(client->dtp_ip, AZ_IPV6_ADDRESS_STRING_LEN, client->netinfo.remote_ip, az_strlen(client->netinfo.remote_ip));
    client->dtp_port = client->netinfo.remote_port - 1;

    client->log_stat = AZ_FTP_NOLOGIN;

    az_ftp_response(client, AZ_FTP_CMD_OK, NULL);
}

static void _az_ftp_cmd_quit(az_ftp_client client, az_ftp_msg cmd)
{
    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    if (az_list_size(client->session_list) != 0)
    {
        while (az_atomic_read(&client->stat) == AZ_FTP_CLIENT_RUN && az_list_size(client->session_list) > 0)
            az_msleep(100);
    }

    az_atomic_set(&client->stat, AZ_FTP_CLIENT_CLOSE);
    az_ftp_response(client, AZ_FTP_LOGOUT_OK, NULL);
}

static void _az_ftp_cmd_port(az_ftp_client client, az_ftp_msg cmd)
{
    int port = 0;
    char p1[8] = { 0 };
    char p2[8] = { 0 };
    char h1[4] = { 0 };
    char h2[4] = { 0 };
    char h3[4] = { 0 };
    char h4[4] = { 0 };
    char ip[AZ_IPV6_ADDRESS_STRING_LEN] = { 0 };
    const char *argv = NULL;
    int ret = 0;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    if (az_ftp_msg_get_argc(cmd) != 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    argv = az_ftp_msg_get_argv(cmd, 1);
    if (argv == NULL)
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }
    ret = sscanf(argv, "%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]", h1, h2, h3, h4, p1, p2);
    if (*h1 == '\0' || *h2 == '\0' || *h3 == '\0' || *h4 == '\0' || *p1 == '\0' || *p2 == '\0')
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    snprintf(ip, AZ_IPV6_ADDRESS_STRING_LEN, "%s.%s.%s.%s", h1, h2, h3, h4);
    if (az_check_ipv4(ip) != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }
    port = atoi(p1) * 256 + atoi(p2);
    if (port <= 0 || port >= 65535)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    client->dtp_mode = DTP_ACTIVE_MODE;
    az_strncpy(client->dtp_ip, AZ_IPV6_ADDRESS_STRING_LEN, ip, az_strlen(ip));
    client->dtp_port = port;
    if (client->pasv_fd != NULL)
        az_close_socket(&client->pasv_fd);

    az_ftp_response(client, AZ_FTP_CMD_OK, NULL);
}

static void _az_ftp_cmd_pasv(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int p1 = 0;
    int p2 = 0;
    char h1[4] = { 0 };
    char h2[4] = { 0 };
    char h3[4] = { 0 };
    char h4[4] = { 0 };
    az_net pasv_fd = NULL;
    int def_pasv_port = 10000;
    char text[128] = { 0 };

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    if (az_ftp_msg_get_argc(cmd) != 0)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    pasv_fd = az_create_socket(client->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
    if (pasv_fd == NULL)
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    do
    {
        flag = az_bind_socket(pasv_fd, client->netinfo.local_ip, def_pasv_port);
        if (flag == AZ_OK)
            break;
        def_pasv_port++;
        if (def_pasv_port >= 65535)
            def_pasv_port = 10000;
    } while (1);
    flag = az_listen_socket(pasv_fd, 1);
    if (flag != AZ_OK)
    {
        az_close_socket(&pasv_fd);
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    client->pasv_fd = pasv_fd;
    client->dtp_mode = DTP_PASSIVE_MODE;
    az_strncpy(client->dtp_ip, AZ_IPV6_ADDRESS_STRING_LEN, client->netinfo.local_ip, az_strlen(client->netinfo.local_ip));
    client->dtp_port = def_pasv_port;

    p1 = client->dtp_port / 256;
    p2 = client->dtp_port % 256;
    flag = sscanf(client->dtp_ip, "%[0-9].%[0-9].%[0-9].%[0-9]", h1, h2, h3, h4);
    snprintf(text, 128, "Entering Passive Mode (%s,%s,%s,%s,%d,%d).", h1, h2, h3, h4, p1, p2);

    az_ftp_response(client, AZ_FTP_PASV_OK, text);
}

static void _az_ftp_cmd_type(az_ftp_client client, az_ftp_msg cmd)
{
    az_ftp_data_type data_type = AZ_DATA_ASCII;
    az_ftp_format data_format = AZ_FORMAT_NOPRINT;
    int local_len = 0;
    char text[1024] = { 0 };

    if (client == NULL || cmd == NULL)
        return;

    if (az_ftp_msg_get_argc(cmd) == 0)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    if (az_ftp_msg_get_argc(cmd) >= 1)
    {
        switch (*az_ftp_msg_get_argv(cmd, 1))
        {
        case 'A':
        case 'a':
            data_type = AZ_DATA_ASCII;
            break;
        case 'E':
        case 'e':
            data_type = AZ_DATA_EBCDIC;
            break;
        case 'I':
        case 'i':
            data_type = AZ_DATA_IMAGE;
            break;
        case 'L':
        case 'l':
            data_type = AZ_DATA_LOCAL;
            break;
        default:
            az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
            return;
            break;
        }
    }
    if (az_ftp_msg_get_argc(cmd) >= 2)
    {
        if (data_type <= AZ_DATA_EBCDIC)
        {
            switch (*az_ftp_msg_get_argv(cmd, 2))
            {
            case 'N':
            case 'n':
                data_format = AZ_FORMAT_NOPRINT;
                break;
            case 'T':
            case 't':
                data_format = AZ_FORMAT_TELNET;
                break;
            case 'C':
            case 'c':
                data_format = AZ_FORMAT_CONTROL;
                break;
            }
        }
        else if (data_type == AZ_DATA_LOCAL)
        {
            local_len = atoi(az_ftp_msg_get_argv(cmd, 2));
            if (local_len <= 0)
            {
                az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
                return;
            }
        }
    }

    if ((data_type != AZ_DATA_ASCII && data_type != AZ_DATA_IMAGE) || data_format != AZ_FORMAT_NOPRINT)
    {
        az_ftp_response(client, AZ_FTP_CMD_NOT_IMPT_PAR, NULL);
        return;
    }

    client->data_type = data_type;
    client->data_format = data_format;
    client->local_len = local_len;
    az_strcatstr(text, 1024, "type set to ");
    switch (data_type)
    {
    case AZ_DATA_ASCII:
        az_strcatchr(text, 1024, 'A');
        break;
    case AZ_DATA_EBCDIC:
        az_strcatchr(text, 1024, 'E');
        break;
    case AZ_DATA_IMAGE:
        az_strcatchr(text, 1024, 'I');
        break;
    case AZ_DATA_LOCAL:
        az_strcatchr(text, 1024, 'L');
        break;
    default:
        break;
    }
    if (data_type <= AZ_DATA_EBCDIC)
    {
        switch (data_format)
        {
        case AZ_FORMAT_NOPRINT:
            az_strcatstr(text, 1024, " N");
            break;
        case AZ_FORMAT_TELNET:
            az_strcatstr(text, 1024, " T");
            break;
        case AZ_FORMAT_CONTROL:
            az_strcatstr(text, 1024, " C");
            break;
        default:
            break;
        }
    }
    else if (data_type == AZ_DATA_LOCAL)
        snprintf(text + az_strlen(text), 1024 - az_strlen(text), " %d", local_len);

    az_ftp_response(client, AZ_FTP_CMD_OK, text);
}

static void _az_ftp_cmd_mode(az_ftp_client client, az_ftp_msg cmd)
{
    const char *argv = NULL;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    if (az_ftp_msg_get_argc(cmd) != 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }
    argv = az_ftp_msg_get_argv(cmd, 1);
    if (argv == NULL)
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    if (*argv == 'S' || *argv == 's')
    {
        client->trans_mode = TRANS_STREAM_MODE;
        az_ftp_response(client, AZ_FTP_CMD_OK, NULL);
    }
    else
    {
        az_ftp_response(client, AZ_FTP_CMD_NOT_IMPT_PAR, NULL);
    }
}

static void _az_ftp_cmd_retr(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int loop = 0;
    int deep = 0;
    //char *argv = NULL;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char ld_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    struct stat statbuf;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    deep = client->dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, false, false);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }
    az_strncpy(ld_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(ld_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(ld_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(ld_dir, _A_NORMAL);
#else
    flag = access(ld_dir, F_OK);
#endif
    if (flag != 0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }
    if (stat(ld_dir, &statbuf) != 0 || (S_IFDIR & statbuf.st_mode))
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    flag = __az_create_dtp_session(client, AZ_DOWNLOAD_DTP, ld_dir);
    if (flag != AZ_OK)
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
}

static void _az_ftp_cmd_stor(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int loop = 0;
    int deep = 0;
    //char *argv = NULL;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char ld_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    struct stat statbuf;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    deep = client->dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, false, false);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }
    az_strncpy(ld_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(ld_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(ld_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(ld_dir, _A_NORMAL);
#else
    flag = access(ld_dir, F_OK);
#endif
    if (flag == 0)
    {
        if (stat(ld_dir, &statbuf) != 0 || (S_IFDIR & statbuf.st_mode))
        {
            az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
            return;
        }
    }

    flag = __az_create_dtp_session(client, AZ_UPLOAD_DTP, ld_dir);
    if (flag != AZ_OK)
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
}

static void _az_ftp_cmd_stou(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    char ld_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) != 0)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    az_strncpy(ld_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(ld_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(ld_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir);
    az_strcatchr(ld_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(ld_dir, AZ_FTP_PATH_MAX_LEN, "stou_");
    __az_rand_str(ld_dir + az_strlen(ld_dir), 16);

    flag = __az_create_dtp_session(client, AZ_STOULOAD_DTP, ld_dir);
    if (flag != AZ_OK)
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
}

static void _az_ftp_cmd_appe(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int loop = 0;
    int deep = 0;
    //char *argv = NULL;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char ld_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    struct stat statbuf;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    deep = client->dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, false, false);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }
    az_strncpy(ld_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(ld_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(ld_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(ld_dir, _A_NORMAL);
#else
    flag = access(ld_dir, F_OK);
#endif
    if (flag == 0)
    {
        if (stat(ld_dir, &statbuf) != 0 || (S_IFDIR & statbuf.st_mode))
        {
            az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
            return;
        }
    }

    flag = __az_create_dtp_session(client, AZ_APPELOAD_DTP, ld_dir);
    if (flag != AZ_OK)
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
}

static void _az_ftp_cmd_rest(az_ftp_client client, az_ftp_msg cmd)
{
    //off_t offset = 0;
    const char *argv = NULL;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) != 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }
    argv = az_ftp_msg_get_argv(cmd, 1);
    if (argv == NULL)
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    client->offset = atol(argv);
    if (client->offset == 0)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }
    client->restart = true;
    az_ftp_response(client, AZ_FTP_NEED_FURTHER, NULL);
}

static void _az_ftp_cmd_rnfr(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int loop = 0;
    int deep = 0;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char rn_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    //struct stat statbuf;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    deep = client->dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, true, false);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    az_strncpy(rn_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(rn_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(rn_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(rn_dir, _A_NORMAL);
#else
    flag = access(rn_dir, F_OK);
#endif
    if (flag != 0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    client->rename = true;
    az_strncpy(client->rename_dir, AZ_FTP_PATH_MAX_LEN, rn_dir, az_strlen(rn_dir));
    az_ftp_response(client, AZ_FTP_NEED_FURTHER, NULL);
}

static void _az_ftp_cmd_rnto(az_ftp_client client, az_ftp_msg cmd)
{
    int ret = 0;
    int flag = 0;
    int loop = 0;
    int deep = 0;
    char *rn_end = NULL;
    char *tmp_end = NULL;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char rn_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    //struct stat statbuf;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (!client->rename)
    {
        az_ftp_response(client, AZ_FTP_CMD_BAD_SEQ, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    deep = client->dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, false, false);
    if (flag != AZ_OK)
    {
        ret = AZ_FTP_FILE_ERR;
        goto END;
    }

    az_strncpy(rn_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(rn_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(rn_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
    for (loop = az_strlen(client->rename_dir) - 1; loop >= 0; loop--)
        if (client->rename_dir[loop] == '/')
            break;
    if (loop >= 0)
        rn_end = &client->rename_dir[loop];
    for (loop = az_strlen(rn_dir) - 1; loop >= 0; loop--)
        if (rn_dir[loop] == '/')
            break;
    if (loop >= 0)
        tmp_end = &rn_dir[loop];
    if (rn_end != NULL && tmp_end != NULL)
    {
        if (rn_end - client->rename_dir != tmp_end - rn_dir || az_strncmp(client->rename_dir, rn_dir, rn_end - client->rename_dir) != 0)
        {
            ret = AZ_FTP_CMD_PARAM_ERR;
            goto END;
        }
    }

    if (rename(client->rename_dir, rn_dir) != 0)
    {
        ret = AZ_FTP_FILE_ERR;
    }
    else
        ret = AZ_FTP_REQ_FILE_OK;

END:
    client->rename = false;
    *client->rename_dir = '\0';
    az_ftp_response(client, ret, NULL);
}

static void _az_ftp_cmd_abor(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    az_ftp_session sess = NULL;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    if (az_list_size(client->session_list) == 0)
    {
        az_ftp_response(client, AZ_FTP_TRANSFER_OK, "abort ok");
        return;
    }

    flag = az_list_ergodic_start(client->session_list, AZ_LIST_HEAD);
    if (flag == AZ_OK)
    {
        for (sess = az_list_ergodic_getnd(client->session_list, NULL); sess != NULL; sess = az_list_ergodic_getnd(client->session_list, NULL))
            az_atomic_set(&sess->abort, AZ_TRUE);
        az_list_ergodic_end(client->session_list);
    }
    else
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, "ergodic session list err");
        return;
    }

    while (az_atomic_read(&client->stat) == AZ_FTP_CLIENT_RUN && az_list_size(client->session_list) > 0)
        az_msleep(100);

    if (az_list_size(client->session_list) > 0)
        az_ftp_response(client, AZ_FTP_SER_CLOSE, NULL);
    else
        az_ftp_response(client, AZ_FTP_TRANSFER_OK, "abort ok");
}

static void _az_ftp_cmd_dele(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int loop = 0;
    int deep = 0;
    //char *argv = NULL;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char rm_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    struct stat statbuf;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    deep = client->dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, true, false);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }
    az_strncpy(rm_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(rm_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(rm_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(rm_dir, _A_NORMAL);
#else
    flag = access(rm_dir, F_OK);
#endif
    if (flag != 0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }
    if (stat(rm_dir, &statbuf) != 0 || (S_IFDIR & statbuf.st_mode))
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    if (unlink(rm_dir) < 0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, "Delete operation failed.");
        return;
    }

    az_ftp_response(client, AZ_FTP_REQ_FILE_OK, "Delete operation successful.");
}

static void _az_ftp_cmd_rmd(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int deep = 0;
    int loop = 0;
    //char *argv = NULL;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char rm_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    struct stat statbuf;

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    deep = client->dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, true, true);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }
    if(az_strncmp(client->work_dir,tmp_dir,az_strlen(tmp_dir))==0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    az_strncpy(rm_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(rm_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(rm_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(rm_dir, _A_NORMAL);
#else
    flag = access(rm_dir, F_OK);
#endif
    if (flag != 0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    if (stat(rm_dir, &statbuf) != 0 || !(S_IFDIR & statbuf.st_mode))
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    if (__az_loop_rmdir(rm_dir) != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    az_ftp_response(client, AZ_FTP_REQ_FILE_OK, "Remove directory operation successful.");
}

static az_ret __az_loop_rmdir(const char *path)
{
    az_list file_stack = NULL;
    az_list dir_stack = NULL;
    bool is_dir = false;
    char rm_path[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    int deep = 0;

    if (path == NULL || *path == '\0')
        return AZ_ERROR;

    file_stack = az_list_init(AZ_STACK_LIST, 0, sizeof(az_dir_info_t), 50, false);
    if (file_stack == NULL)
        return AZ_ERROR;
    dir_stack = az_list_init(AZ_STACK_LIST, 0, sizeof(char)*AZ_FTP_PATH_MAX_LEN, 50, false);
    if (dir_stack == NULL)
        return AZ_ERROR;

    if (az_ergodic_lodir(file_stack, path, &deep, NULL, NULL, NULL) < 0)
        goto ERR;
    //遍历删除文件夹内的所有文件并记录所访问到的所有文件夹
    while (az_list_size(file_stack) > 0)
    {
        if (az_ergodic_lodir(file_stack, NULL, &deep, rm_path, &is_dir, NULL) < 0)
            goto ERR;

        if (is_dir)
        {
            if (az_ergodic_lodir(file_stack, rm_path, &deep, NULL, NULL, NULL) < 0)
                goto ERR;
            az_list_insert(dir_stack, AZ_LIST_HEAD, 0, rm_path, sizeof(char)*AZ_FTP_PATH_MAX_LEN);
        }
        else
        {
            if (remove(rm_path) < 0)
                goto ERR;
        }
    }
    //删除访问到的所有文件夹
    while (az_list_size(dir_stack) > 0)
    {
        if (az_list_pop(dir_stack, AZ_LIST_HEAD, dir, NULL) != AZ_OK)
            goto ERR;
        if (rmdir(dir) < 0)
            goto ERR;
    }
    //删除最外层文件夹
    if (rmdir(path) < 0)
        goto ERR;
    az_list_destory(&file_stack);
    az_list_destory(&dir_stack);
    return AZ_OK;
ERR:
    if (file_stack != NULL)
        az_list_destory(&file_stack);
    if (dir_stack != NULL)
        az_list_destory(&dir_stack);
    return AZ_ERROR;
}

static void _az_ftp_cmd_mkd(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    int deep = 0;
    int loop = 0;
    char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char mk_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char text[1024] = { 0 };

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }
    if (az_ftp_msg_get_argc(cmd) < 1)
    {
        az_ftp_response(client, AZ_FTP_CMD_PARAM_ERR, NULL);
        return;
    }

    for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
    {
        az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
        if (loop != az_ftp_msg_get_argc(cmd))
            az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
    }
    if (*ch_dir == '\0')
    {
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
        return;
    }

    deep = client->dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, false, false);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    az_strncpy(mk_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(mk_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(mk_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);

    flag = az_mkloop_dir(mk_dir);
    if (flag != AZ_OK)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    snprintf(text, 1024, "\"/%s\" create OK", tmp_dir);

    az_ftp_response(client, AZ_FTP_CREATE_OK, text);
}

static void _az_ftp_cmd_pwd(az_ftp_client client, az_ftp_msg cmd)
{
    char text[1024] = { 0 };

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    snprintf(text, 1024, "\"/%s\"", client->work_dir);

    az_ftp_response(client, AZ_FTP_CREATE_OK, text);
}

static void _az_ftp_cmd_list(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char ld_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    if (az_ftp_msg_get_argc(cmd) > 0)
    {
        int deep = 0;
        int loop = 0;
        char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };

        for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
        {
            az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
            if (loop != az_ftp_msg_get_argc(cmd))
                az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
        }
        if (*ch_dir == '\0')
        {
            az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
            return;
        }

        deep = client->dir_deep;
        flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, true, false);
        if (flag != AZ_OK)
        {
            az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
            return;
        }
    }

    az_strncpy(ld_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(ld_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(ld_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(ld_dir, _A_NORMAL);
#else
    flag = access(ld_dir, F_OK);
#endif
    if (flag != 0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    flag = __az_create_dtp_session(client, AZ_LIST_DTP, ld_dir);
    if (flag != AZ_OK)
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
}

static void _az_ftp_cmd_nlst(az_ftp_client client, az_ftp_msg cmd)
{
    int flag = 0;
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    char ld_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };

    if (client == NULL || cmd == NULL)
        return;

    if (client->log_stat != AZ_FTP_OKLOGIN)
    {
        az_ftp_response(client, AZ_FTP_NO_LOGIN, NULL);
        return;
    }

    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, client->work_dir, az_strlen(client->work_dir));
    if (az_ftp_msg_get_argc(cmd) > 0)
    {
        int deep = 0;
        int loop = 0;
        char ch_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };

        for (loop = 1; loop <= az_ftp_msg_get_argc(cmd); loop++)
        {
            az_strcatstr(ch_dir, AZ_FTP_PATH_MAX_LEN, az_ftp_msg_get_argv(cmd, loop));
            if (loop != az_ftp_msg_get_argc(cmd))
                az_strcatchr(ch_dir, AZ_FTP_PATH_MAX_LEN, ' ');
        }
        if (*ch_dir == '\0')
        {
            az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
            return;
        }

        deep = client->dir_deep;
        flag = __az_ftp_change_workdir(ch_dir, &deep, tmp_dir, true, false);
        if (flag != AZ_OK)
        {
            az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
            return;
        }
    }

    az_strncpy(ld_dir, AZ_FTP_PATH_MAX_LEN, client->home_dir, az_strlen(client->home_dir));
    az_strcatchr(ld_dir, AZ_FTP_PATH_MAX_LEN, '/');
    az_strcatstr(ld_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir);
#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(ld_dir, _A_NORMAL);
#else
    flag = access(ld_dir, F_OK);
#endif
    if (flag != 0)
    {
        az_ftp_response(client, AZ_FTP_FILE_ERR, NULL);
        return;
    }

    flag = __az_create_dtp_session(client, AZ_NLIST_DTP, ld_dir);
    if (flag != AZ_OK)
        az_ftp_response(client, AZ_FTP_LOCAL_ERR, NULL);
}

static void _az_ftp_cmd_syst(az_ftp_client client, az_ftp_msg cmd)
{
    if (client == NULL || cmd == NULL)
        return;

    az_ftp_response(client, AZ_FTP_SYS_TYPE, "UNIX Type: L8");
}

static void _az_ftp_cmd_noop(az_ftp_client client, az_ftp_msg cmd)
{
    if (client == NULL || cmd == NULL)
        return;

    az_ftp_response(client, AZ_FTP_CMD_OK, NULL);
}

static int __az_ftp_change_workdir(const char *change, int *dir_deep, char *work_dir, bool is_exit, bool is_dir)
{
    int deep = 0;
    char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };

    deep = *dir_deep;
    az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, work_dir, az_strlen(work_dir));

    //if (*change == '/')
    //    return AZ_ERROR;
    if (*change == '/')
    {
        deep = 0;
        *tmp_dir = '\0';
        change++;
    }

    for (; *change != '\0';)
    {
        const char *tmp = az_strschr(change, '/', false);
        if (tmp == NULL)
            tmp = change + az_strlen(change);
        if (az_strncmp("~", change, tmp - change) == 0)
        {
            deep = 0;
            *tmp_dir = '\0';
        }
        else if (az_strncmp(".", change, tmp - change) == 0)
        {
        }
        else if (az_strncmp("..", change, tmp - change) == 0)
        {
            int loop = 0;

            deep--;
            if (deep < 0)
                return AZ_ERROR;

            for (loop = az_strlen(tmp_dir) - 1; loop >= 0; loop--)
            {
                if (tmp_dir[loop] == '/')
                    break;
            }
            tmp_dir[loop] = '\0';
        }
        else
        {
            int offset = az_strlen(tmp_dir);
            struct stat statbuf;

            deep++;
            if (offset != 0)
            {
                az_strcatchr(tmp_dir, AZ_FTP_PATH_MAX_LEN, '/');
                offset++;
            }
            az_strncpy(tmp_dir + offset, (size_t)AZ_FTP_PATH_MAX_LEN - offset, change, tmp - change);

            if (*tmp == '\0')
            {
                if (is_exit && stat(tmp_dir, &statbuf) != 0)
                    return AZ_ERROR;
                if (is_exit && is_dir && !(S_IFDIR & statbuf.st_mode))
                    return AZ_ERROR;
            }
            else if (stat(tmp_dir, &statbuf) != 0 || !(S_IFDIR & statbuf.st_mode))
                return AZ_ERROR;
        }
        if (*tmp != '\0')
            change = tmp + 1;
        else
            change = tmp;
    }

    *dir_deep = deep;
    if (deep == 0)
        *work_dir = '\0';
    else
        az_strncpy(work_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir, az_strlen(tmp_dir));

    return AZ_OK;
}

static char* __az_rand_str(char *str, int len)
{
    char *buf = str;

    if (str == NULL || len <= 0)
        return NULL;

    while (len--)
    {
        *str = ___az_rand_char_letter();
        str++;
    }
    *str = '\0';

    return buf;
}

static char ___az_rand_char_letter(void)
{
    char ret = 65;
    srand((unsigned int)az_system_rtime(NULL) + rand());
    ret = (char)(ret + rand() % 58);
    if (ret >= 91 && ret <= 96)
        ret += 6;

    return ret;
}

static int __az_create_dtp_session(az_ftp_client client, az_dtp_type type, char *file_name)
{
    int flag = 0;
    az_ftp_session dtp_session = NULL;
    az_task_hd hd = NULL;

    if (client == NULL || file_name == NULL || *file_name == '\0')
        return AZ_ERROR;

    if (client->simplify)
    {
        dtp_session = (az_ftp_session)az_mpcalloc(client->mp, sizeof(az_ftp_session_t));
        if (dtp_session == NULL)
            goto ERR;
    }
    else
    {
        dtp_session = (az_ftp_session)az_list_allocnd(client->session_list, sizeof(az_ftp_session_t));
        if (dtp_session == NULL)
            goto ERR;
    }

    if (client->dtp_mode == DTP_PASSIVE_MODE)
    {
        if (client->pasv_fd == NULL)
        {
            az_net pasv_fd = NULL;

            pasv_fd = az_create_socket(client->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
            if (pasv_fd == NULL)
                goto ERR;
            flag = az_bind_socket(pasv_fd, client->dtp_ip, client->dtp_port);
            if (flag != AZ_OK)
            {
                az_close_socket(&pasv_fd);
                goto ERR;
            }
            flag = az_listen_socket(pasv_fd, 1);
            if (flag != AZ_OK)
            {
                az_close_socket(&pasv_fd);
                goto ERR;
            }
            client->pasv_fd = pasv_fd;
        }
    }

    dtp_session->s_id = az_atomic_fetch_inc(&client->s_id);
    az_strncpy(dtp_session->file_name, AZ_FTP_PATH_MAX_LEN, file_name, az_strlen(file_name));
    dtp_session->cli_ctx = client;
    dtp_session->dtp_mode = client->dtp_mode;
    dtp_session->data_fd = client->pasv_fd;
    dtp_session->trans_mode = client->trans_mode;
    az_strncpy(dtp_session->dtp_ip, AZ_IPV6_ADDRESS_STRING_LEN, client->dtp_ip, az_strlen(client->dtp_ip));
    dtp_session->dtp_port = client->dtp_port;
    az_atomic_set(&dtp_session->abort, AZ_FALSE);
    az_atomic_set(&dtp_session->run, AZ_TRUE);

    switch (type)
    {
    case AZ_UPLOAD_DTP:
        if (client->restart)
        {
            dtp_session->offset = client->offset;
            client->offset = 0;
            client->restart = false;
        }
        else
            dtp_session->offset = 0;
        dtp_session->appe = false;
        dtp_session->stou = false;
        hd = (az_task_hd)az_ftp_upload_task;
        break;
    case AZ_DOWNLOAD_DTP:
        if (client->restart)
        {
            dtp_session->offset = client->offset;
            client->offset = 0;
            client->restart = false;
        }
        else
            dtp_session->offset = 0;
        dtp_session->appe = false;
        dtp_session->stou = false;
        hd = (az_task_hd)az_ftp_download_task;
        break;
    case AZ_APPELOAD_DTP:
        dtp_session->offset = 0;
        dtp_session->appe = true;
        dtp_session->stou = false;
        hd = (az_task_hd)az_ftp_upload_task;
        break;
    case AZ_STOULOAD_DTP:
        dtp_session->offset = 0;
        dtp_session->appe = false;
        dtp_session->stou = true;
        hd = (az_task_hd)az_ftp_upload_task;
        break;
    case AZ_LIST_DTP:
        dtp_session->offset = 0;
        dtp_session->appe = false;
        dtp_session->stou = false;
        hd = (az_task_hd)az_ftp_list_task;
        break;
    case AZ_NLIST_DTP:
        dtp_session->offset = 0;
        dtp_session->appe = false;
        dtp_session->stou = false;
        hd = (az_task_hd)az_ftp_nlist_task;
        break;
    }

    if (hd == NULL)
        goto ERR;

    if (client->simplify)
    {
        hd(dtp_session);
        az_mpfree(client->mp, (void **)&dtp_session);
    }
    else
    {
        az_task_id t_id = 0;
        az_task_info_t task = { 0 };

        az_list_insertnd(client->session_list, AZ_LIST_TAIL, dtp_session->s_id, dtp_session);
        task.level = TASK_LEVEL_0;
        task.func = hd;
        task.finish_cb = (az_task_hd)az_ftp_dtp_finish;
        task.param = dtp_session;
        task.data_len = 0;

        t_id = az_tpadd(client->tp, &task);
        if (t_id == AZ_ERROR)
            goto ERR;
    }

    client->pasv_fd = NULL;
    return AZ_OK;
ERR:
    if (dtp_session != NULL)
    {
        if (client->simplify)
            az_mpfree(client->mp, (void **)&dtp_session);
        else
            az_list_delnd(client->session_list, (void **)&dtp_session);
    }
    return AZ_ERROR;
}
