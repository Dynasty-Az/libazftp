#include"az_ftp_client_dtp.h"

typedef struct az_mini_client_s
{
    az_memp mp;
    bool log_flag;

    az_ftp_login_status login_state;
    az_net ctl_fd;
    char ser_ip[AZ_IPV4_ADDRESS_STRING_LEN];
    int ser_port;
    char *user;
    char *pwd;
    char recv_buf[2 * 1024 * 1024];
    int data_len;

    az_ftp_dtp_mode dtp_mode;
    az_ftp_trans_mode trans_mode;
    az_net dtp_fd;
    char dtp_ip[AZ_IPV4_ADDRESS_STRING_LEN];
    int dtp_port;

    char dir_current[AZ_FTP_PATH_MAX_LEN];

    az_file_session trans_info;
}az_mini_cli_t, *az_mini_cli;

static az_ret __az_dtp_send_cmd(az_mini_cli ctx, az_ftp_cmd type, const char *argv);
static az_ftp_msg __az_dtp_waite_reply(az_mini_cli ctx, bool temporary);
static az_ret __az_dtp_connect(az_mini_cli ctx);
static void __az_dtp_hangup(az_mini_cli ctx);
static az_net __az_dtp_actvtrans(az_mini_cli ctx);
static az_ret __az_dtp_pasvtrans(az_mini_cli ctx, char *dtp_ip, int *dtp_port);

static az_net az_cli_active(az_memp pool, az_ftp_clictrl ctrl);
static az_ret az_cli_passive(az_ftp_clictrl ctrl, char *ser_ip, int *ser_port);

static void __az_file_rlock(int fd);
static void __az_file_wlock(int fd);
static void __az_file_unlock(int fd);
static int __az_file_write(int fd, uint8_t *data, int len);

static az_mini_cli _az_dtp_create_mini_client(az_client_info_t info, az_file_session trans_info, bool log_flag);
static void _az_dtp_free_mini_client(az_mini_cli *mini);
static void __az_dtp_trans_task(az_mini_cli mini);
static void __az_dtp_trans_end(az_mini_cli mini);

az_ret az_dtp_list(az_memp pool, az_ftp_clictrl ctrl, az_ftp_dtp_mode dtp_mode, const char *path, char **data, bool ex)
{
    int flag = 0;
    bool rpl_flag = false;
    char ser_ip[AZ_IPV4_ADDRESS_STRING_LEN] = { 0 };
    int ser_port = 0;
    az_net listen_fd = NULL;
    az_net data_fd = NULL;
    az_clictrl_ev ev = NULL;
    char *tmp_data = NULL;
    int tmp_data_len = 0;
    int recv_data_len = 0;

    if (pool == NULL || ctrl == NULL || data == NULL)
        return AZ_ERROR;
    //设置数据格式
    if (az_clictrl_exec(ctrl, FTP_CMD_TYPE, "A N") != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(ctrl, FTP_CMD_TYPE, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_CMD_OK)
    {
        az_clictrl_evfree(ctrl, &ev);
        return AZ_ERROR;
    }
    az_clictrl_evfree(ctrl, &ev);
    //分配数据接收空间
    tmp_data = (char *)az_mpcalloc(pool, 512);
    if (tmp_data == NULL)
        return AZ_ERROR;
    tmp_data_len += 512;
    //设置传输模式
    if (dtp_mode == DTP_ACTIVE_MODE)
    {
        listen_fd = az_cli_active(pool, ctrl);
        if (listen_fd == NULL)
            return AZ_ERROR;
    }
    else
    {
        if (az_cli_passive(ctrl, ser_ip, &ser_port) != AZ_OK)
            return AZ_ERROR;
    }
    //发送请求列表命令
    if (ex)
    {
        if (az_clictrl_exec(ctrl, FTP_CMD_LIST, path) != AZ_OK)
            goto ERR;
    }
    else
    {
        if (az_clictrl_exec(ctrl, FTP_CMD_NLST, path) != AZ_OK)
            goto ERR;
    }
    //接收临时响应
RERECV:
    if (ex)
        ev = az_clictrl_waite(ctrl, FTP_CMD_LIST, true);
    else
        ev = az_clictrl_waite(ctrl, FTP_CMD_NLST, true);
    rpl_flag = false;
    if (ev == NULL)
        goto ERR;
    if (ev->code < 200 && ev->code != AZ_FTP_FILE_OK)
        goto RERECV;
    else if (ev->code >= 200 && ev->code < 300)
        goto END;
    else if (ev->code >= 300)
        goto ERR;

    rpl_flag = true;
    //建立数据连接
    if (dtp_mode == DTP_ACTIVE_MODE)
    {
        data_fd = az_accept_socket(pool, listen_fd);
        if (data_fd == NULL)
            goto ERR;
        az_close_socket(&listen_fd);
    }
    else
    {
        data_fd = az_create_socket(pool, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
        if (data_fd == NULL)
            goto ERR;
        if (az_connect_socket(data_fd, ser_ip, ser_port) != AZ_OK)
            goto ERR;
    }
    //接收数据
    while (az_clictrl_state(ctrl) == AZ_FTP_CLIENT_RUN)
    {
        flag = az_recv(data_fd, tmp_data + recv_data_len, tmp_data_len - recv_data_len, 0);
        if (flag == AZ_ERROR)
        {
            //az_writelog(AZ_LOG_ERROR, "az ftp client: recv list data err");
            goto ERR;
        }
        else if (flag == AZ_AGAIN)
            continue;
        else if (flag == 0)
        {
            //az_writelog(AZ_LOG_INFO, "az ftp client: recv list data end");
            break;
        }
        else
        {
            recv_data_len += flag;
            if (recv_data_len >= tmp_data_len)
            {
                char *tmp = NULL;
                tmp_data_len += 512;
                tmp = (char *)az_mprealloc(pool, (void **)&tmp_data, tmp_data_len);
                if (tmp == NULL)
                    goto ERR;
                tmp_data = tmp;
            }
        }
    }
    //接收命令响应
    if (ex)
        ev = az_clictrl_waite(ctrl, FTP_CMD_LIST, false);
    else
        ev = az_clictrl_waite(ctrl, FTP_CMD_NLST, false);
    rpl_flag = false;
    if (ev == NULL)
        goto ERR;
END:
    if (ev->code != AZ_FTP_TRANSFER_OK)
        goto ERR;

    *data = tmp_data;
    if (listen_fd != NULL)
        az_close_socket(&listen_fd);
    az_close_socket(&data_fd);
    az_clictrl_evfree(ctrl, &ev);

    return AZ_OK;
ERR:
    if (listen_fd != NULL)
        az_close_socket(&listen_fd);
    if (data_fd != NULL)
        az_close_socket(&data_fd);
    if (tmp_data != NULL)
        az_mpfree(pool, (void **)&tmp_data);
    if (rpl_flag)
    {
        if (ex)
            ev = az_clictrl_waite(ctrl, FTP_CMD_LIST, false);
        else
            ev = az_clictrl_waite(ctrl, FTP_CMD_NLST, false);
    }
    az_clictrl_evfree(ctrl, &ev);
    return AZ_ERROR;
}

az_ret az_dtp_trans(az_taskp tp, az_client_info_t info, az_file_session trans_info, bool log_flag)
{
    az_mini_cli mini = NULL;
    az_task_info_t task = { 0 };

    if (tp == NULL || trans_info == NULL)
        return AZ_ERROR;

    mini = _az_dtp_create_mini_client(info, trans_info, log_flag);
    if (mini == NULL)
        goto ERR;

    task.level = TASK_LEVEL_0;
    task.func = (az_task_hd)__az_dtp_trans_task;
    task.finish_cb = (az_task_hd)__az_dtp_trans_end;
    task.param = mini;
    task.data_len = 0;

    if (az_tpadd(tp, &task) == AZ_ERROR)
        goto ERR;

    return AZ_OK;
ERR:
    az_atomic_set(&trans_info->trans_state, AZ_TRANS_ERR);
    if (mini != NULL)
        _az_dtp_free_mini_client(&mini);
    return AZ_ERROR;
}

static void __az_dtp_trans_task(az_mini_cli mini)
{
    int flag = 0;
    az_ftp_msg reply = NULL;
    az_net listen_fd = NULL;
    az_net dtp_fd = NULL;
    char ser_ip[AZ_IPV4_ADDRESS_STRING_LEN] = { 0 };
    int ser_port = 0;
    int recv_len = 0;
    off_t send_len = 0;
    uint8_t recv_data[2 * 1024 * 1024] = { 0 };
    int file_fd = -1;
    bool locked = false;
    bool rpl_flag = false;
    int64_t last_file_size = 0;
    time_t last_time = 0;

    az_atomic_set(&mini->trans_info->trans_state, AZ_TRANS_RUNNING);
    //打开文件
    if (mini->trans_info->trans_type == AZ_FTP_UPLOAD)
        file_fd = open(mini->trans_info->local_path, O_RDONLY, 0644);
    else
        file_fd = open(mini->trans_info->local_path, O_CREAT | O_RDWR, 0644);
    if (file_fd < 0)
        goto ERR;
    //设置文件锁
    if (mini->trans_info->trans_type == AZ_FTP_UPLOAD)
        __az_file_rlock(file_fd);
    else
        __az_file_wlock(file_fd);
    locked = true;
    //判断文件是否续传
    if (mini->trans_info->offset > 0)
    {
        if (lseek(file_fd, mini->trans_info->offset, SEEK_SET) < 0)
            goto ERR;
        az_atomic64_add(&mini->trans_info->up_down_len, mini->trans_info->offset);
    }
    else
    {
        ftruncate(file_fd, 0);
        if (lseek(file_fd, 0, SEEK_SET) < 0)
            goto ERR;
    }
    if (mini->trans_info->trans_type == AZ_FTP_UPLOAD)
    {
        struct stat statbuf;

        if (fstat(file_fd, &statbuf) != 0 || !S_ISREG(statbuf.st_mode))
            goto ERR;
        send_len = statbuf.st_size;
        if (mini->trans_info->offset > 0)
            send_len -= mini->trans_info->offset;
    }
    //连接服务器
    if (__az_dtp_connect(mini) != AZ_OK)
        goto ERR;
    //设置传输模式
    if (mini->dtp_mode == DTP_ACTIVE_MODE)
    {
        listen_fd = __az_dtp_actvtrans(mini);
        if (listen_fd == NULL)
            goto ERR;
    }
    else
    {
        dtp_fd = az_create_socket(mini->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
        if (dtp_fd == NULL)
            goto ERR;
        if (__az_dtp_pasvtrans(mini, ser_ip, &ser_port) != AZ_OK)
            goto ERR;
    }
    //发送重开始请求
    if (mini->trans_info->offset > 0)
    {
        char text[128] = { 0 };

        snprintf(text, 128, "%ld", mini->trans_info->offset);
        if (__az_dtp_send_cmd(mini, FTP_CMD_REST, text) != AZ_OK)
            goto ERR;
        reply = __az_dtp_waite_reply(mini, false);
        if (reply == NULL)
            goto ERR;
        if (az_ftp_msg_get_code(reply) != AZ_FTP_NEED_FURTHER)
            goto ERR;
        az_ftp_msg_free(&reply);
    }
    //发起传输请求
    if (mini->trans_info->trans_type == AZ_FTP_UPLOAD)
    {
        if (__az_dtp_send_cmd(mini, FTP_CMD_STOR, mini->trans_info->remote_path) != AZ_OK)
            goto ERR;
    }
    else
    {
        if (__az_dtp_send_cmd(mini, FTP_CMD_RETR, mini->trans_info->remote_path) != AZ_OK)
            goto ERR;
    }
    //接收临时响应
RERECV:
    reply = __az_dtp_waite_reply(mini, true);
    rpl_flag = false;
    if (reply == NULL)
        goto ERR;
    if (az_ftp_msg_get_code(reply) < 200 && az_ftp_msg_get_code(reply) != AZ_FTP_FILE_OK)
        goto RERECV;
    else if (az_ftp_msg_get_code(reply) >= 200 && az_ftp_msg_get_code(reply) < 300)
        goto END;
    else if (az_ftp_msg_get_code(reply) >= 300)
        goto ERR;
    az_ftp_msg_free(&reply);
    rpl_flag = true;
    //建立数据连接
    if (mini->dtp_mode == DTP_ACTIVE_MODE)
    {
        dtp_fd = az_accept_socket(mini->mp, listen_fd);
        if (dtp_fd == NULL)
            goto ERR;
        az_close_socket(&listen_fd);
    }
    else
    {
        if (az_connect_socket(dtp_fd, ser_ip, ser_port) != AZ_OK)
            goto ERR;
    }
    //传输数据
    while (az_atomic_read(&mini->trans_info->trans_state) == AZ_TRANS_RUNNING)
    {
        if (mini->trans_info->trans_type == AZ_FTP_UPLOAD)
        {
            off_t ret_len = 0;

            int len = send_len > 4096 ? 4096 : send_len;
            ret_len = sendfile(az_socket_get_fd(dtp_fd), file_fd, NULL, len);
            if (ret_len < 0)
                break;
            send_len -= ret_len;
            az_atomic64_add(&mini->trans_info->up_down_len, ret_len);
            if (send_len <= 0)
                break;
        }
        else
        {
            recv_len = az_recv(dtp_fd, recv_data, 2 * 1024 * 1024, 0);
            if (recv_len == AZ_ERROR)
            {
                if (mini->log_flag)
                    az_writelog(AZ_LOG_ERROR, "mini client: data link recv err");
                break;
            }
            else if (recv_len == 0)
            {
                if (mini->log_flag)
                    az_writelog(AZ_LOG_INFO, "mini client: data link closed");
                break;
            }
            else if (recv_len > 0)
            {
                flag = __az_file_write(file_fd, recv_data, recv_len);
                if (flag == AZ_ERROR)
                {
                    if (mini->log_flag)
                        az_writelog(AZ_LOG_ERROR, "mini client: write file err");
                    break;
                }
                else if (flag != recv_len)
                {
                    if (mini->log_flag)
                        az_writelog(AZ_LOG_ERROR, "mini client: not have space");
                    break;
                }
                az_atomic64_add(&mini->trans_info->up_down_len, flag);
            }
        }

        if (az_system_rtime(NULL) - last_time >= 1)
        {
            last_time = az_system_rtime(NULL);
            az_atomic64_set(&mini->trans_info->speed, az_atomic64_read(&mini->trans_info->up_down_len) - last_file_size);
            last_file_size = az_atomic64_read(&mini->trans_info->up_down_len);
        }
    }
    az_close_socket(&dtp_fd);
    __az_file_unlock(file_fd);
    locked = false;
    close(file_fd);
    file_fd = -1;

    rpl_flag = false;
    reply = __az_dtp_waite_reply(mini, false);
    if (reply == NULL)
        goto ERR;
END:
    if (az_ftp_msg_get_code(reply) != AZ_FTP_TRANSFER_OK)
        goto ERR;
    az_ftp_msg_free(&reply);
    if (last_time == 0)
        az_atomic64_set(&mini->trans_info->speed, az_atomic64_read(&mini->trans_info->up_down_len));
    az_atomic_set(&mini->trans_info->trans_state, AZ_TRANS_END);

    return;
ERR:
    az_atomic_set(&mini->trans_info->trans_state, AZ_TRANS_ERR);
    if (reply != NULL)
        az_ftp_msg_free(&reply);
    if (listen_fd != NULL)
        az_close_socket(&listen_fd);
    if (dtp_fd != NULL)
        az_close_socket(&dtp_fd);
    if (locked)
        __az_file_unlock(file_fd);
    if (file_fd >= 0)
        close(file_fd);
    if (rpl_flag)
    {
        reply = __az_dtp_waite_reply(mini, false);
        if (reply != NULL)
            az_ftp_msg_free(&reply);
    }
    return;
}

static void __az_dtp_trans_end(az_mini_cli mini)
{
    __az_dtp_hangup(mini);

    _az_dtp_free_mini_client(&mini);
}

/*
void az_clidtp_download(az_mini_cli ctx)
{
    int flag = 0;
    int file_fd = -1;
    az_net ctl_fd = NULL;
    az_net dtp_fd = NULL;
    az_net dtp_listen_fd = NULL;
    char ser_ip[AZ_IPV4_ADDRESS_STRING_LEN] = { 0 };
    int ser_port = 0;
    bool locked = false;
    az_ftp_msg reply = NULL;
    int recv_len = 0;
    uint8_t recv_data[2 * 1024 * 1024] = { 0 };

    {
        int loop = 0;
        for (loop = az_strlen(ctx->remote_dir) - 1; loop >= 0; loop--)
        {
            if (ctx->remote_dir[loop] == '/')
                break;
        }
        loop++;
        az_strcatstr(ctx->local_dir, AZ_FTP_PATH_MAX_LEN, &ctx->remote_dir[loop]);
    }

    file_fd = open(ctx->local_dir, O_CREAT | O_WRONLY, 0644);
    if (file_fd < 0)
        goto ERR;
    _az_file_wlock(file_fd);
    locked = true;

    if (ctx->offset > 0)
    {
        if (lseek(file_fd, ctx->offset, SEEK_SET) < 0)
            goto ERR;
    }
    else
    {
        ftruncate(file_fd, 0);
        if (lseek(file_fd, 0, SEEK_SET) < 0)
            goto ERR;
    }

    ctl_fd = _az_dtp_connect(ctx);
    if (ctl_fd == NULL)
        goto ERR;
    //设置传输模式
    if (ctx->dtp_mode == DTP_ACTIVE_MODE)
    {
        dtp_listen_fd = _az_dtp_actvtrans(ctx, ctl_fd);
        if (dtp_listen_fd == NULL)
            goto ERR;
    }
    else
    {
        if (_az_dtp_pasvtrans(ctx, ctl_fd, ser_ip, &ser_port) != AZ_OK)
            goto ERR;
        dtp_fd = az_create_socket(ctx->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
        if (dtp_fd == NULL)
            goto ERR;
    }
    //发起传输请求
    if (ctx->offset > 0)
    {
        char text[128] = { 0 };

        snprintf(text, 128, "%ld", ctx->offset);
        if (_az_dtp_send_cmd(ctx->mp, ctl_fd, FTP_CMD_REST, text) != AZ_OK)
            goto ERR;
        reply = _az_dtp_waite_reply(ctx, ctl_fd, true);
        if (reply == NULL)
            goto ERR;
        if (az_ftp_msg_get_code(reply) != AZ_FTP_NEED_FURTHER)
            goto ERR;
        az_ftp_msg_free(&reply);
    }
    if (_az_dtp_send_cmd(ctx->mp, ctl_fd, FTP_CMD_RETR, ctx->remote_dir) != AZ_OK)
        goto ERR;

    if (ctx->dtp_mode == DTP_ACTIVE_MODE)
    {
        dtp_fd = az_accept_socket(ctx->mp, dtp_listen_fd);
        if (dtp_fd == NULL)
            goto ERR;
        az_close_socket(&dtp_listen_fd);
    }
    else
    {
        if (az_connect_socket(dtp_fd, ser_ip, ser_port) != AZ_OK)
            goto ERR;
    }

    do
    {
        reply = _az_dtp_waite_reply(ctx, ctl_fd, true);
        if (reply == NULL)
            goto ERR;
        if (az_ftp_msg_get_code(reply) == AZ_FTP_FILE_OK)
            break;
        else if (az_ftp_msg_get_code(reply) >= 300)
            goto ERR;
    } while (az_ftp_msg_get_code(reply) == AZ_FTP_DATACONN_OK);
    az_ftp_msg_free(&reply);

    while (1)
    {
        recv_len = az_recv(dtp_fd, recv_data, 2 * 1024 * 1024, 0);
        if (recv_len == AZ_ERROR)
        {
            az_writelog(AZ_LOG_ERROR, "mini client: data link recv err");
            break;
        }
        else if (recv_len == 0)
        {
            az_writelog(AZ_LOG_INFO, "mini client: data link closed");
            break;
        }
        else if (recv_len > 0)
        {
            flag = _az_file_write(file_fd, recv_data, recv_len);
            if (flag == AZ_ERROR)
            {
                az_writelog(AZ_LOG_ERROR, "mini client: write file err");
                break;
            }
            else if (flag != recv_len)
            {
                az_writelog(AZ_LOG_ERROR, "mini client: not have space");
                break;
            }

            ctx->up_down_len += flag;
        }
    }
    az_close_socket(&dtp_fd);
    reply = _az_dtp_waite_reply(ctx, ctl_fd, true);
    if (reply == NULL)
        goto ERR;
    if (az_ftp_msg_get_code(reply) != AZ_FTP_TRANSFER_OK)
        goto ERR;
    az_ftp_msg_free(&reply);

    _az_file_unlock(file_fd);
    close(file_fd);
    ctx->state = AZ_TRANS_END;
    //退出登录
    _az_dtp_hangup(ctx, ctl_fd);
    az_close_socket(&ctl_fd);
    return;
ERR:
    az_ftp_msg_free(&reply);
    if (dtp_fd != NULL)
        az_close_socket(&dtp_fd);
    if (locked)
        _az_file_unlock(file_fd);
    if (file_fd >= 0)
        close(file_fd);
    if (ctl_fd != NULL)
    {
        //退出登录
        _az_dtp_hangup(ctx, ctl_fd);
        az_close_socket(&ctl_fd);
    }
    ctx->state = AZ_TRANS_ERR;
}
*/

static az_net az_cli_active(az_memp pool, az_ftp_clictrl ctrl)
{
    az_clictrl_ev ev = NULL;
    az_netinfo_ipv4_t netinfo;
    int p1 = 0;
    int p2 = 0;
    char h1[4] = { 0 };
    char h2[4] = { 0 };
    char h3[4] = { 0 };
    char h4[4] = { 0 };
    char text[128] = { 0 };
    az_net act_fd = NULL;
    int def_act_port = 10000;

    if (ctrl == NULL)
        return NULL;

    az_clictrl_netinfo(ctrl, &netinfo);

    act_fd = az_create_socket(pool, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
    if (act_fd == NULL)
        return NULL;
    do
    {
        if (az_bind_socket(act_fd, netinfo.local_ip, def_act_port) == AZ_OK)
            break;
        def_act_port++;
        if (def_act_port >= 65535)
            def_act_port = 10000;
    } while (1);
    if (az_listen_socket(act_fd, 1) != AZ_OK)
    {
        az_close_socket(&act_fd);
        return NULL;
    }
    p1 = def_act_port / 256;
    p2 = def_act_port % 256;
    sscanf(netinfo.local_ip, "%[0-9].%[0-9].%[0-9].%[0-9]", h1, h2, h3, h4);
    snprintf(text, 128, "%s,%s,%s,%s,%d,%d", h1, h2, h3, h4, p1, p2);

    if (az_clictrl_exec(ctrl, FTP_CMD_PORT, text) != AZ_OK)
    {
        az_close_socket(&act_fd);
        return NULL;
    }
    ev = az_clictrl_waite(ctrl, FTP_CMD_PORT, false);
    if (ev == NULL)
    {
        az_close_socket(&act_fd);
        return NULL;
    }
    if (ev->code != AZ_FTP_CMD_OK)
    {
        az_close_socket(&act_fd);
        az_clictrl_evfree(ctrl, &ev);
        return NULL;
    }
    az_clictrl_evfree(ctrl, &ev);

    return act_fd;
}

static az_ret az_cli_passive(az_ftp_clictrl ctrl, char *ser_ip, int *ser_port)
{
    az_clictrl_ev ev = NULL;
    char p1[8] = { 0 };
    char p2[8] = { 0 };
    char h1[4] = { 0 };
    char h2[4] = { 0 };
    char h3[4] = { 0 };
    char h4[4] = { 0 };
    int port = 0;
    char ip[AZ_IPV4_ADDRESS_STRING_LEN] = { 0 };
    char *start = NULL;

    if (ctrl == NULL || ser_ip == NULL || ser_port == NULL)
        return AZ_ERROR;

    if (az_clictrl_exec(ctrl, FTP_CMD_PASV, NULL) != AZ_OK)
        return AZ_ERROR;
    ev = az_clictrl_waite(ctrl, FTP_CMD_PASV, false);
    if (ev == NULL)
        return AZ_ERROR;
    if (ev->code != AZ_FTP_PASV_OK)
    {
        az_clictrl_evfree(ctrl, &ev);
        return AZ_ERROR;
    }

    start = az_strschr(ev->msg, '(', false);
    if (start == NULL)
    {
        az_clictrl_evfree(ctrl, &ev);
        return AZ_ERROR;
    }
    start++;
    sscanf(start, "%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]", h1, h2, h3, h4, p1, p2);
    if (*h1 == '\0' || *h2 == '\0' || *h3 == '\0' || *h4 == '\0' || *p1 == '\0' || *p2 == '\0')
    {
        az_clictrl_evfree(ctrl, &ev);
        return AZ_ERROR;
    }
    snprintf(ip, AZ_IPV6_ADDRESS_STRING_LEN, "%s.%s.%s.%s", h1, h2, h3, h4);
    if (az_check_ipv4(ip) != AZ_OK)
    {
        az_clictrl_evfree(ctrl, &ev);
        return AZ_ERROR;
    }
    port = atoi(p1) * 256 + atoi(p2);
    if (port <= 0 || port >= 65535)
    {
        az_clictrl_evfree(ctrl, &ev);
        return AZ_ERROR;
    }

    az_strncpy(ser_ip, AZ_IPV4_ADDRESS_STRING_LEN, ip, az_strlen(ip));
    *ser_port = port;

    az_clictrl_evfree(ctrl, &ev);
    return AZ_OK;
}


static az_mini_cli _az_dtp_create_mini_client(az_client_info_t info, az_file_session trans_info, bool log_flag)
{
    az_mini_cli tmp = NULL;
    az_memp pool = NULL;

    if (trans_info == NULL || info.ser_ip == NULL || *info.ser_ip == '\0' || info.ser_port <= 0 || info.ser_port > 65535)
        return NULL;

    pool = az_memp_create(AZ_MEM_POOL_DEFAULT_SIZE, false);
    if (pool == NULL)
        return NULL;

    tmp = (az_mini_cli)az_mpcalloc(pool, sizeof(az_mini_cli_t));
    if (tmp == NULL)
        goto ERR;
    tmp->mp = pool;
    tmp->log_flag = log_flag;
    az_strncpy(tmp->ser_ip, AZ_IPV4_ADDRESS_STRING_LEN, info.ser_ip, az_strlen(info.ser_ip));
    tmp->ser_port = info.ser_port;
    if (info.user != NULL && *info.pwd != '\0')
    {
        tmp->user = (char *)az_mpcalloc(tmp->mp, az_strlen(info.user) + 1);
        if (tmp->user == NULL)
            goto ERR;
        az_strncpy(tmp->user, az_strlen(info.user) + 1, info.user, az_strlen(info.user));
        if (info.pwd != NULL&&*info.pwd != '\0')
        {
            tmp->pwd = (char *)az_mpcalloc(tmp->mp, az_strlen(info.pwd) + 1);
            if (tmp->pwd == NULL)
                goto ERR;
            az_strncpy(tmp->pwd, az_strlen(info.pwd) + 1, info.pwd, az_strlen(info.pwd));
        }
    }
    if (info.current_dir != NULL && *info.current_dir != '\0')
        az_strncpy(tmp->dir_current, AZ_FTP_PATH_MAX_LEN, info.current_dir, az_strlen(info.current_dir));
    tmp->dtp_mode = info.dtp_mode;
    tmp->trans_mode = info.trans_mode;
    tmp->trans_info = trans_info;
    az_atomic_set(&tmp->trans_info->trans_state, AZ_TRANS_WAITE);
    tmp->login_state = AZ_FTP_NOLOGIN;

    return tmp;
ERR:
    if (pool != NULL)
        az_memp_destory(pool);
    return NULL;
}

static void _az_dtp_free_mini_client(az_mini_cli *mini)
{
    if (*mini == NULL)
        return;

    az_memp_destory((*mini)->mp);

    *mini = NULL;
}


static az_ret __az_dtp_connect(az_mini_cli ctx)
{
    int flag = 0;
    az_ftp_msg reply = NULL;

    if (ctx == NULL)
        return AZ_ERROR;

    ctx->ctl_fd = az_create_socket(ctx->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
    if (ctx->ctl_fd == NULL)
        return AZ_ERROR;
    flag = az_connect_socket(ctx->ctl_fd, ctx->ser_ip, ctx->ser_port);
    if (flag != AZ_OK)
        goto ERR;
    //接收220欢迎信息
    reply = __az_dtp_waite_reply(ctx, false);
    if (reply == NULL)
        goto ERR;
    if (az_ftp_msg_get_code(reply) != 220)
        goto ERR;
    az_ftp_msg_free(&reply);
    //登陆
    if (__az_dtp_send_cmd(ctx, FTP_CMD_USER, ctx->user) != AZ_OK)
        goto ERR;
    reply = __az_dtp_waite_reply(ctx, false);
    if (reply == NULL)
        goto ERR;
    if (az_ftp_msg_get_code(reply) == AZ_FTP_NEED_PASS)
    {
        az_ftp_msg_free(&reply);
        if (__az_dtp_send_cmd(ctx, FTP_CMD_PASS, ctx->pwd) != AZ_OK)
            goto ERR;

        reply = __az_dtp_waite_reply(ctx, false);
        if (reply == NULL)
            goto ERR;
    }
    if (az_ftp_msg_get_code(reply) != AZ_FTP_LOGIN_OK)
        goto ERR;
    az_ftp_msg_free(&reply);
    ctx->login_state = AZ_FTP_OKLOGIN;
    //切换成与主客户端同一路径
    if (__az_dtp_send_cmd(ctx, FTP_CMD_CWD, ctx->dir_current) != AZ_OK)
        goto ERR;
    reply = __az_dtp_waite_reply(ctx, false);
    if (reply == NULL)
        goto ERR;
    if (az_ftp_msg_get_code(reply) != AZ_FTP_REQ_FILE_OK)
        goto ERR;
    az_ftp_msg_free(&reply);
    //设置文件表示类型为二进制类型
    if (__az_dtp_send_cmd(ctx, FTP_CMD_TYPE, "I") != AZ_OK)
        goto ERR;
    reply = __az_dtp_waite_reply(ctx, false);
    if (reply == NULL)
        goto ERR;
    if (az_ftp_msg_get_code(reply) != AZ_FTP_CMD_OK)
        goto ERR;
    az_ftp_msg_free(&reply);

    return AZ_OK;
ERR:
    if (reply != NULL)
        az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

static void __az_dtp_hangup(az_mini_cli ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->login_state == AZ_FTP_OKLOGIN)
    {
        az_ftp_msg reply = NULL;

        if (__az_dtp_send_cmd(ctx, FTP_CMD_QUIT, NULL) == AZ_OK)
        {
            reply = __az_dtp_waite_reply(ctx, false);
            if (reply != NULL)
            {
                if (az_ftp_msg_get_code(reply) == AZ_FTP_LOGOUT_OK)
                {
                }
                else
                {
                }
                az_ftp_msg_free(&reply);
            }
        }
    }

    az_close_socket(&ctx->ctl_fd);
}

//设置主动传输模式
static az_net __az_dtp_actvtrans(az_mini_cli ctx)
{
    int flag = 0;
    az_net listen_fd = NULL;
    az_netinfo_ipv4_t netinfo;
    int def_act_port = 10000;
    int p1 = 0;
    int p2 = 0;
    char h1[4] = { 0 };
    char h2[4] = { 0 };
    char h3[4] = { 0 };
    char h4[4] = { 0 };
    char text[128] = { 0 };
    az_ftp_msg reply = NULL;

    if (ctx == NULL || ctx->dtp_mode != DTP_ACTIVE_MODE)
        return NULL;

    az_socket_connect_info(ctx->ctl_fd, NULL, &netinfo);

    listen_fd = az_create_socket(ctx->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
    if (listen_fd == NULL)
        return NULL;
    do
    {
        flag = az_bind_socket(listen_fd, netinfo.local_ip, def_act_port);
        if (flag == AZ_OK)
            break;
        def_act_port++;
        if (def_act_port >= 65535)
            def_act_port = 10000;
    } while (1);
    flag = az_listen_socket(listen_fd, 1);
    if (flag != AZ_OK)
        goto ERR;

    p1 = def_act_port / 256;
    p2 = def_act_port % 256;
    sscanf(netinfo.local_ip, "%[0-9].%[0-9].%[0-9].%[0-9]", h1, h2, h3, h4);
    snprintf(text, 128, "%s,%s,%s,%s,%d,%d", h1, h2, h3, h4, p1, p2);

    if (__az_dtp_send_cmd(ctx, FTP_CMD_PORT, text) != AZ_OK)
        goto ERR;
    reply = __az_dtp_waite_reply(ctx, false);
    if (reply == NULL)
        goto ERR;

    if (az_ftp_msg_get_code(reply) != AZ_FTP_CMD_OK)
        goto ERR;

    az_ftp_msg_free(&reply);
    return listen_fd;
ERR:
    if(listen_fd!=NULL)
        az_close_socket(&listen_fd);
    if (reply != NULL)
        az_ftp_msg_free(&reply);
    return NULL;
}
//设置被动传输模式
static az_ret __az_dtp_pasvtrans(az_mini_cli ctx, char *dtp_ip, int *dtp_port)
{
    az_ftp_msg reply = NULL;
    const char *res = NULL;
    char *start = NULL;
    char p1[8] = { 0 };
    char p2[8] = { 0 };
    char h1[4] = { 0 };
    char h2[4] = { 0 };
    char h3[4] = { 0 };
    char h4[4] = { 0 };
    int port = 0;
    char ip[AZ_IPV4_ADDRESS_STRING_LEN] = { 0 };

    if (ctx == NULL || dtp_ip == NULL || dtp_port == NULL)
        return AZ_ERROR;

    if (__az_dtp_send_cmd(ctx, FTP_CMD_PASV, NULL) != AZ_OK)
        return AZ_ERROR;
    reply = __az_dtp_waite_reply(ctx, false);
    if (reply == NULL)
        return AZ_ERROR;
    if (az_ftp_msg_get_code(reply) != AZ_FTP_PASV_OK)
        goto ERR;
    res = az_ftp_msg_get_res(reply);
    if (res == NULL)
        goto ERR;

    start = az_strschr(res, '(', false);
    if (start == NULL)
        goto ERR;
    start++;

    sscanf(start, "%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]%*[',']%[0-9]", h1, h2, h3, h4, p1, p2);
    if (*h1 == '\0' || *h2 == '\0' || *h3 == '\0' || *h4 == '\0' || *p1 == '\0' || *p2 == '\0')
        goto ERR;
    snprintf(ip, AZ_IPV6_ADDRESS_STRING_LEN, "%s.%s.%s.%s", h1, h2, h3, h4);
    if (az_check_ipv4(ip) != AZ_OK)
        goto ERR;
    port = atoi(p1) * 256 + atoi(p2);
    if (port <= 0 || port >= 65535)
        goto ERR;

    az_strncpy(dtp_ip, AZ_IPV4_ADDRESS_STRING_LEN, ip, az_strlen(ip));
    *dtp_port = port;

    az_ftp_msg_free(&reply);
    return AZ_OK;
ERR:
    if (reply != NULL)
        az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

static az_ret __az_dtp_send_cmd(az_mini_cli ctx, az_ftp_cmd type, const char *argv)
{
    az_ftp_msg cmd = NULL;
    const char *send_data = NULL;
    int flag = 0;

    if (ctx == NULL)
        return AZ_ERROR;

    cmd = az_ftp_make_cmd(ctx->mp, type, argv);
    if (cmd == NULL)
        goto ERR;

    send_data = az_ftp_msg_to_str(cmd);
    if (send_data == NULL)
        goto ERR;

    flag = az_send(ctx->ctl_fd, send_data, az_strlen(send_data), 0);
    if (flag == AZ_ERROR || flag != az_strlen(send_data))
        goto ERR;
    else if (flag == 0)
        goto ERR;
    az_ftp_msg_free(&cmd);

    return AZ_OK;
ERR:
    if (cmd != NULL)
        az_ftp_msg_free(&cmd);
    return AZ_ERROR;
}

static az_ftp_msg __az_dtp_waite_reply(az_mini_cli ctx, bool temporary)
{
    int flag = 0;
    int recv_len = 0;
    az_ftp_msg reply = NULL;

    if (ctx == NULL)
        return NULL;

    while (az_atomic_read(&ctx->trans_info->trans_state) == AZ_TRANS_RUNNING)
    {
        if (ctx->data_len > 0)
        {
        REPARSER:
            flag = az_ftp_reply_parser(ctx->mp, ctx->recv_buf, 2 * 1024 * 1024, &ctx->data_len, &reply);
            if (flag == 1)
            {
                if (ctx->log_flag)
                    az_writelog(AZ_LOG_INFO, "az client ftp: recv reply data ...");
            }
            else if (flag != AZ_ERROR)
            {
                if (!temporary && az_ftp_msg_get_code(reply) >= 100 && az_ftp_msg_get_code(reply) < 200)
                    az_ftp_msg_free(&reply);
                else
                    break;
            }
            if (flag == AZ_AGAIN)
                goto REPARSER;
            if (flag == AZ_ERROR)
            {
                if (ctx->log_flag)
                    az_writelog(AZ_LOG_ERROR, "az client ftp: parser server reply failed");
            }
        }

        recv_len = az_recv(ctx->ctl_fd, ctx->recv_buf + ctx->data_len, 2 * 1024 * 1024 - ctx->data_len, 0);
        if (recv_len == AZ_ERROR)
            break;
        else if (recv_len == 0)
            break;
        else if (recv_len > 0)
            ctx->data_len += recv_len;
    }

    return reply;
}

static void __az_file_rlock(int fd)
{
    int flag = 0;
    struct flock the_lock;

    Az_Memzero(&the_lock, sizeof(struct flock));
    the_lock.l_type = F_RDLCK;
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0;

    do
    {
        flag = fcntl(fd, F_SETLKW, &the_lock);
    } while (flag < 0 && errno == EINTR);
}

static void __az_file_wlock(int fd)
{
    int flag = 0;
    struct flock the_lock;

    Az_Memzero(&the_lock, sizeof(struct flock));
    the_lock.l_type = F_WRLCK;
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0;

    do
    {
        flag = fcntl(fd, F_SETLKW, &the_lock);
    } while (flag < 0 && errno == EINTR);
}

static void __az_file_unlock(int fd)
{
    struct flock the_lock;
    Az_Memzero(&the_lock, sizeof(struct flock));
    the_lock.l_type = F_UNLCK;
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0;

    fcntl(fd, F_SETLK, &the_lock);
}

static int __az_file_write(int fd, uint8_t *data, int len)
{
    int flag = 0;
    int write_len = 0;

    if (fd < 0 || data == NULL || len <= 0)
        return AZ_ERROR;

    do
    {
        flag = write(fd, data + write_len, len - write_len);
        if (flag < 0)
        {
            if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
            {
                az_msleep(1);
                continue;
            }
            else
                return write_len;
        }
        write_len += flag;
    } while (write_len < len);

    return write_len;
}
