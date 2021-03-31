#include"az_ftp_client_ctrl.h"

struct az_ftp_clictrl_s
{
    az_atomic_t state;
    az_memp mp;
    bool log_flag;
    //az_taskp tp;

    az_net ctl_fd;
    az_thread th_send;
    az_thread th_recv;
    char *hello_str;

    az_list list_cmd;
    az_list list_reply_ev;
    //az_list list_mini_cli;
};

//az_ret az_cli_connect_ok(az_ftp_client cli);
//az_ret az_cli_login(az_ftp_client cli);
//az_ret az_cli_logout(az_ftp_client cli);
//az_ret az_cli_cwd(az_ftp_client cli, const char *path);
//az_ret az_cli_cdup(az_ftp_client cli);
//
//az_ret az_cli_active(az_ftp_client cli, char *rm_ip, int rm_port, az_net **dtp_fd);
//az_ret az_cli_passive(az_ftp_client cli, char *ser_ip, int *ser_port);
//
//az_ret az_cli_download(az_ftp_client cli, const char *rm_path, const char *lo_path, off_t offset);
//az_ret az_cli_upload(az_ftp_client cli, const char *lo_path, const char *rm_path, off_t offset);
//az_ret az_cli_rename(az_ftp_client cli, const char *old, const char *new);
//az_ret az_cli_delete(az_ftp_client cli, const char *file);
//az_ret az_cli_rmd(az_ftp_client cli, const char *dir);
//az_ret az_cli_mkdir(az_ftp_client cli, const char *path);
//az_ret az_cli_pwd(az_ftp_client cli);
//az_ret az_cli_list(az_memp pool, az_ftp_client cli, char *path, char **list);
//az_ret az_cli_nlist(az_memp pool, az_ftp_client cli, char *path, char **nlist);
//az_ret az_cli_noop(az_ftp_client cli);
//static az_ret _az_pi_list(az_memp pool, az_ftp_client cli, az_ftp_cmd type, char *path, char **data);
//static az_ftp_msg _az_waite_end(az_ftp_client cli);

static int __az_find_by_cmd(az_clictrl_ev data, az_ftp_cmd *cmd);
static int __az_find_by_next(az_clictrl_ev data, void *req);
static int _az_clictrl_send_cmd(void *data);
static int _az_clictrl_recv_reply(void *data);

az_ftp_clictrl az_clictrl_create(az_memp pool, const char *ser_ip, int ser_port, bool log_flag)
{
    az_ftp_clictrl tmp = NULL;
    az_clictrl_event_t hello;
    az_clictrl_ev hello_info = NULL;

    if (pool == NULL || ser_ip == NULL || *ser_ip == '\0' || ser_port <= 0 || ser_port > 65535)
        return NULL;

    tmp = (az_ftp_clictrl)az_mpcalloc(pool, sizeof(az_ftp_clictrl_t));
    if (tmp == NULL)
        return NULL;

    tmp->mp = pool;
    tmp->log_flag = log_flag;
    az_atomic_set(&tmp->state, AZ_FTP_CLIENT_INIT);

    tmp->list_cmd = az_list_init(AZ_DEF_QUEUE_LIST, 0, sizeof(az_ftp_msg), 5, true);
    if (tmp->list_cmd == NULL)
        goto ERR;
    tmp->list_reply_ev = az_list_init(AZ_DEF_QUEUE_LIST, 1, sizeof(az_clictrl_event_t), 5, true);
    if (tmp->list_reply_ev == NULL)
        goto ERR;

    tmp->ctl_fd = az_create_socket(tmp->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
    if (tmp->ctl_fd == NULL)
    {
        if (tmp->log_flag)
            az_writelog(AZ_LOG_ERROR, "az ftp client: create socket failed");
        goto ERR;
    }
    if (az_connect_socket(tmp->ctl_fd, (char *)ser_ip, ser_port) != AZ_OK)
    {
        if (tmp->log_flag)
            az_writelog(AZ_LOG_ERROR, "az ftp client: socket connect to ftp server [%s:%d] failed", ser_ip, ser_port);
        goto ERR;
    }
    if (az_socket_set_nonblock(tmp->ctl_fd, AZ_SOCKET_NONBLOCK) != AZ_OK)
    {
        if (tmp->log_flag)
            az_writelog(AZ_LOG_ERROR, "az ftp client: ser ctl socket no-block failed");
        goto ERR;
    }
    
    az_atomic_set(&tmp->state, AZ_FTP_CLIENT_RUN);
    hello.cmd = FTP_CMD_UNKNOWN;
    hello.code = 0;
    hello.msg = NULL;
    hello.msg_len = 0;
    az_list_insert(tmp->list_reply_ev, AZ_LIST_TAIL, 0, &hello, sizeof(az_clictrl_event_t));
    tmp->th_recv = az_create_thread(tmp->mp, "pi_recv", 0, false, true, _az_clictrl_recv_reply, tmp);
    if (tmp->th_recv == NULL)
        goto ERR;
    tmp->th_send = az_create_thread(tmp->mp, "pi_send", 0, false, true, _az_clictrl_send_cmd, tmp);
    if (tmp->th_send == NULL)
        goto ERR;

    hello_info = az_clictrl_waite(tmp, FTP_CMD_UNKNOWN, false);
    if (hello_info == NULL)
        goto ERR;
    if (hello_info->msg != NULL)
    {
        if (tmp->log_flag)
            az_writelog(AZ_LOG_INFO, "%s", hello_info->msg);
        tmp->hello_str = (char *)az_mpcalloc(tmp->mp, az_strlen(hello_info->msg) + 1);
        if (tmp->hello_str != NULL)
            az_strncpy(tmp->hello_str, az_strlen(hello_info->msg) + 1, hello_info->msg, az_strlen(hello_info->msg));
    }
    az_clictrl_evfree(tmp, &hello_info);

    return tmp;
ERR:
    if (tmp != NULL)
    {
        az_atomic_set(&tmp->state, AZ_FTP_CLIENT_ERR);

        if (tmp->th_recv != NULL)
            az_waite_thread(&tmp->th_recv);
        if (tmp->th_send != NULL)
            az_waite_thread(&tmp->th_send);
        if (tmp->ctl_fd != NULL)
            az_close_socket(&tmp->ctl_fd);
        if (tmp->list_reply_ev != NULL)
            az_list_destory(&tmp->list_reply_ev);
        if (tmp->list_cmd != NULL)
            az_list_destory(&tmp->list_cmd);
        az_mpfree(pool, (void **)&tmp);
    }
    return NULL;
}

void az_clictrl_netinfo(az_ftp_clictrl pi, az_netinfo_ipv4 netinfo)
{
    if (pi == NULL || netinfo == NULL)
        return;

    az_socket_connect_info(pi->ctl_fd, NULL, netinfo);
}

const char* az_clictrl_serhello(az_ftp_clictrl pi)
{
    if (pi == NULL || pi->hello_str == NULL)
        return NULL;
    return (const char *)pi->hello_str;
}

az_ret az_clictrl_exec(az_ftp_clictrl pi, az_ftp_cmd cmd, const char *argv)
{
    az_ftp_msg msg = NULL;

    if (pi == NULL || az_atomic_read(&pi->state) != AZ_FTP_CLIENT_RUN)
        return AZ_ERROR;

    msg = az_ftp_make_cmd(pi->mp, cmd, argv);
    if (msg == NULL)
        return AZ_ERROR;

    az_list_insert(pi->list_cmd, AZ_LIST_TAIL, 0, &msg, sizeof(az_ftp_msg));

    return AZ_OK;
}

az_clictrl_ev az_clictrl_waite(az_ftp_clictrl pi, az_ftp_cmd cmd, bool temporary)
{
    az_clictrl_ev tmp = NULL;

    if (pi == NULL)
        return NULL;

    while (az_atomic_read(&pi->state) == AZ_FTP_CLIENT_RUN || az_atomic_read(&pi->state) == AZ_FTP_CLIENT_SERCLOSE)
    {
        tmp = az_list_reqfindnd(pi->list_reply_ev, AZ_LIST_HEAD, (az_list_find_reqh)__az_find_by_cmd, &cmd, NULL);
        if (tmp != NULL && temporary)
            break;
        else if (tmp != NULL && tmp->code >= 200)
            break;
        az_msleep(10);
    }

    return tmp;
}

void az_clictrl_evfree(az_ftp_clictrl pi, az_clictrl_ev *reply)
{
    if (pi == NULL || *reply == NULL)
        return;

    if ((*reply)->msg != NULL)
        az_mpfree(pi->mp, (void **)&(*reply)->msg);

    az_list_delnd(pi->list_reply_ev, (void **)reply);
}

az_ftp_client_status az_clictrl_state(az_ftp_clictrl pi)
{
    return az_atomic_read(&pi->state);
}

void az_clictrl_destory(az_ftp_clictrl *pi)
{
    if (*pi == NULL)
        return;

    if (az_atomic_read(&(*pi)->state) == AZ_FTP_CLIENT_RUN)
        az_atomic_set(&(*pi)->state, AZ_FTP_CLIENT_CLOSE);

    if ((*pi)->th_recv != NULL)
        az_waite_thread(&(*pi)->th_recv);
    if ((*pi)->th_send != NULL)
        az_waite_thread(&(*pi)->th_send);
    if ((*pi)->ctl_fd != NULL)
        az_close_socket(&(*pi)->ctl_fd);
    if ((*pi)->list_reply_ev != NULL)
    {
        az_clictrl_event_t reply;

        while (az_list_size((*pi)->list_reply_ev) > 0)
        {
            if (az_list_pop((*pi)->list_reply_ev, AZ_LIST_HEAD, &reply, NULL) == AZ_OK)
            {
                if (reply.msg != NULL)
                    az_mpfree((*pi)->mp, (void **)&reply.msg);
            }
        }
        az_list_destory(&(*pi)->list_reply_ev);
    }
    if ((*pi)->list_cmd != NULL)
    {
        az_ftp_msg cmd = NULL;

        while (az_list_size((*pi)->list_cmd) > 0)
        {
            az_list_pop((*pi)->list_cmd, AZ_LIST_HEAD, &cmd, NULL);
            if (cmd != NULL)
                az_ftp_msg_free(&cmd);
        }
        az_list_destory(&(*pi)->list_cmd);
    }
    if ((*pi)->hello_str != NULL)
        az_mpfree((*pi)->mp, (void **)&(*pi)->hello_str);
    az_mpfree((*pi)->mp, (void **)pi);
}

static int _az_clictrl_send_cmd(void *data)
{
    int flag = 0;
    int num = 0;
    int epfd = -1;
    struct epoll_event ev;
    struct epoll_event events[1];
    az_ftp_clictrl ctx = NULL;
    az_ftp_msg cmd = NULL;
    az_clictrl_event_t reply;

    if (data == NULL)
        return 0;
    ctx = (az_ftp_clictrl)data;

    epfd = epoll_create(1);
    if (epfd < 0)
    {
        if (ctx->log_flag)
            az_writelog(AZ_LOG_ERROR, "Az FTP: recv epoll fd create error!");
        az_atomic_set(&ctx->state, AZ_FTP_CLIENT_ERR);
        goto ERR;
    }

    while (az_atomic_read(&ctx->state) == AZ_FTP_CLIENT_RUN)
    {
        int send_len = 0;
        int data_len = 0;

        if (cmd == NULL)
            az_list_get(ctx->list_cmd, AZ_LIST_HEAD, &cmd, NULL);
        if (cmd == NULL)
        {
            az_msleep(10);
            continue;
        }

        ev.data.fd = az_socket_get_fd(ctx->ctl_fd);  //设置要处理的事件类型
        ev.events = EPOLLOUT;
        flag = epoll_ctl(epfd, EPOLL_CTL_ADD, az_socket_get_fd(ctx->ctl_fd), &ev);
        if (flag != 0)
        {
            if (ctx->log_flag)
                az_writelog(AZ_LOG_ERROR, "FTP send: send fd add epoll event error!");
            az_msleep(10);
            continue;
        }
        do
        {
            num = epoll_wait(epfd, events, 1, 50);
            if (num > 0 && events[0].data.fd == az_socket_get_fd(ctx->ctl_fd))
            {
                const char *send_data = NULL;

                send_data = az_ftp_msg_to_str(cmd);
                data_len = az_strlen(send_data);

                flag = az_send(ctx->ctl_fd, send_data + send_len, data_len - send_len, 0);
                if (flag == AZ_ERROR)
                {
                    az_atomic_set(&ctx->state, AZ_FTP_CLIENT_LINKERR);
                    break;
                }
                else if (flag == 0)
                {
                    az_atomic_set(&ctx->state, AZ_FTP_CLIENT_SERCLOSE);
                    break;
                }
                else
                    send_len += flag;
            }
        } while (send_len < data_len);
        epoll_ctl(epfd, EPOLL_CTL_DEL, az_socket_get_fd(ctx->ctl_fd), &ev);

        reply.cmd = az_ftp_msg_get_cmd(cmd);
        if (send_len < data_len)
            reply.code = AZ_ERROR;
        else
            reply.code = 0;
        reply.msg_len = 0;
        reply.msg = NULL;
        az_list_insert(ctx->list_reply_ev, AZ_LIST_TAIL, 0, &reply, sizeof(az_clictrl_event_t));

        az_list_pop(ctx->list_cmd, AZ_LIST_HEAD, NULL, NULL);
        az_ftp_msg_free(&cmd);
    }

    close(epfd);
    return 0;
ERR:
    az_atomic_set(&ctx->state, AZ_FTP_CLIENT_ERR);
    if (epfd >= 0)
        close(epfd);
    return -1;
}

static int _az_clictrl_recv_reply(void *data)
{
    int flag = 0;
    int num = 0;
    int epfd = -1;
    struct epoll_event ev;
    struct epoll_event events[1];
    az_ftp_clictrl ctx = NULL;
    char recv_buf[2 * 1024 * 1024] = { 0 };
    int data_len = 0;
    int recv_len = 0;
    az_ftp_msg reply = NULL;

    if (data == NULL)
        return 0;
    ctx = (az_ftp_clictrl)data;

    epfd = epoll_create(1);
    if (epfd < 0)
    {
        if (ctx->log_flag)
            az_writelog(AZ_LOG_ERROR, "Az FTP: recv epoll fd create error!");
        az_atomic_set(&ctx->state, AZ_FTP_CLIENT_ERR);
        goto ERR;
    }

    ev.data.fd = az_socket_get_fd(ctx->ctl_fd);  //设置要处理的事件类型
    ev.events = EPOLLIN | EPOLLET;
    flag = epoll_ctl(epfd, EPOLL_CTL_ADD, az_socket_get_fd(ctx->ctl_fd), &ev);
    if (flag != 0)
    {
        if (ctx->log_flag)
            az_writelog(AZ_LOG_ERROR, "Az FTP: recv epoll fd create error!");
        az_atomic_set(&ctx->state, AZ_FTP_CLIENT_ERR);
        goto ERR;
    }

    while (az_atomic_read(&ctx->state) == AZ_FTP_CLIENT_RUN)
    {
        num = epoll_wait(epfd, events, 1, 500);
        if (num <= 0)
            continue;

        if ((events[0].events & EPOLLIN) && events[0].data.fd == az_socket_get_fd(ctx->ctl_fd))
        {
            recv_len = az_recv(ctx->ctl_fd, recv_buf + data_len, 2 * 1024 * 1024 - data_len, 0);
            if (recv_len == AZ_ERROR)
            {
                if (ctx->log_flag)
                    az_writelog(AZ_LOG_ERROR, "az ftp client: server ctrl link err");
                az_atomic_set(&ctx->state, AZ_FTP_CLIENT_LINKERR);
            }
            else if (recv_len == 0)
            {
                if (ctx->log_flag)
                    az_writelog(AZ_LOG_INFO, "az ftp client: server ctrl link closed");
                az_atomic_set(&ctx->state, AZ_FTP_CLIENT_SERCLOSE);
            }
            else if (recv_len > 0)
            {
                data_len += recv_len;
                //az_writelog(AZ_LOG_DEBUG, "recv th: recv data: %s [recv len: %d data len: %d]", recv_buf, recv_len, data_len);
            REPARSER:
                flag = az_ftp_reply_parser(ctx->mp, recv_buf, 2 * 1024 * 1024, &data_len, &reply);
                if (flag == 1)
                    continue;
                else if (flag != AZ_ERROR)
                {
                    az_clictrl_ev reply_info = NULL;

                    reply_info = (az_clictrl_ev)az_list_reqfindnd(ctx->list_reply_ev, AZ_LIST_HEAD, (az_list_find_reqh)__az_find_by_next, &reply_info, NULL);
                    if (reply_info != NULL)
                    {
                        reply_info->code = az_ftp_msg_get_code(reply);
                        if (reply_info->msg == NULL)
                        {
                            reply_info->msg_len = az_strlen(az_ftp_msg_get_res(reply));
                            reply_info->msg = (char *)az_mpcalloc(ctx->mp, reply_info->msg_len + 1);
                            if (reply_info->msg != NULL)
                                az_strncpy(reply_info->msg, reply_info->msg_len + 1, az_ftp_msg_get_res(reply), reply_info->msg_len);
                        }
                        else
                        {
                            char *tmp = NULL;

                            tmp = (char *)az_mprealloc(ctx->mp, (void **)&reply_info->msg, az_strlen(az_ftp_msg_get_res(reply)) + 1);
                            if (tmp == NULL)
                            {
                                reply_info->msg_len = 0;
                                az_mpfree(ctx->mp, (void **)&reply_info->msg);
                            }
                            else
                            {
                                reply_info->msg = tmp;
                                reply_info->msg_len = az_strlen(az_ftp_msg_get_res(reply));
                                az_strncpy(reply_info->msg, reply_info->msg_len + 1, az_ftp_msg_get_res(reply), reply_info->msg_len);
                            }
                        }
                    }
                    if (ctx->log_flag)
                    {
                        az_writelog(AZ_LOG_DEBUG, "recv th: az_ftp_msg_get_code(reply): %d", az_ftp_msg_get_code(reply));
                        az_writelog(AZ_LOG_DEBUG, "recv th: az_ftp_msg_get_res(reply): %s", az_ftp_msg_get_res(reply));
                    }
                    az_ftp_msg_free(&reply);
                }
                if (flag == AZ_AGAIN)
                    goto REPARSER;
                if (flag == AZ_ERROR)
                {
                    if (ctx->log_flag)
                        az_writelog(AZ_LOG_ERROR, "az client ftp: parser server reply failed");
                }
            }
        }
    }
    epoll_ctl(epfd, EPOLL_CTL_DEL, az_socket_get_fd(ctx->ctl_fd), &ev);

    close(epfd);
    return 0;
ERR:
    az_atomic_set(&ctx->state, AZ_FTP_CLIENT_ERR);
    if (epfd >= 0)
        close(epfd);
    return -1;
}

static int __az_find_by_cmd(az_clictrl_ev data, az_ftp_cmd *cmd)
{
    if (data->cmd == *cmd && (data->code < 0 || data->code >= 100))
        return AZ_OK;
    return AZ_ERROR;
}

static int __az_find_by_next(az_clictrl_ev data, void *req)
{
    if (data->code >= 0 && data->code < 200)
        return AZ_OK;
    return AZ_ERROR;
}

/*
az_ret az_cli_connect_ok(az_ftp_client cli)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL)
        return AZ_ERROR;

    reply = az_cli_waite_reply(cli);
    if (reply == NULL)
        return AZ_ERROR;

    while (az_atomic_read(&cli->state) == AZ_FTP_CLIENT_RUN)
    {
        if (az_ftp_msg_get_code(reply) >= 100 && az_ftp_msg_get_code(reply) <= 199)
        {
            az_writelog(AZ_LOG_INFO, "az client ftp: ftp server waite state: %d/%s", az_ftp_msg_get_code(reply), az_ftp_msg_get_res(reply));
            az_ftp_msg_free(&reply);
            reply = az_cli_waite_reply(cli);
            if (reply == NULL)
                return AZ_ERROR;
            continue;
        }
        else if (az_ftp_msg_get_code(reply) == AZ_FTP_SER_READY)
        {
            az_writelog(AZ_LOG_INFO, "az client ftp: recv ftp server hello message: %s", az_ftp_msg_get_res(reply));
            az_ftp_msg_free(&reply);
            return AZ_OK;
        }
        else
        {
            az_writelog(AZ_LOG_INFO, "az client ftp: ftp server err state: %d/%s", az_ftp_msg_get_code(reply), az_ftp_msg_get_res(reply));
            break;
        }
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_login(az_ftp_client cli)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL)
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_USER, cli->user_name) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_NEED_PASS)
    {
        az_ftp_msg_free(&reply);
        if (az_cli_send_cmd(cli, FTP_CMD_PASS, cli->pwd) != AZ_OK)
            return AZ_ERROR;

        reply = _az_waite_end(cli);
        if (reply == NULL)
            return AZ_ERROR;
    }

    if (az_ftp_msg_get_code(reply) == AZ_FTP_LOGIN_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_logout(az_ftp_client cli)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL)
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_QUIT, NULL) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_LOGOUT_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_cwd(az_ftp_client cli, const char *path)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL || path == NULL || *path == '\0')
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_CWD, path) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_REQ_FILE_OK)
    {
        const char *res = NULL;
        int deep = 0;
        char *start = NULL;

        res = az_ftp_msg_get_res(reply);
        if (res == NULL)
        {
            az_ftp_msg_free(&reply);
            return AZ_ERROR;
        }
        if (*res != '"' || az_strschr(++res, '"') == NULL)
        {
            az_ftp_msg_free(&reply);
            return AZ_ERROR;
        }
        az_strncpy(cli->dir_current, AZ_FTP_PATH_MAX_LEN, res, az_strschr(res, '"') - res);
        if (cli->dir_current[az_strlen(cli->dir_current) - 1] == '/')
            cli->dir_current[az_strlen(cli->dir_current) - 1] = '\0';
        for (start = az_strschr(cli->dir_current, '/'); start != NULL; start = az_strschr(start, '/'))
        {
            start++;
            if (*start != '\0')
                deep++;
        }
        cli->dir_deep = deep;

        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_cdup(az_ftp_client cli)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL)
        return AZ_ERROR;

    if (cli->dir_deep == 0)
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_CDUP, NULL) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_CMD_OK)
    {
        cli->dir_deep--;
        if (cli->dir_deep == 0)
            az_strncpy(cli->dir_current, AZ_FTP_PATH_MAX_LEN, "/", az_strlen("/"));
        else
        {
            int loop = 0;
            for (loop = az_strlen(cli->dir_current) - 1; loop >= 0; loop--)
            {
                if (cli->dir_current[loop] == '/')
                    break;
            }
            cli->dir_current[loop] = '\0';
        }

        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_active(az_ftp_client cli, char *rm_ip, int rm_port, az_net **dtp_fd)
{
    az_ftp_msg reply = NULL;
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

    if (cli == NULL)
        return AZ_ERROR;

    if (rm_ip == NULL || *rm_ip == '\0' || rm_port <= 0 || rm_port > 65535)
    {
        int flag = 0;
        az_socket_connect_info(cli->ctl_fd, NULL, &netinfo);
        rm_ip = netinfo.local_ip;

        act_fd = az_create_socket(cli->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
        if (act_fd == NULL)
        {
            return AZ_ERROR;
        }
        do
        {
            flag = az_bind_socket(act_fd, rm_ip, def_act_port);
            if (flag == AZ_OK)
                break;
            def_act_port++;
            if (def_act_port >= 65535)
                def_act_port = 10000;
        } while (1);
        flag = az_listen_socket(act_fd, 1);
        if (flag != AZ_OK)
        {
            az_close_socket(&act_fd);
            return AZ_ERROR;
        }
        rm_port = def_act_port;
    }
    p1 = rm_port / 256;
    p2 = rm_port % 256;
    sscanf(rm_ip, "%[0-9].%[0-9].%[0-9].%[0-9]", h1, h2, h3, h4);
    snprintf(text, 128, "%s,%s,%s,%s,%d,%d", h1, h2, h3, h4, p1, p2);

    if (az_cli_send_cmd(cli, FTP_CMD_PORT, text) != AZ_OK)
        goto ERR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        goto ERR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_CMD_OK)
    {
        if (dtp_fd != NULL)
            *dtp_fd = act_fd;
        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

ERR:
    if (act_fd != NULL)
        az_close_socket(&act_fd);
    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_passive(az_ftp_client cli, char *ser_ip, int *ser_port)
{
    az_ftp_msg reply = NULL;
    const char *res = NULL;
    char p1[8] = { 0 };
    char p2[8] = { 0 };
    char h1[4] = { 0 };
    char h2[4] = { 0 };
    char h3[4] = { 0 };
    char h4[4] = { 0 };
    int port = 0;
    char ip[AZ_IPV4_ADDRESS_STRING_LEN] = { 0 };

    if (cli == NULL || ser_ip == NULL || ser_port == NULL)
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_PASV, NULL) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_PASV_OK)
    {
        char *start = NULL;

        res = az_ftp_msg_get_res(reply);
        if (res == NULL)
            goto ERR;

        start = az_strschr(res, '(');
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

        az_strncpy(ser_ip, AZ_IPV4_ADDRESS_STRING_LEN, ip, az_strlen(ip));
        ser_port = port;

        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

ERR:
    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

//rm_path只能是远程文件路径不能是目录，lo_path只能是本地已存在的目录
az_ret az_cli_download(az_ftp_client cli, const char *rm_path, const char *lo_path, off_t offset)
{
    int flag = 0;
    struct stat statbuf;
    char *file_info = NULL;
    off_t file_size = 0;
    az_mini_cli mini_client = NULL;
    az_task_info_t task = { 0 };

    if (cli == NULL || rm_path == NULL || *rm_path == '\0')
        return AZ_ERROR;
    if (lo_path != NULL && *lo_path != '\0')
    {
        if (stat(lo_path, &statbuf) != 0 || !(S_IFDIR & statbuf.st_mode))
            return AZ_ERROR;
    }

    flag = az_cli_list(cli->mp, cli, rm_path, &file_info);
    if (flag != AZ_OK)
        return AZ_ERROR;

    //这里解析文件大小


    mini_client = (az_mini_cli)az_list_allocnd(cli->mini_cli_list, sizeof(az_mini_cli_t));
    if (mini_client == NULL)
        goto ERR;

    mini_client->type = AZ_FTP_DOWNLOAD;
    mini_client->state = AZ_TRANS_WAITE;
    az_strncpy(mini_client->remote_dir, AZ_FTP_PATH_MAX_LEN, rm_path, az_strlen(rm_path));
    if (lo_path != NULL && *lo_path != '\0')
        az_strncpy(mini_client->local_dir, AZ_FTP_PATH_MAX_LEN, lo_path, az_strlen(lo_path));
    else
        az_strncpy(mini_client->local_dir, AZ_FTP_PATH_MAX_LEN, "./", az_strlen("./"));
    mini_client->offset = offset;
    mini_client->file_size = file_size;
    mini_client->mp = cli->mp;
    mini_client->user_name = cli->user_name;
    mini_client->pwd = cli->pwd;
    mini_client->dtp_mode = cli->dtp_mode;
    mini_client->trans_mode = cli->trans_mode;
    az_strncpy(mini_client->dir_current, AZ_FTP_PATH_MAX_LEN, cli->dir_current, az_strlen(cli->dir_current));

    task.level = TASK_LEVEL_0;
    task.func = (az_task_hd)az_clidtp_download;
    task.finish_cb = NULL;
    task.param = mini_client;
    task.data_len = 0;
    *task.task_name = '\0';

    az_tpadd(cli->tp, &task);
    az_list_insertnd(cli->mini_cli_list, AZ_LIST_TAIL, az_list_size(cli->mini_cli_list), mini_client);

    az_mpfree(cli->mp, (void **)file_info);
    return AZ_OK;
ERR:
    if (file_info != NULL)
        az_mpfree(cli->mp, (void **)file_info);
    if (mini_client != NULL)
        az_list_delnd(cli->mini_cli_list, (void **)&mini_client);
    return AZ_ERROR;
}

//lo_path只能是本地文件路径不能是目录，rm_path只能是远端已存在的路径
az_ret az_cli_upload(az_ftp_client cli, const char *lo_path, const char *rm_path, off_t offset)
{
    char bk_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };
    az_ftp_msg reply = NULL;
    struct stat statbuf;
    az_mini_cli mini_client = NULL;
    az_task_info_t task = { 0 };

    if (cli == NULL || lo_path == NULL || *lo_path == '\0')
        return AZ_ERROR;
    if (stat(lo_path, &statbuf) != 0 || !(S_IFMT & statbuf.st_mode))
        return AZ_ERROR;

    if (rm_path != NULL && *rm_path != '\0')
    {
        az_strncpy(bk_dir, AZ_FTP_PATH_MAX_LEN, cli->dir_current, az_strlen(cli->dir_current));
        if (az_cli_cwd(cli, rm_path) != AZ_OK)
            return AZ_ERROR;
    }

    mini_client = (az_mini_cli)az_list_allocnd(cli->mini_cli_list, sizeof(az_mini_cli_t));
    if (mini_client == NULL)
        return AZ_ERROR;
    mini_client->type = AZ_FTP_UPLOAD;
    mini_client->state = AZ_TRANS_WAITE;
    az_strncpy(mini_client->local_dir, AZ_FTP_PATH_MAX_LEN, lo_path, az_strlen(lo_path));
    az_strncpy(mini_client->remote_dir, AZ_FTP_PATH_MAX_LEN, cli->dir_current, az_strlen(cli->dir_current));
    mini_client->offset = offset;
    mini_client->file_size = statbuf.st_size;
    mini_client->mp = cli->mp;
    mini_client->user_name = cli->user_name;
    mini_client->pwd = cli->pwd;
    mini_client->dtp_mode = cli->dtp_mode;
    mini_client->trans_mode = cli->trans_mode;

    task.level = TASK_LEVEL_0;
    task.func = (az_task_hd)az_clidtp_upload;
    task.finish_cb = NULL;
    task.param = mini_client;
    task.data_len = 0;
    *task.task_name = '\0';

    az_tpadd(cli->tp, &task);
    az_list_insertnd(cli->mini_cli_list, AZ_LIST_TAIL, az_list_size(cli->mini_cli_list), mini_client);

    if (*bk_dir != '\0')
        az_cli_cwd(cli, bk_dir);
    return AZ_OK;
}

az_ret az_cli_rename(az_ftp_client cli, const char *old, const char *new)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL || old == NULL || *old == '\0' || new == NULL || *new == '\0')
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_RNFR, old) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) != AZ_FTP_NEED_FURTHER)
    {
        az_ftp_msg_free(&reply);
        return AZ_ERROR;
    }
    az_ftp_msg_free(&reply);

    if (az_cli_send_cmd(cli, FTP_CMD_RNTO, new) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_REQ_FILE_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_delete(az_ftp_client cli, const char *file)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL || file == NULL || *file == '\0')
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_DELE, file) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_REQ_FILE_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_rmd(az_ftp_client cli, const char *dir)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL || dir == NULL || *dir == '\0')
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_RMD, dir) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_REQ_FILE_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_mkdir(az_ftp_client cli, const char *path)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL || path == NULL || *path == '\0')
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_MKD, path) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_CREATE_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}

az_ret az_cli_pwd(az_ftp_client cli)
{
    az_ftp_msg reply = NULL;
    const char *res = NULL;
    int deep = 0;
    char *start = NULL;

    if (cli == NULL)
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_PWD, NULL) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) != AZ_FTP_CREATE_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_ERROR;
    }

    res = az_ftp_msg_get_res(reply);
    if (res == NULL)
    {
        az_ftp_msg_free(&reply);
        return AZ_ERROR;
    }
    if (*res != '"' || az_strschr(++res, '"') == NULL)
    {
        az_ftp_msg_free(&reply);
        return AZ_ERROR;
    }

    az_strncpy(cli->dir_current, AZ_FTP_PATH_MAX_LEN, res, az_strschr(res, '"') - res);
    if (cli->dir_current[az_strlen(cli->dir_current) - 1] == '/')
        cli->dir_current[az_strlen(cli->dir_current) - 1] = '\0';
    for (start = az_strschr(cli->dir_current, '/'); start != NULL; start = az_strschr(start, '/'))
    {
        start++;
        if (*start != '\0')
            deep++;
    }
    cli->dir_deep = deep;

    az_ftp_msg_free(&reply);
    return AZ_OK;
}

az_ret az_cli_list(az_memp pool, az_ftp_client cli, char *path, char **list)
{
    return _az_pi_list(pool, cli, FTP_CMD_LIST, path, list);
}

az_ret az_cli_nlist(az_memp pool, az_ftp_client cli, char *path, char **nlist)
{
    return _az_pi_list(pool, cli, FTP_CMD_NLST, path, nlist);
}

az_ret az_cli_noop(az_ftp_client cli)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL)
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_NOOP, NULL) != AZ_OK)
        return AZ_ERROR;

    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;

    if (az_ftp_msg_get_code(reply) == AZ_FTP_CMD_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_OK;
    }

    az_ftp_msg_free(&reply);
    return AZ_ERROR;
}
*/

/*
static az_ret _az_pi_list(az_memp pool, az_ftp_client cli, az_ftp_cmd type, char *path, char **data)
{
    int flag = 0;
    bool rpl_flag = false;
    az_ftp_msg reply = NULL;
    char ser_ip[AZ_IPV4_ADDRESS_STRING_LEN] = { 0 };
    int ser_port = 0;
    az_net listen_fd = NULL;
    az_net data_fd = NULL;
    char *tmp_data = NULL;
    int tmp_data_len = 0;
    int recv_data_len = 0;

    if (pool == NULL || cli == NULL || data == NULL || path == NULL || *path == '\0' || (type != FTP_CMD_LIST && type != FTP_CMD_NLST))
        return AZ_ERROR;

    if (az_cli_send_cmd(cli, FTP_CMD_TYPE, "A N") != AZ_OK)
        return AZ_ERROR;
    reply = _az_waite_end(cli);
    if (reply == NULL)
        return AZ_ERROR;
    if (az_ftp_msg_get_code(reply) != AZ_FTP_CMD_OK)
    {
        az_ftp_msg_free(&reply);
        return AZ_ERROR;
    }
    az_ftp_msg_free(&reply);

    tmp_data = (char *)az_mpcalloc(pool, 512);
    if (tmp_data == NULL)
        return AZ_ERROR;
    tmp_data_len += 512;

    if (cli->dtp_mode == DTP_ACTIVE_MODE)
    {
        if (az_cli_active(cli, NULL, 0, &listen_fd) != AZ_OK)
            goto ERR;
    }
    else
    {
        if (az_cli_passive(cli, ser_ip, &ser_port) != AZ_OK)
            goto ERR;
    }

    if (az_cli_send_cmd(cli, type, path) != AZ_OK)
        goto ERR;

    //可能需要接收150响应

    if (cli->dtp_mode == DTP_ACTIVE_MODE)
    {
        data_fd = az_accept_socket(cli->mp, listen_fd);
        if (data_fd == NULL)
            goto ERR;
        az_close_socket(&listen_fd);
    }
    else
    {
        data_fd = az_create_socket(cli->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
        if (data_fd == NULL)
            goto ERR;
        flag = az_connect_socket(data_fd, ser_ip, ser_port);
        if (flag != AZ_OK)
            goto ERR;
    }

    //可能需要接收125响应

    while (az_atomic_read(&cli->state) == AZ_FTP_CLIENT_RUN)
    {
        flag = az_recv(data_fd, tmp_data + recv_data_len, tmp_data_len - recv_data_len, 0);
        if (flag == AZ_ERROR)
        {
            az_writelog(AZ_LOG_ERROR, "az ftp client: recv list data err");
            rpl_flag = true;
            goto ERR;
        }
        else if (flag == AZ_AGAIN)
            continue;
        else if (flag == 0)
        {
            az_writelog(AZ_LOG_INFO, "az ftp client: recv list data end");
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
                {
                    rpl_flag = true;
                    goto ERR;
                }
                tmp_data = tmp;
            }
        }
    }

    do
    {
        reply = _az_waite_end(cli);
        //if (az_ftp_msg_get_code(reply) == AZ_FTP_DATACONN_OK || az_ftp_msg_get_code(reply) == AZ_FTP_FILE_OK)
        //    continue;
        if (az_ftp_msg_get_code(reply) == AZ_FTP_TRANSFER_OK)
        {
            *data = tmp_data;
            az_close_socket(&data_fd);
            az_ftp_msg_free(&reply);
            return AZ_OK;
        }
        else if (az_ftp_msg_get_code(reply) >= 300)
            break;
    } while (1);

ERR:
    if (listen_fd != NULL)
        az_close_socket(&listen_fd);
    if (data_fd != NULL)
        az_close_socket(&data_fd);
    if (tmp_data != NULL)
        az_mpfree(pool, (void **)&tmp_data);
    if (rpl_flag)
    {
        reply = _az_waite_end(cli);
        az_ftp_msg_free(&reply);
    }
    return AZ_ERROR;
}

static az_ftp_msg _az_waite_end(az_ftp_client cli)
{
    az_ftp_msg reply = NULL;

    do
    {
        az_ftp_msg_free(&reply);
        reply = az_cli_waite_reply(cli);
        if (reply == NULL)
            return NULL;
        //if (az_ftp_msg_get_code(reply) == AZ_FTP_DATACONN_OK || az_ftp_msg_get_code(reply) == AZ_FTP_FILE_OK)
        //    break;
    } while (az_atomic_read(&cli->state) == AZ_FTP_CLIENT_RUN && az_ftp_msg_get_code(reply) >= 100 && az_ftp_msg_get_code(reply) <= 199);

    return reply;
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
        const char *tmp = az_strschr(change, '/');
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
            az_strncpy(tmp_dir + offset, AZ_FTP_PATH_MAX_LEN - offset, change, tmp - change);
        }
        if (*tmp != '\0')
            change = tmp + 1;
        else
            change = tmp;
    }

    *dir_deep = deep;
    az_strncpy(work_dir, AZ_FTP_PATH_MAX_LEN, tmp_dir, az_strlen(tmp_dir));

    return AZ_OK;
}
*/