#include"az_ftp_server_dtp.h"
#if defined(__az_windows_32__) || defined(__az_windows_64__)
#else
#include<sys/sendfile.h>
#include<pwd.h>
#include<grp.h>
#endif

static void _az_file_rlock(int fd);
static void _az_file_wlock(int fd);
static void _az_file_unlock(int fd);
static int _az_file_write(int fd, uint8_t *data, int len);

static char* uid_to_name(uid_t uid);
static char* gid_to_name(gid_t gid);
static void command_list(az_ftp_session session, bool ex);
static az_net create_ftp_fd(az_memp pool, az_ftp_dtp_mode dtp_mode, az_net *listen_fd, char *dtp_ip, int dtp_port);
static int snfileinfo(char *buf, int buf_len, char *file_name, struct stat *info);
static int get_dir_info(az_memp pool, char *path, bool is_dir, bool ex, char **data);

void az_ftp_list_task(az_ftp_session session)
{
    if (session == NULL)
        return;

    command_list(session, true);
}

void az_ftp_nlist_task(az_ftp_session session)
{
    if (session == NULL)
        return;

    command_list(session, false);
}

void az_ftp_upload_task(az_ftp_session session)
{
    int flag = 0;
    int ret = 0;
    int file_fd = -1;
    bool locked = false;
    int epfd = -1;
    uint8_t recv_data[2 * 1024 * 1024] = { 0 };
    struct epoll_event ev;
    struct epoll_event events[1];
    int recv_len = 0;

    if (session == NULL)
        return;
    az_writelog(AZ_LOG_DEBUG, "session: start upload task ...");
    file_fd = open(session->file_name, O_CREAT | O_WRONLY, 0644);
    if (file_fd < 0)
    {
        ret = AZ_FTP_FILE_BUSY;
        az_writelog(AZ_LOG_ERROR, "session: open file [%s] failed", session->file_name);
        goto END;
    }
    _az_file_wlock(file_fd);
    locked = true;
    if (session->appe)
    {
        if (lseek(file_fd, 0, SEEK_END) < 0)
        {
            ret = AZ_FTP_FILE_ERR;
            az_writelog(AZ_LOG_ERROR, "session: seek to file [end] failed");
            goto END;
        }
    }
    else if (session->offset > 0)
    {
        if (lseek(file_fd, session->offset, SEEK_SET) < 0)
        {
            ret = AZ_FTP_FILE_ERR;
            az_writelog(AZ_LOG_ERROR, "session: seek to file [%ld] failed", session->offset);
            goto END;
        }
    }
    else
    {
        ftruncate(file_fd, 0);
        if (lseek(file_fd, 0, SEEK_SET) < 0)
        {
            ret = AZ_FTP_FILE_ERR;
            az_writelog(AZ_LOG_ERROR, "session: seek to file [0] failed");
            goto END;
        }
    }
    az_writelog(AZ_LOG_DEBUG, "session: file is readly");
    az_ftp_response(session->cli_ctx, AZ_FTP_FILE_OK, NULL);

    epfd = epoll_create(1);
    if (epfd < 0)
    {
        ret = AZ_FTP_LOCAL_ERR;
        az_writelog(AZ_LOG_ERROR, "session: create epoll fd failed");
        goto END;
    }
    session->data_fd = create_ftp_fd(session->cli_ctx->mp, session->dtp_mode, &session->data_fd, session->dtp_ip, session->dtp_port);
    if (session->data_fd == NULL)
    {
        ret = AZ_FTP_DATACONN_ERR;
        az_writelog(AZ_LOG_ERROR, "session: create data fd failed");
        goto END;
    }
    flag = az_socket_set_nonblock(session->data_fd, AZ_SOCKET_NONBLOCK);
    if (flag != AZ_OK)
    {
        ret = AZ_FTP_LOCAL_ERR;
        az_writelog(AZ_LOG_ERROR, "session: set data fd no block failed");
        goto END;
    }
    ev.data.fd = az_socket_get_fd(session->data_fd);  //设置要处理的事件类型
    ev.events = EPOLLIN | EPOLLHUP | EPOLLET;
    flag = epoll_ctl(epfd, EPOLL_CTL_ADD, az_socket_get_fd(session->data_fd), &ev);
    if (flag != 0)
    {
        ret = AZ_FTP_LOCAL_ERR;
        az_writelog(AZ_LOG_ERROR, "session: set epoll event failed");
        goto END;
    }
    az_writelog(AZ_LOG_DEBUG, "session: data link is readly");
    //az_ftp_response(session->mp, session->reply_list, AZ_FTP_DATACONN_OK, NULL);

    while (az_atomic_read(&session->run) && az_atomic_read(&session->abort) == AZ_FALSE)
    {
        //az_writelog(AZ_LOG_DEBUG, "session: data link waite for recv data ...");
        flag = epoll_wait(epfd, events, 1, 500);
        if (flag > 0 && events[0].data.fd == az_socket_get_fd(session->data_fd))
        {
            if (events[0].events & EPOLLIN)
            {
                do
                {
                    recv_len = az_recv(session->data_fd, recv_data, 2 * 1024 * 1024, 0);
                    //az_writelog(AZ_LOG_DEBUG, "session: data link recv len [%d]", recv_len);
                    if (recv_len == AZ_ERROR)
                    {
                        ret = AZ_FTP_TRANSFER_ABOR;
                        az_writelog(AZ_LOG_ERROR, "session: data link recv err");
                        goto END;
                    }
                    else if (recv_len == 0)
                    {
                        ret = AZ_FTP_TRANSFER_OK;
                        az_writelog(AZ_LOG_INFO, "session: data link closed");
                        goto END;
                    }
                    else if (recv_len > 0)
                    {
                        //az_writelog(AZ_LOG_DEBUG, "session: write data for file");
                        flag = _az_file_write(file_fd, recv_data, recv_len);
                        if (flag == AZ_ERROR)
                        {
                            ret = AZ_FTP_FILE_BUSY;
                            az_writelog(AZ_LOG_ERROR, "session: write file err");
                            goto END;
                        }
                        else if (flag != recv_len)
                        {
                            ret = AZ_FTP_NO_SPACE;
                            az_writelog(AZ_LOG_ERROR, "session: not have space");
                            goto END;
                        }
                    }
                } while (recv_len > 0);
            }
            else if (events[0].events & EPOLLHUP)
            {
                ret = AZ_FTP_TRANSFER_OK;
                az_writelog(AZ_LOG_INFO, "session: data link closed");
                break;
            }
        }
    }

END:
    if (epfd >= 0)
    {
        epoll_ctl(epfd, EPOLL_CTL_DEL, az_socket_get_fd(session->data_fd), &ev);
        close(epfd);
    }
    if (locked)
        _az_file_unlock(file_fd);
    if (file_fd >= 0)
        close(file_fd);
    if (session->data_fd != NULL)
        az_close_socket(&session->data_fd);
    if (az_atomic_read(&session->abort) == AZ_TRUE)
        ret = AZ_FTP_TRANSFER_ABOR;
    if (session->stou && ret == AZ_FTP_TRANSFER_OK)
        az_ftp_response(session->cli_ctx, AZ_FTP_REQ_FILE_OK, session->file_name);
    else
        az_ftp_response(session->cli_ctx, ret, NULL);
    az_writelog(AZ_LOG_DEBUG, "session: upload task end");
}

void az_ftp_download_task(az_ftp_session session)
{
    int flag = 0;
    int ret = 0;
    int file_fd = -1;
    bool locked = false;
    int epfd = -1;
    struct epoll_event ev;
    struct epoll_event events[1];
    off_t send_len = 0;
    struct stat statbuf;

    if (session == NULL)
        return;

    file_fd = open(session->file_name, O_RDONLY);
    if (file_fd < 0)
    {
        ret = AZ_FTP_FILE_BUSY;
        goto END;
    }
    _az_file_rlock(file_fd);
    locked = true;
    flag = fstat(file_fd, &statbuf);
    if (flag != 0 || !S_ISREG(statbuf.st_mode))
    {
        ret = AZ_FTP_FILE_ERR;
        goto END;
    }
    send_len = statbuf.st_size;
    if (session->offset > 0)
    {
        if (session->offset >= send_len)
            send_len = 0;
        else
            send_len -= session->offset;

        if (send_len > 0 && lseek(file_fd, session->offset, SEEK_SET) < 0)
        {
            ret = AZ_FTP_FILE_ERR;
            goto END;
        }
    }
    else
    {
        if (lseek(file_fd, 0, SEEK_SET) < 0)
        {
            ret = AZ_FTP_FILE_ERR;
            goto END;
        }
    }
    az_ftp_response(session->cli_ctx, AZ_FTP_FILE_OK, NULL);

    epfd = epoll_create(1);
    if (epfd < 0)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }
    session->data_fd = create_ftp_fd(session->cli_ctx->mp, session->dtp_mode, &session->data_fd, session->dtp_ip, session->dtp_port);
    if (session->data_fd == NULL)
    {
        ret = AZ_FTP_DATACONN_ERR;
        goto END;
    }
    flag = az_socket_set_nonblock(session->data_fd, AZ_SOCKET_NONBLOCK);
    if (flag != AZ_OK)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }
    ev.data.fd = az_socket_get_fd(session->data_fd);  //设置要处理的事件类型
    ev.events = EPOLLOUT;
    flag = epoll_ctl(epfd, EPOLL_CTL_ADD, az_socket_get_fd(session->data_fd), &ev);
    if (flag != 0)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }
    //az_ftp_response(session->mp, session->reply_list, AZ_FTP_DATACONN_OK, NULL);

    while (az_atomic_read(&session->run) && az_atomic_read(&session->abort) == AZ_FALSE && send_len > 0)
    {
        flag = epoll_wait(epfd, events, 1, 100);
        if (flag > 0 && events[0].data.fd == az_socket_get_fd(session->data_fd))
        {
            off_t ret_len = 0;
            int len = send_len > 4096 ? 4096 : send_len;
            ret_len = sendfile(az_socket_get_fd(session->data_fd), file_fd, NULL, len);
            if (ret_len < 0)
                break;

            send_len -= ret_len;
        }
    }

    epoll_ctl(epfd, EPOLL_CTL_DEL, az_socket_get_fd(session->data_fd), &ev);
    if (az_atomic_read(&session->abort) == AZ_TRUE && send_len > 0)
        ret = AZ_FTP_TRANSFER_ABOR;
    else if (send_len > 0)
        ret = AZ_FTP_LOCAL_ERR;
    else
        ret = AZ_FTP_TRANSFER_OK;
END:
    if (epfd >= 0)
        close(epfd);
    if (locked)
        _az_file_unlock(file_fd);
    if (file_fd >= 0)
        close(file_fd);
    if (session->data_fd != NULL)
        az_close_socket(&session->data_fd);
    az_ftp_response(session->cli_ctx, ret, NULL);
}

/*
void az_ftp_appeload_task(az_ftp_session session)
{
    int flag = 0;
    int ret = 0;
    int file_fd = -1;
    bool locked = false;
    int epfd = -1;
    uint8_t recv_data[2 * 1024 * 1024] = { 0 };
    struct epoll_event ev;
    struct epoll_event events[1];
    int recv_len = 0;

    if (session == NULL)
        return;

    file_fd = open(session->file_name, O_CREAT | O_WRONLY, 0644);
    if (file_fd < 0)
    {
        ret = AZ_FTP_FILE_BUSY;
        goto END;
    }
    _az_file_wlock(file_fd);
    locked = true;
    if (lseek(file_fd, 0, SEEK_END) < 0)
    {
        ret = AZ_FTP_FILE_ERR;
        goto END;
    }
    az_ftp_response(session->cli_ctx, AZ_FTP_FILE_OK, NULL);

    epfd = epoll_create(1);
    if (epfd < 0)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }
    session->data_fd = create_ftp_fd(session->mp, session->dtp_mode, &session->data_fd, session->dtp_ip, session->dtp_port);
    if (session->data_fd == NULL)
    {
        ret = AZ_FTP_DATACONN_ERR;
        goto END;
    }
    flag = az_socket_set_nonblock(session->data_fd, AZ_SOCKET_NONBLOCK);
    if (flag != AZ_OK)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }
    ev.data.fd = az_socket_get_fd(session->data_fd);  //设置要处理的事件类型
    ev.events = EPOLLIN | EPOLLET;
    flag = epoll_ctl(epfd, EPOLL_CTL_ADD, az_socket_get_fd(session->data_fd), &ev);
    if (flag != 0)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }
    //az_ftp_response(session->mp, session->reply_list, AZ_FTP_DATACONN_OK, NULL);

    while (az_atomic_read(&session->run) && az_atomic_read(&session->abort) == AZ_FALSE)
    {
        flag = epoll_wait(epfd, events, 1, 100);
        if (flag > 0 && events[0].data.fd == az_socket_get_fd(session->data_fd))
        {
            //这里需要修改成一直recv直到recv返回again
            recv_len = az_recv(session->data_fd, recv_data, 2 * 1024 * 1024, 0);
            if (recv_len == AZ_AGAIN)
                continue;
            else if (recv_len == AZ_ERROR)
            {
                ret = AZ_FTP_TRANSFER_ABOR;
                break;
            }
            else if (recv_len == 0)
            {
                ret = AZ_FTP_TRANSFER_OK;
                break;
            }

            flag = _az_file_write(file_fd, recv_data, recv_len);
            if (flag == AZ_ERROR)
            {
                ret = AZ_FTP_LOCAL_ERR;
                break;
            }
            else if (flag != recv_len)
            {
                ret = AZ_FTP_NO_SPACE;
                break;
            }
        }
    }

    epoll_ctl(epfd, EPOLL_CTL_DEL, az_socket_get_fd(session->data_fd), &ev);
    if (az_atomic_read(&session->abort) == AZ_TRUE)
        ret = AZ_FTP_TRANSFER_ABOR;
END:
    if (epfd >= 0)
        close(epfd);
    if (session->data_fd != NULL)
        az_close_socket(&session->data_fd);
    if (locked)
        _az_file_unlock(file_fd);
    if (file_fd >= 0)
        close(file_fd);
    az_ftp_response(session->cli_ctx, ret, NULL);
}
*/

void az_ftp_dtp_finish(az_ftp_session session)
{
    if (session == NULL)
        return;

    if (!session->cli_ctx->simplify)
        az_list_delnd(session->cli_ctx->session_list, (void **)&session);
    az_writelog(AZ_LOG_DEBUG, "session: dtp task end");
}

static void command_list(az_ftp_session session, bool ex)
{
    int flag = 0;
    int ret = 0;
    int len = 0;
    int epfd = -1;
    bool is_dir = true;
    struct epoll_event ev;
    struct epoll_event events[1];
    struct stat stat_info;
    int send_len = 0;
    char *send_data = NULL;

    if (stat(session->file_name, &stat_info) != 0)
    {
        ret = AZ_FTP_FILE_ERR;
        goto END;
    }
    if (!(S_IFDIR & stat_info.st_mode))
        is_dir = false;

    //list dir
    send_len = get_dir_info(session->cli_ctx->mp, session->file_name, is_dir, ex, &send_data);
    if (send_len == AZ_ERROR)
    {
        ret = AZ_FTP_FILE_BUSY;
        goto END;
    }
    az_writelog(AZ_LOG_DEBUG, "send dir info:\n%s", send_data);
    az_ftp_response(session->cli_ctx, AZ_FTP_FILE_OK, NULL);

    epfd = epoll_create(1);
    if (epfd < 0)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }
    session->data_fd = create_ftp_fd(session->cli_ctx->mp, session->dtp_mode, &session->data_fd, session->dtp_ip, session->dtp_port);
    if (session->data_fd == NULL)
    {
        ret = AZ_FTP_DATACONN_ERR;
        goto END;
    }
    flag = az_socket_set_nonblock(session->data_fd, AZ_SOCKET_NONBLOCK);
    if (flag != AZ_OK)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }
    ev.data.fd = az_socket_get_fd(session->data_fd);  //设置要处理的事件类型
    ev.events = EPOLLOUT;
    flag = epoll_ctl(epfd, EPOLL_CTL_ADD, az_socket_get_fd(session->data_fd), &ev);
    if (flag != 0)
    {
        ret = AZ_FTP_LOCAL_ERR;
        goto END;
    }

    //az_ftp_response(session->mp, session->reply_list, AZ_FTP_DATACONN_OK, NULL);
    while (az_atomic_read(&session->run) && az_atomic_read(&session->abort) == AZ_FALSE && len < send_len)
    {
        flag = epoll_wait(epfd, events, 1, 100);
        if (flag > 0 && events[0].data.fd == az_socket_get_fd(session->data_fd))
        {
            flag = az_send(session->data_fd, send_data + len, send_len - len, 0);
            if (flag == 0 || flag == AZ_ERROR)
                break;
            len += flag;
        }
    }

    epoll_ctl(epfd, EPOLL_CTL_DEL, az_socket_get_fd(session->data_fd), &ev);
    if (az_atomic_read(&session->abort) == AZ_TRUE && len < send_len)
        ret = AZ_FTP_TRANSFER_ABOR;
    else if (len < send_len)
        ret = AZ_FTP_LOCAL_ERR;
    else
        ret = AZ_FTP_TRANSFER_OK;
END:
    if (send_data != NULL)
        az_mpfree(session->cli_ctx->mp, (void **)&send_data);
    if (epfd >= 0)
        close(epfd);
    if (session->data_fd != NULL)
        az_close_socket(&session->data_fd);
    az_ftp_response(session->cli_ctx, ret, NULL);
}

static az_net create_ftp_fd(az_memp pool, az_ftp_dtp_mode dtp_mode, az_net *listen_fd, char *dtp_ip, int dtp_port)
{
    int flag = 0;
    az_net tmp = NULL;
    int epfd = -1;
    struct epoll_event ev;
    az_netinfo_ipv4_t netinfo;

    if (dtp_mode == DTP_ACTIVE_MODE)
    {
        az_writelog(AZ_LOG_DEBUG, "session: create active mode data fd");

        if (dtp_ip == NULL || *dtp_ip == '\0' || dtp_port < 0 || dtp_port > 65535)
            return NULL;

        tmp = az_create_socket(pool, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
        if (tmp == NULL)
        {
            az_writelog(AZ_LOG_ERROR, "session: create active socket failed");
            goto ERR;
        }

        flag = az_connect_socket(tmp, dtp_ip, dtp_port);
        if (flag != AZ_OK)
        {
            az_writelog(AZ_LOG_ERROR, "session: connect to [%s:%d] failed", dtp_ip, dtp_port);
            goto ERR;
        }
    }
    else
    {
        int count = 0;
        struct epoll_event events[1];

        if (*listen_fd == NULL)
            return NULL;
        az_writelog(AZ_LOG_DEBUG, "session: create pasv mode data fd");
        epfd = epoll_create(1);
        if (epfd < 0)
        {
            az_writelog(AZ_LOG_ERROR, "session: create epoll fd failed");
            goto ERR;
        }
        flag = az_socket_set_nonblock(*listen_fd, AZ_SOCKET_NONBLOCK);
        if (flag != AZ_OK)
        {
            az_writelog(AZ_LOG_ERROR, "session: set listen fd to no block failed");
            goto ERR;
        }

        ev.data.fd = az_socket_get_fd(*listen_fd);  //设置要处理的事件类型
        ev.events = EPOLLIN;
        flag = epoll_ctl(epfd, EPOLL_CTL_ADD, az_socket_get_fd(*listen_fd), &ev);
        if (flag != 0)
        {
            az_writelog(AZ_LOG_ERROR, "session: add epoll event failed");
            goto ERR;
        }

        while (1)
        {
            az_writelog(AZ_LOG_DEBUG, "session: listen fd waite for connect [%d]...", count);
            if (count >= 30)
                break;
            flag = epoll_wait(epfd, events, 1, 500);
            if (flag > 0 && events[0].data.fd == az_socket_get_fd(*listen_fd))
            {
                tmp = az_accept_socket(pool, *listen_fd);
                if (tmp == NULL)
                {
                    az_writelog(AZ_LOG_ERROR, "session: listen fd accept failed");
                    goto ERR;
                }
                break;
            }
            count++;
        }
        if (tmp == NULL)
            goto ERR;
        epoll_ctl(epfd, EPOLL_CTL_DEL, az_socket_get_fd(*listen_fd), &ev);
        close(epfd);
        az_close_socket(listen_fd);
    }

    az_socket_connect_info(tmp, NULL, &netinfo);
    az_writelog(AZ_LOG_DEBUG, "session: create data fd ok, [local-%s:%d remote-%s:%d]", netinfo.local_ip, netinfo.local_port, netinfo.remote_ip, netinfo.remote_port);

    return tmp;
ERR:
    if (epfd >= 0)
    {
        epoll_ctl(epfd, EPOLL_CTL_DEL, az_socket_get_fd(*listen_fd), &ev);
        close(epfd);
    }
    if (tmp != NULL)
        az_close_socket(&tmp);
    if (*listen_fd != NULL)
        az_close_socket(listen_fd);
    az_writelog(AZ_LOG_ERROR, "session: create active mode fd failed");
    return NULL;
}

static int get_dir_info(az_memp pool, char *path, bool is_dir, bool ex, char **data)
{
    int flag = 0;
    int send_len = 0;
    char *send_data = NULL;
    int data_len = 1024 * 10;
    struct stat stat_info;
    DIR *dir_ptr = NULL;
    struct dirent *direntp = NULL;

    send_data = az_mpcalloc(pool, data_len);
    if (send_data == NULL)
        return AZ_ERROR;

    if (is_dir)
    {
        dir_ptr = opendir(path);
        if (dir_ptr == NULL)
            goto ERR;

        while ((direntp = readdir(dir_ptr)) != NULL)
        {
            char tmp_dir[AZ_FTP_PATH_MAX_LEN] = { 0 };

            if (az_strcmp(direntp->d_name, ".") == 0)
                continue;

            if (ex)
            {
                az_strncpy(tmp_dir, AZ_FTP_PATH_MAX_LEN, path, az_strlen(path));
                az_strcatchr(tmp_dir, AZ_FTP_PATH_MAX_LEN, '/');
                az_strcatstr(tmp_dir, AZ_FTP_PATH_MAX_LEN, direntp->d_name);
                flag = stat(tmp_dir, &stat_info);
                if (flag != 0)
                    continue;

                flag = snfileinfo(NULL, 0, direntp->d_name, &stat_info);
                if ((data_len - send_len) - (flag + 1) < 0)
                {
                    char *tmp = NULL;
                    tmp = (char *)az_mprealloc(pool, (void **)&send_data, data_len + 1024 * 10);
                    if (tmp == NULL)
                        goto ERR;
                    send_data = tmp;
                    data_len += (1024 * 10);
                }
                send_len += snfileinfo(send_data + send_len, data_len - send_len, direntp->d_name, &stat_info);
            }
            else
            {
                flag = snprintf(NULL, 0, "%s\r\n", direntp->d_name);
                if ((data_len - send_len) - (flag + 1) < 0)
                {
                    char *tmp = NULL;
                    tmp = (char *)az_mprealloc(pool, (void **)&send_data, data_len + 1024 * 10);
                    if (tmp == NULL)
                        goto ERR;
                    send_data = tmp;
                    data_len += (1024 * 10);
                }
                send_len += snprintf(send_data + send_len, data_len - send_len, "%s\r\n", direntp->d_name);
            }
        }
        closedir(dir_ptr);
    }
    else
    {
        int loop = 0;

        flag = stat(path, &stat_info);
        if (flag != 0)
            goto ERR;

        for (loop = az_strlen(path) - 1; loop >= 0; loop--)
            if (path[loop] == '/')
                break;

        if (ex)
        {
            flag = snfileinfo(NULL, 0, &path[loop + 1], &stat_info);
            if (data_len < flag + 1)
            {
                char *tmp = NULL;
                tmp = (char *)az_mprealloc(pool, (void **)&send_data, flag + 1);
                if (tmp == NULL)
                    goto ERR;
                send_data = tmp;
                data_len = flag + 1;
            }
            send_len = snfileinfo(send_data, data_len, &path[loop + 1], &stat_info);
        }
        else
        {
            flag = snprintf(NULL, 0, "%s\r\n", &path[loop + 1]);
            if (data_len < flag + 1)
            {
                char *tmp = NULL;
                tmp = (char *)az_mprealloc(pool, (void **)&send_data, flag + 1);
                if (tmp == NULL)
                    goto ERR;
                send_data = tmp;
                data_len = flag + 1;
            }
            send_len = snprintf(send_data, data_len, "%s\r\n", &path[loop + 1]);
        }
    }

    *data = send_data;
    return send_len;
ERR:
    if (dir_ptr != NULL)
        closedir(dir_ptr);
    if (send_data != NULL)
        az_mpfree(pool, (void **)&send_data);
    return AZ_ERROR;
}

static int snfileinfo(char *buf, int buf_len, char *file_name, struct stat *info)
{
    int len = 0;

    if (file_name == NULL || *file_name == '\0' || info == NULL)
        return AZ_ERROR;

    len = snprintf(buf, buf_len, "----------");
    if (buf_len > 10)
    {
        switch (info->st_mode & S_IFMT)
        {
        case S_IFREG:
            buf[0] = '-';
            break;
        case S_IFDIR:
            buf[0] = 'd';
            break;
        case S_IFCHR:
            buf[0] = 'c';
            break;
        case S_IFLNK:
            buf[0] = 'l';
            break;
        case S_IFIFO:
            buf[0] = 'p';
            break;
        case S_IFSOCK:
            buf[0] = 's';
            break;
        case S_IFBLK:
            buf[0] = 'b';
            break;
        }

        if ((info->st_mode & S_IRUSR))
            buf[1] = 'r';
        if ((info->st_mode & S_IWUSR))
            buf[2] = 'w';
        if ((info->st_mode & S_IXUSR))
            buf[3] = 'x';
        if ((info->st_mode & S_IRGRP))
            buf[4] = 'r';
        if ((info->st_mode & S_IWGRP))
            buf[5] = 'w';
        if ((info->st_mode & S_IXGRP))
            buf[6] = 'x';
        if ((info->st_mode & S_IROTH))
            buf[7] = 'r';
        if ((info->st_mode & S_IWOTH))
            buf[8] = 'w';
        if ((info->st_mode & S_IXOTH))
            buf[9] = 'x';

        if (info->st_mode & S_ISUID)
            buf[3] = (buf[3] == 'x') ? 's' : 'S';
        if (info->st_mode & S_ISGID)
            buf[6] = (buf[6] == 'x') ? 's' : 'S';
        if (info->st_mode & S_ISVTX)
            buf[9] = (buf[9] == 'x') ? 't' : 'T';
    }

    if (buf == NULL || buf_len == 0)
    {
        //len += snprintf(NULL, 0, " %4d", (int)info->st_nlink);
        len += snprintf(NULL, 0, "%8s", uid_to_name(info->st_uid));
        len += snprintf(NULL, 0, "%8s", gid_to_name(info->st_uid));
        len += snprintf(NULL, 0, " %16ld", (long)info->st_size);
        len += snprintf(NULL, 0, " %.12s", 4 + ctime(&info->st_mtime));
        len += snprintf(NULL, 0, " %s\r\n", file_name);
    }
    else
    {
        //len += snprintf(buf + len, buf_len - len, " %4d", (int)info->st_nlink);
        len += snprintf(buf + len, buf_len - len, "%8s", uid_to_name(info->st_uid));
        len += snprintf(buf + len, buf_len - len, "%8s", gid_to_name(info->st_uid));
        len += snprintf(buf + len, buf_len - len, " %16ld", (long)info->st_size);
        len += snprintf(buf + len, buf_len - len, " %.12s", 4 + ctime(&info->st_mtime));
        len += snprintf(buf + len, buf_len - len, " %s\r\n", file_name);
    }

    return len;
}

static char* uid_to_name(uid_t uid)
{
    struct passwd *pw_ptr = NULL;

    pw_ptr = getpwuid(uid);
    if (pw_ptr == NULL)
        return NULL;
    return pw_ptr->pw_name;
}

static char* gid_to_name(gid_t gid)
{
    struct group *grp_ptr = NULL;

    grp_ptr = getgrgid(gid);
    if (grp_ptr == NULL)
        return NULL;
    return grp_ptr->gr_name;
}

static void _az_file_rlock(int fd)
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

static void _az_file_wlock(int fd)
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

static void _az_file_unlock(int fd)
{
    struct flock the_lock;
    Az_Memzero(&the_lock, sizeof(struct flock));
    the_lock.l_type = F_UNLCK;
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0;

    fcntl(fd, F_SETLK, &the_lock);
}

static int _az_file_write(int fd, uint8_t *data, int len)
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
