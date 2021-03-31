#include<azftp/az_ftp_server.h>
#include"az_ftp_include.h"
#include"az_ftp_server_pi.h"

struct az_ftp_server_s
{
    az_atomic_t run;
    az_memp mp;
    az_taskp tp;
    az_ftp_config_t cnf;

    az_net listen_fd;
    az_net def_dtp_fd;
    az_thread th_listen;
    //az_thread th_watch;
    int recv_epfd;
    int send_epfd;
    int listen_epfd;

    az_atomic_t client_num;
    az_list client_list;
};

typedef struct az_ftp_trans_ctx_s
{
    az_atomic_t run;
    az_memp mp;

    int recv_epfd;
    int send_epfd;

    az_atomic_t *client_num;
    az_list client_list;
}az_ftp_trans_ctx_t, *az_ftp_trans_ctx;

//static az_ftp_server server = NULL;

static int _az_ftp_server_listen_handle(void *data);
static int _az_ftp_server_recv_handle(void *data);
static int _az_ftp_server_send_handle(void *data);
static void _az_ftp_client(void *data);
static void _az_ftp_client_exit(void *data);

#define USE_AZ_CNF 1
az_ret az_ftp_load_cnf(char *path, az_ftp_config cnf)
{
#ifdef USE_AZ_CNF
    az_cnf cnf_parser = NULL;
    const char *val = NULL;
#else
    int flag = 0;
    char *bufflag = NULL;
    char line[CONFIG_LINE_SIZE] = { 0 };
    char key[CONFIG_KEY_LEN] = { 0 };
    char value[CONFIG_VALUE_LEN] = { 0 };
    FILE *fp = NULL;
#endif
    struct stat statbuf;

    if (path == NULL || *path == '\0' || cnf == NULL)
        return AZ_ERROR;

    Az_Memzero(cnf, sizeof(az_ftp_config_t));
    cnf->daemonize = false;
    cnf->simplify = false;
    cnf->max_client = 100;
    cnf->log_flag = false;
    cnf->log_cnf.level = AZ_LOG_ERROR;
    cnf->log_cnf.file_size = 12;
    cnf->log_cnf.max_log_num = 100000;
    cnf->log_cnf.merge_flag = true;
    cnf->log_cnf.display_flag = false;
    cnf->log_cnf.net_log = false;

#ifdef USE_AZ_CNF
    cnf_parser = az_cnf_parser(NULL, path, false);
    if (cnf_parser == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "parser conf file [%s] failed !", path);
        goto ERR;
    }
    
    val = az_cnf_get(cnf_parser, "ftp-server/bind-ip");
    if (val == NULL || (!az_check_ipv4(val) && !az_check_ipv6(val)))
        az_strncpy(cnf->listen_ip, AZ_IPV6_ADDRESS_STRING_LEN, "0.0.0.0", az_strlen("0.0.0.0"));
    else
        az_strncpy(cnf->listen_ip, AZ_IPV4_ADDRESS_STRING_LEN, val, az_strlen(val));

    val= az_cnf_get(cnf_parser, "ftp-server/bind-port");
    if (val == NULL || atoi(val) <= 0 || atoi(val) > 65535)
        cnf->listen_port = 21;
    else
        cnf->listen_port = atoi(val);

    val = az_cnf_get(cnf_parser, "ftp-server/base-dir");
    if (val == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Conf file don`t have 'base-dir'");
        goto ERR;
    }
    else
        az_strncpy(cnf->base_dir, AZ_FTP_PATH_MAX_LEN, val, az_strlen(val));
    if (cnf->base_dir[az_strlen(cnf->base_dir) - 1] == '/')
        cnf->base_dir[az_strlen(cnf->base_dir) - 1] = '\0';
    if (stat(cnf->base_dir, &statbuf) == 0 && !(S_IFDIR & statbuf.st_mode))
    {
        az_writelog(AZ_LOG_ERROR, "Config 'base-dir' is not a directory");
        goto ERR;
    }

    val = az_cnf_get(cnf_parser, "ftp-server/auth-dir");
    if (val == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Conf file don`t have 'auth-dir'");
        goto ERR;
    }
    else
        az_strncpy(cnf->auth_dir, AZ_FTP_PATH_MAX_LEN, val, az_strlen(val));
    if (stat(cnf->auth_dir, &statbuf) != 0 || !S_ISREG(statbuf.st_mode))
    {
        az_writelog(AZ_LOG_ERROR, "Config 'auth-dir' is not a file");
        goto ERR;
    }

    val = az_cnf_get(cnf_parser, "ftp-server/daemonize");
    if (val != NULL)
    {
        if (az_strcasecmp("YES", val) == 0)
            cnf->daemonize = true;
        else if (az_strcasecmp("NO", val) == 0)
            cnf->daemonize = false;
    }

    val = az_cnf_get(cnf_parser, "ftp-server/max-client-num");
    if (val != NULL && atoi(val) > 0)
        cnf->max_client = atoi(val);

    val = az_cnf_get(cnf_parser, "ftp-server/simplify");
    if (val != NULL)
    {
        if (az_strcasecmp("YES", val) == 0)
            cnf->simplify = true;
        else if (az_strcasecmp("NO", val) == 0)
            cnf->simplify = false;
    }

    val= az_cnf_get(cnf_parser, "ftp-log/log-path");
    if (val != NULL)
    {
        az_strncpy(cnf->log_cnf.log_path, AZ_LOG_PATH_LEN_MAX, val, az_strlen(val));
        val = az_cnf_get(cnf_parser, "ftp-log/log-level");
        if (val != NULL)
        {
            if (az_strcasecmp("ERROR", val) == 0)
                cnf->log_cnf.level = AZ_LOG_ERROR;
            else if (az_strcasecmp("INFO", val) == 0)
                cnf->log_cnf.level = AZ_LOG_INFO;
            else if (az_strcasecmp("DEBUG", val) == 0)
                cnf->log_cnf.level = AZ_LOG_DEBUG;
            else
                cnf->log_cnf.level = AZ_LOG_ERROR;
        }
        val = az_cnf_get(cnf_parser, "ftp-log/log-max-filesize");
        if (val != NULL)
        {
            if (az_strschr(val, 'K', false) != NULL || az_strschr(val, 'k', false) != NULL)
                cnf->log_cnf.file_size = atol(val) / 1024;
            else if (az_strschr(val, 'M', false) != NULL || az_strschr(val, 'm', false) != NULL)
                cnf->log_cnf.file_size = atol(val);
            else if (az_strschr(val, 'G', false) != NULL || az_strschr(val, 'g', false) != NULL)
                cnf->log_cnf.file_size = atol(val) * 1024;
            else
                cnf->log_cnf.file_size = atol(val);
        }
        if (cnf->log_cnf.file_size < 12)
            cnf->log_cnf.file_size = 12;
        val = az_cnf_get(cnf_parser, "ftp-log/log-max-entry");
        if(val!=NULL)
            cnf->log_cnf.max_log_num = atoi(val);
        if (cnf->log_cnf.max_log_num <= 1000)
            cnf->log_cnf.max_log_num = 1001;
        val = az_cnf_get(cnf_parser, "ftp-log/log-merge-flag");
        if (val != NULL)
        {
            if (az_strcasecmp("YES", val) == 0)
                cnf->log_cnf.merge_flag = true;
            else if (az_strcasecmp("NO", val) == 0)
                cnf->log_cnf.merge_flag = false;
            else
                cnf->log_cnf.merge_flag = true;
        }
        val = az_cnf_get(cnf_parser, "ftp-log/log-display");
        if (val != NULL)
        {
            if (az_strcasecmp("YES", val) == 0)
                cnf->log_cnf.display_flag = true;
            else if (az_strcasecmp("NO", val) == 0)
                cnf->log_cnf.display_flag = false;
            else
                cnf->log_cnf.display_flag = false;
        }
        val = az_cnf_get(cnf_parser, "ftp-log/net-log");
        if (val != NULL)
        {
            if (az_strcasecmp("YES", val) == 0)
                cnf->log_cnf.net_log = true;
            else if (az_strcasecmp("NO", val) == 0)
                cnf->log_cnf.net_log = false;
            else
                cnf->log_cnf.net_log = false;
        }
        if (cnf->log_cnf.net_log)
        {
            val = az_cnf_get(cnf_parser, "ftp-log/log-bind");
            if (val != NULL && (az_check_ipv4(val) || az_check_ipv6(val)))
                az_strncpy(cnf->log_cnf.bind_ip, AZ_IPV6_ADDRESS_STRING_LEN, val, az_strlen(val));
            else
                az_strncpy(cnf->log_cnf.bind_ip, AZ_IPV6_ADDRESS_STRING_LEN, "127.0.0.1", az_strlen("127.0.0.1"));
            val = az_cnf_get(cnf_parser, "ftp-log/log-port");
            if (val != NULL&&atoi(val) > 0 && atoi(val) < 65535)
                cnf->log_cnf.bind_port = atoi(val);
            else
                cnf->log_cnf.bind_port = 20205;
            val = az_cnf_get(cnf_parser, "ftp-log/log-client-num");
            if (val != NULL && atoi(val) > 0 && atoi(val) < 10)
                cnf->log_cnf.max_client_num = atoi(val);
            else
                cnf->log_cnf.max_client_num = 3;
        }
    }
    if (cnf->daemonize)
        cnf->log_cnf.display_flag = false;

    az_cnf_free(&cnf_parser);
    return AZ_OK;
ERR:
    if (cnf_parser != NULL)
        az_cnf_free(&cnf_parser);
    return AZ_ERROR;
#else
    fp = fopen(path, "r");
    if (fp == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Conf file [%s] open failed !", path);
        goto ERR;
    }

    while (!feof(fp))
    {
        Az_Memzero(line, CONFIG_LINE_SIZE);
        bufflag = fgets(line, CONFIG_LINE_SIZE, fp);
        if (bufflag != NULL&&*bufflag != '#')
        {
            Az_Memzero(key, CONFIG_KEY_LEN);
            sscanf(line, "%[^'\r'|'\n'|'\t'|#]", key);
            flag = az_strcasecmp(key, "[ftp-server]");
            if (flag == 0)
                break;
        }
    }
    if (feof(fp) == 0)
    {
        while (!feof(fp))
        {
            Az_Memzero(line, CONFIG_LINE_SIZE);
            bufflag = fgets(line, CONFIG_LINE_SIZE, fp);
            //az_writelog(AZ_LOG_DEBUG, "line :%s", line);
            if (bufflag != NULL&&*bufflag != '#')
            {
                if (*bufflag == '[')
                    break;

                Az_Memzero(key, CONFIG_KEY_LEN);
                Az_Memzero(value, CONFIG_VALUE_LEN);
                sscanf(line, "%[^=| |'\t']%*[^0-9A-Za-z|'/'|'~'|'.']%[^'\r'|'\n'| |'\t'|#]", key, value);
                //az_writelog(AZ_LOG_DEBUG, "key :%s  --  value :%s", key, value);
                if (az_strcmp(key, "bind-ip") == 0)
                    az_strncpy(cnf->listen_ip, AZ_IPV4_ADDRESS_STRING_LEN, value, az_strlen(value));
                else if (az_strcmp(key, "bind-port") == 0)
                    cnf->listen_port = atoi(value);
                else if (az_strcmp(key, "base-dir") == 0)
                    az_strncpy(cnf->base_dir, AZ_FTP_PATH_MAX_LEN, value, az_strlen(value));
                else if (az_strcmp(key, "auth-dir") == 0)
                    az_strncpy(cnf->auth_dir, AZ_FTP_PATH_MAX_LEN, value, az_strlen(value));
                else if (az_strcmp(key, "daemonize") == 0)
                {
                    if (az_strcasecmp("YES", value) == 0)
                        cnf->daemonize = true;
                    else if (az_strcasecmp("NO", value) == 0)
                        cnf->daemonize = false;
                }
                else if (az_strcmp(key, "max-client-num") == 0)
                    cnf->max_client = atoi(value);
                else if (az_strcmp(key, "simplify") == 0)
                {
                    if (az_strcasecmp("YES", value) == 0)
                        cnf->simplify = true;
                    else if (az_strcasecmp("NO", value) == 0)
                        cnf->simplify = false;
                }
            }
        }
        if (*cnf->listen_ip == '\0')
            az_strncpy(cnf->listen_ip, AZ_IPV6_ADDRESS_STRING_LEN, "0.0.0.0", az_strlen("0.0.0.0"));
        if (cnf->listen_port <= 0 || cnf->listen_port > 65535)
            cnf->listen_port = 21;
        if (*cnf->base_dir == '\0')
        {
            az_writelog(AZ_LOG_ERROR, "Conf file don`t have 'base-dir'");
            goto ERR;
        }
        if (cnf->base_dir[az_strlen(cnf->base_dir) - 1] == '/')
            cnf->base_dir[az_strlen(cnf->base_dir) - 1] = '\0';
        if (stat(cnf->base_dir, &statbuf) == 0 && !(S_IFDIR & statbuf.st_mode))
        {
            az_writelog(AZ_LOG_ERROR, "Config 'base-dir' is not a directory");
            goto ERR;
        }
        if (*cnf->auth_dir == '\0')
        {
            az_writelog(AZ_LOG_ERROR, "Conf file don`t have 'auth-dir'");
            goto ERR;
        }
        if (stat(cnf->auth_dir, &statbuf) != 0 || !S_ISREG(statbuf.st_mode))
        {
            az_writelog(AZ_LOG_ERROR, "Config 'auth-dir' is not a file");
            goto ERR;
        }
    }
    else
    {
        az_writelog(AZ_LOG_ERROR, "Conf file not find '[ftp-server]' ");
        goto ERR;
    }
    flag = fseek(fp, 0, SEEK_SET);
    if (flag != 0)
    {
        az_writelog(AZ_LOG_ERROR, "Paser conf file failed");
        goto ERR;
    }

    while (!feof(fp))
    {
        Az_Memzero(line, CONFIG_LINE_SIZE);
        bufflag = fgets(line, CONFIG_LINE_SIZE, fp);
        if (bufflag != NULL&&*bufflag != '#')
        {
            Az_Memzero(key, CONFIG_KEY_LEN);
            sscanf(line, "%[^'\r'|'\n'|'\t'|#]", key);
            flag = az_strcasecmp(key, "[ftp-log]");
            if (flag == 0)
                break;
        }
    }
    if (feof(fp) == 0)
    {
        while (!feof(fp))
        {
            Az_Memzero(line, CONFIG_LINE_SIZE);
            bufflag = fgets(line, CONFIG_LINE_SIZE, fp);
            if (bufflag != NULL&&*bufflag != '#')
            {
                if (*bufflag == '[')
                    break;
                Az_Memzero(key, CONFIG_KEY_LEN);
                Az_Memzero(value, CONFIG_VALUE_LEN);
                sscanf(line, "%[^=| |'\t']%*[^0-9A-Za-z|'/'|'~'|'.']%[^'\r'|'\n'| |'\t'|#]", key, value);

                if (az_strcmp(key, "log-path") == 0)
                    az_strncpy(cnf->log_cnf.log_path, AZ_LOG_PATH_LEN_MAX, value, az_strlen(value));
                else if (az_strcmp(key, "log-level") == 0)
                {
                    if (az_strcasecmp("ERROR", value) == 0)
                        cnf->log_cnf.level = AZ_LOG_ERROR;
                    else if (az_strcasecmp("INFO", value) == 0)
                        cnf->log_cnf.level = AZ_LOG_INFO;
                    else if (az_strcasecmp("DEBUG", value) == 0)
                        cnf->log_cnf.level = AZ_LOG_DEBUG;
                    else
                        cnf->log_cnf.level = AZ_LOG_ERROR;
                }
                else if (az_strcmp(key, "log-max-filesize") == 0)
                {
                    if (az_strschr(value, 'K', false) != NULL || az_strschr(value, 'k', false) != NULL)
                        cnf->log_cnf.file_size = atol(value) / 1024;
                    else if (az_strschr(value, 'M', false) != NULL || az_strschr(value, 'm', false) != NULL)
                        cnf->log_cnf.file_size = atol(value);
                    else if (az_strschr(value, 'G', false) != NULL || az_strschr(value, 'g', false) != NULL)
                        cnf->log_cnf.file_size = atol(value) * 1024;
                    else
                        cnf->log_cnf.file_size = atol(value);
                }
                else if (az_strcmp(key, "log-max-entry") == 0)
                    cnf->log_cnf.max_log_num = atoi(value);
                else if (az_strcmp(key, "log-merge-flag") == 0)
                {
                    if (az_strcasecmp("YES", value) == 0)
                        cnf->log_cnf.merge_flag = true;
                    else if (az_strcasecmp("NO", value) == 0)
                        cnf->log_cnf.merge_flag = false;
                    else
                        cnf->log_cnf.merge_flag = true;
                }
                else if (az_strcmp(key, "log-display") == 0)
                {
                    if (az_strcasecmp("YES", value) == 0)
                        cnf->log_cnf.display_flag = true;
                    else if (az_strcasecmp("NO", value) == 0)
                        cnf->log_cnf.display_flag = false;
                    else
                        cnf->log_cnf.display_flag = false;
                }
                else if (az_strcmp(key, "net-log") == 0)
                {
                    if (az_strcasecmp("YES", value) == 0)
                        cnf->log_cnf.net_log = true;
                    else if (az_strcasecmp("NO", value) == 0)
                        cnf->log_cnf.net_log = false;
                    else
                        cnf->log_cnf.net_log = false;
                }
                else if (az_strcmp(key, "log-bind") == 0)
                    az_strncpy(cnf->log_cnf.bind_ip, AZ_IPV6_ADDRESS_STRING_LEN, value, az_strlen(value));
                else if (az_strcmp(key, "log-port") == 0)
                    cnf->log_cnf.bind_port = atoi(value);
                else if (az_strcmp(key, "log-client-num") == 0)
                    cnf->log_cnf.max_client_num = atoi(value);
            }
        }

        if (*cnf->log_cnf.log_path != '\0')
            cnf->log_flag = true;
        if (cnf->log_cnf.file_size < 12)
            cnf->log_cnf.file_size = 12;
        if (cnf->log_cnf.max_log_num <= 1000)
            cnf->log_cnf.max_log_num = 1001;
        if (cnf->log_flag && cnf->log_cnf.net_log)
        {
            if (az_check_ipv4(cnf->log_cnf.bind_ip) != 0)
                az_strncpy(cnf->log_cnf.bind_ip, AZ_IPV6_ADDRESS_STRING_LEN, "127.0.0.1", az_strlen("127.0.0.1"));
            if (cnf->log_cnf.bind_port <= 0 || cnf->log_cnf.bind_port > 65535)
                cnf->log_cnf.bind_port = 20205;
        }
    }

    if (cnf->daemonize)
        cnf->log_cnf.display_flag = false;

    fclose(fp);
    return AZ_OK;
ERR:
    if (fp != NULL)
        fclose(fp);
    return AZ_ERROR;
#endif
}

az_ftp_server az_ftp_server_init(az_ftp_config cnf)
{
    int flag = 0;
    az_memp mp = NULL;
    az_ftp_server tmp = NULL;

    if (cnf == NULL)
        return NULL;

    if (cnf->log_flag)
    {
        flag = az_log_init(&cnf->log_cnf);
        if (flag != AZ_OK)
        {
            az_writelog(AZ_LOG_ERROR, "Az FTP: azlog init failed");
            goto ERR;
        }
        az_writelog(AZ_LOG_INFO, "Az FTP: enabled azlog recode");
    }
    else
        az_writelog(AZ_LOG_INFO, "Az FTP: disabled azlog recode");

    if (cnf->listen_port <= 1024 && getuid() != 0)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: must be started as root");
        return NULL;
    }

    mp = az_memp_create(AZ_MEM_POOL_DEFAULT_SIZE, true);
    if (mp == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: create memory pool failed");
        goto ERR;
    }

    if (cnf->daemonize == true)
        daemon(0, 0);

    tmp = (az_ftp_server)az_mpcalloc(mp, sizeof(az_ftp_server_t));
    if (tmp == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: alloc server ctx memory [size:%lu] failed", sizeof(az_ftp_server_t));
        goto ERR;
    }
    tmp->mp = mp;
    Az_Memcpy(&tmp->cnf, cnf, sizeof(az_ftp_config_t));
    az_atomic_set(&tmp->run, AZ_FALSE);
    az_atomic_set(&tmp->client_num, 0);
    tmp->recv_epfd = -1;
    tmp->send_epfd = -1;

#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(tmp->cnf.base_dir, _A_NORMAL);
#else
    flag = access(tmp->cnf.base_dir, F_OK);
#endif
    if (flag != 0)
    {
        flag = az_mkloop_dir(tmp->cnf.base_dir);
        if (flag != AZ_OK)
        {
            az_writelog(AZ_LOG_ERROR, "Az FTP: create base dir [%s] failed", tmp->cnf.base_dir);
            goto ERR;
        }
    }

    tmp->client_list = az_list_init(AZ_DEF_LIST, 0, sizeof(az_ftp_client_t), tmp->cnf.max_client, true);
    if (tmp->client_list == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: create client list failed");
        goto ERR;
    }

    tmp->tp = az_taskp_create(1, tmp->cnf.max_client, 0, 0);
    if (tmp->tp == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: create task pool failed");
        goto ERR;
    }

    if (!tmp->cnf.simplify)
    {
        tmp->recv_epfd = epoll_create(tmp->cnf.max_client);
        if (tmp->recv_epfd < 0)
        {
            az_writelog(AZ_LOG_ERROR, "Az FTP: recv epoll fd create error!");
            goto ERR;
        }
        tmp->send_epfd = epoll_create(1);
        if (tmp->send_epfd < 0)
        {
            az_writelog(AZ_LOG_ERROR, "Az FTP: recv epoll fd create error!");
            goto ERR;
        }
    }
    tmp->listen_epfd = epoll_create(100);
    if (tmp->listen_epfd < 0)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: recv epoll fd create error!");
        goto ERR;
    }

    tmp->listen_fd = az_create_socket(tmp->mp, AZ_NET_IPV4, AZ_TCP_SOCKET, 0);
    if (tmp->listen_fd == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: create server listen socket failed");
        goto ERR;
    }
    //az_socket_set_reuseaddr(tmp->listen_fd, AZ_SOCKET_REUSE_ON);
    flag = az_bind_socket(tmp->listen_fd, tmp->cnf.listen_ip, tmp->cnf.listen_port);
    if (flag != AZ_OK)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: bind server listen socket failed [%s:%d]", tmp->cnf.listen_ip, tmp->cnf.listen_port);
        goto ERR;
    }
    flag = az_listen_socket(tmp->listen_fd, tmp->cnf.max_client);
    if (flag != AZ_OK)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: listen server listen socket failed");
        goto ERR;
    }
    flag = az_socket_set_nonblock(tmp->listen_fd, AZ_SOCKET_NONBLOCK);
    if (flag != AZ_OK)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: listen server listen socket failed");
        goto ERR;
    }

    return tmp;
ERR:
    if (tmp != NULL)
    {
        if (tmp->listen_fd)
            az_close_socket(&tmp->listen_fd);
        if (!tmp->cnf.simplify)
        {
            if (tmp->recv_epfd >= 0)
                close(tmp->recv_epfd);
            if (tmp->send_epfd >= 0)
                close(tmp->send_epfd);
        }
        if (tmp->listen_epfd >= 0)
            close(tmp->listen_epfd);
        if (tmp->tp != NULL)
            az_taskp_destory(&tmp->tp);
        if (tmp->client_list != NULL)
            az_list_destory(&tmp->client_list);
    }
    if (mp != NULL)
        az_memp_destory(mp);
    return NULL;
}

az_ret az_ftp_server_run(az_ftp_server ctx)
{
    if (ctx == NULL)
        return AZ_ERROR;

    az_writelog(AZ_LOG_INFO, "******************** AZ ftp conf ********************");
    az_writelog(AZ_LOG_INFO, "**  bind-ip: %s", ctx->cnf.listen_ip);
    az_writelog(AZ_LOG_INFO, "**  bind-port: %d", ctx->cnf.listen_port);
    az_writelog(AZ_LOG_INFO, "**  base-dir: %s", ctx->cnf.base_dir);
    az_writelog(AZ_LOG_INFO, "**  max-client-num: %d", ctx->cnf.max_client);
    if (ctx->cnf.daemonize)
        az_writelog(AZ_LOG_INFO, "**  daemonize: yes");
    else
        az_writelog(AZ_LOG_INFO, "**  daemonize: no");
    if (ctx->cnf.log_flag)
    {
        az_writelog(AZ_LOG_INFO, "**  enable-log: yes");
        az_writelog(AZ_LOG_INFO, "**  log-path: %s", ctx->cnf.log_cnf.log_path);
    }
    else
        az_writelog(AZ_LOG_INFO, "**  enable-log: no");
    az_writelog(AZ_LOG_INFO, "******************************************************");

    chdir(ctx->cnf.base_dir);
    az_atomic_set(&ctx->run, AZ_TRUE);
    ctx->th_listen = az_create_thread(ctx->mp, "azftp-listen", 0, false, true, _az_ftp_server_listen_handle, (void *)ctx);
    if (ctx->th_listen == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "Az FTP: create listen thread failed");
        goto ERR;
    }

    return AZ_OK;
ERR:
    az_atomic_set(&ctx->run, AZ_FALSE);
    return AZ_ERROR;
}

bool az_ftp_server_stat(az_ftp_server ctx)
{
    if (ctx == NULL)
        return false;

    if (az_atomic_read(&ctx->run) == AZ_TRUE)
        return true;
    return false;
}

void az_ftp_server_destory(az_ftp_server *ctx)
{
    //int flag = 0;
    //az_ftp_client cli_ctx = NULL;

    if (*ctx == NULL)
        return;

    az_atomic_set(&(*ctx)->run, AZ_FALSE);
    if ((*ctx)->th_listen)
        az_waite_thread(&(*ctx)->th_listen);
    az_taskp_destory(&(*ctx)->tp);
    if (!(*ctx)->cnf.simplify)
    {
        close((*ctx)->recv_epfd);
        close((*ctx)->send_epfd);
    }
    close((*ctx)->listen_epfd);
    az_close_socket(&(*ctx)->listen_fd);
    az_list_destory(&(*ctx)->client_list);
    az_memp_destory((*ctx)->mp);
    (*ctx) = NULL;
}

az_ret az_ftp_server_set_unsupcmd(az_ftp_server ctx, az_ftp_cmd cmd_type)
{
    if (ctx == NULL)
        return AZ_ERROR;
    if (az_atomic_read(&ctx->run) == AZ_TRUE)
        return AZ_ERROR;
    return az_ftp_set_uncmd(cmd_type);
}

az_ret az_ftp_server_set_callback(az_ftp_server ctx, az_ftp_cmd cmd_type, cmd_cb cb)
{
    if (ctx == NULL || cb == NULL)
        return AZ_ERROR;
    if (az_atomic_read(&ctx->run) == AZ_TRUE)
        return AZ_ERROR;
    return az_ftp_set_cmdcb(cmd_type, cb);
}

static int _az_ftp_server_listen_handle(void *data)
{
    int flag = 0;
    int num = 0;
    int loop = 0;
    az_ftp_server ser_ctx = NULL;
    az_thread th_recv = NULL;
    az_thread th_send = NULL;
    struct epoll_event ev;
    struct epoll_event events[100];
    az_ftp_client cli_ctx = NULL;
    az_task_info_t cli_task = { 0 };
    az_ftp_trans_ctx_t trans_ctx;

    if (data == NULL)
        return AZ_ERROR;
    ser_ctx = (az_ftp_server)data;
    Az_Memzero(&trans_ctx, sizeof(az_ftp_trans_ctx_t));

    ev.data.fd = az_socket_get_fd(ser_ctx->listen_fd);  //设置要处理的事件类型
    ev.events = EPOLLIN;
    flag = epoll_ctl(ser_ctx->listen_epfd, EPOLL_CTL_ADD, az_socket_get_fd(ser_ctx->listen_fd), &ev);
    if (flag != 0)
    {
        az_writelog(AZ_LOG_ERROR, "FTP listen: listen fd add epoll event error!");
        az_atomic_set(&ser_ctx->run, AZ_FALSE);
        return AZ_ERROR;
    }

    if (!ser_ctx->cnf.simplify)
    {
        trans_ctx.mp = ser_ctx->mp;
        trans_ctx.recv_epfd = ser_ctx->recv_epfd;
        trans_ctx.send_epfd = ser_ctx->send_epfd;
        trans_ctx.client_list = ser_ctx->client_list;
        trans_ctx.client_num = &ser_ctx->client_num;
        az_atomic_set(&trans_ctx.run, AZ_TRUE);

        th_recv = az_create_thread(ser_ctx->mp, "azftp-recv", 0, false, true, _az_ftp_server_recv_handle, &trans_ctx);
        if (th_recv == NULL)
        {
            az_writelog(AZ_LOG_ERROR, "Az FTP: create recv thread failed");
            goto ERR;
        }
        th_send = az_create_thread(ser_ctx->mp, "azftp-send", 0, false, true, _az_ftp_server_send_handle, &trans_ctx);
        if (th_send == NULL)
        {
            az_writelog(AZ_LOG_ERROR, "Az FTP: create send thread failed");
            goto ERR;
        }
    }

    az_writelog(AZ_LOG_DEBUG, "Az ftp: server start wait for client connect ...");
    while (az_atomic_read(&ser_ctx->run))
    {
        num = epoll_wait(ser_ctx->listen_epfd, events, 100, 500);
        if (num > 0)
        {
            for (loop = 0; loop < num; loop++)
            {
                if (events[loop].data.fd == az_socket_get_fd(ser_ctx->listen_fd))
                {
                    az_net cli_fd = NULL;

                    cli_fd = az_accept_socket(ser_ctx->mp, ser_ctx->listen_fd);
                    if (cli_fd == NULL)
                    {
                        az_writelog(AZ_LOG_ERROR, "Az ftp: server accept client failed");
                        continue;
                    }
                    if (az_atomic_read(&ser_ctx->client_num) >= ser_ctx->cnf.max_client)
                    {
                        az_close_socket(&cli_fd);
                        az_writelog(AZ_LOG_INFO, "Az ftp: server client num is max");
                        continue;
                    }

                    if (cli_ctx == NULL)
                        cli_ctx = (az_ftp_client)az_list_allocnd(ser_ctx->client_list, sizeof(az_ftp_client_t));
                    if (cli_ctx == NULL)
                    {
                        az_close_socket(&cli_fd);
                        az_writelog(AZ_LOG_ERROR, "Az ftp: server alloc client ctx node failed");
                        continue;
                    }
                    az_socket_set_nonblock(cli_fd, AZ_SOCKET_NONBLOCK);

                    cli_ctx->client_fd = cli_fd;
                    cli_ctx->ser_ctx = ser_ctx;
                    cli_ctx->ser_recv_epfd = ser_ctx->recv_epfd;
                    az_socket_connect_info(cli_ctx->client_fd, NULL, &cli_ctx->netinfo);
                    az_strncpy(cli_ctx->home_dir, AZ_FTP_PATH_MAX_LEN, ser_ctx->cnf.base_dir, az_strlen(ser_ctx->cnf.base_dir));
                    az_strncpy(cli_ctx->auth_dir, AZ_FTP_PATH_MAX_LEN, ser_ctx->cnf.auth_dir, az_strlen(ser_ctx->cnf.auth_dir));
                    cli_ctx->dtp_mode = DTP_ACTIVE_MODE;
                    az_strncpy(cli_ctx->dtp_ip, AZ_IPV6_ADDRESS_STRING_LEN, cli_ctx->netinfo.remote_ip, az_strlen(cli_ctx->netinfo.remote_ip));
                    cli_ctx->dtp_port = cli_ctx->netinfo.remote_port - 1;
                    cli_ctx->rename = false;
                    cli_ctx->restart = false;
                    cli_ctx->simplify = ser_ctx->cnf.simplify;
                    az_atomic_set(&cli_ctx->s_id, 0);
                    cli_ctx->mp = az_memp_create(AZ_MEM_POOL_DEFAULT_SIZE, true);
                    if (cli_ctx->mp == NULL)
                        goto NEXT;
                    if (ser_ctx->cnf.simplify)
                    {
                        cli_ctx->tp = NULL;
                        cli_ctx->cmd_list = NULL;
                        cli_ctx->reply_list = NULL;
                        cli_ctx->session_list = NULL;
                    }
                    else
                    {
                        cli_ctx->tp = az_taskp_create(1, 5, 0, 0);
                        if (cli_ctx->tp == NULL)
                            goto NEXT;
                        cli_ctx->cmd_list = az_list_init(AZ_DEF_QUEUE_LIST, 0, sizeof(az_ftp_msg), 5, true);
                        if (cli_ctx->cmd_list == NULL)
                            goto NEXT;
                        cli_ctx->reply_list = az_list_init(AZ_DEF_QUEUE_LIST, 0, sizeof(az_ftp_msg), 5, true);
                        if (cli_ctx->reply_list == NULL)
                            goto NEXT;
                        cli_ctx->session_list = az_list_init(AZ_DEF_LIST, 0, sizeof(az_ftp_session_t), 5, true);
                        if (cli_ctx->session_list == NULL)
                            goto NEXT;
                    }

                    az_atomic_set(&cli_ctx->stat, AZ_FTP_CLIENT_RUN);
                    cli_task.level = TASK_LEVEL_0;
                    cli_task.func = (az_task_hd)_az_ftp_client;
                    cli_task.finish_cb = (az_task_hd)_az_ftp_client_exit;
                    cli_task.param = cli_ctx;
                    cli_task.data_len = 0;
                    if (az_tpadd(ser_ctx->tp, &cli_task) == AZ_ERROR)
                        goto NEXT;

                    az_atomic_inc(&ser_ctx->client_num);
                    az_list_insertnd(ser_ctx->client_list, AZ_LIST_TAIL, az_socket_get_fd(cli_ctx->client_fd), cli_ctx);
                    az_writelog(AZ_LOG_DEBUG, "Az ftp: client [%s:%d] is connected OK", cli_ctx->netinfo.remote_ip, cli_ctx->netinfo.remote_port);
                    cli_ctx = NULL;
                NEXT:
                    if (cli_ctx != NULL)
                    {
                        if (cli_ctx->client_fd != NULL)
                            az_close_socket(&cli_fd);
                        if (cli_ctx->mp != NULL)
                            az_memp_destory(cli_ctx->mp);
                        if (cli_ctx->tp != NULL)
                            az_taskp_destory(&cli_ctx->tp);
                        if (cli_ctx->cmd_list != NULL)
                            az_list_destory(&cli_ctx->cmd_list);
                        if (cli_ctx->reply_list != NULL)
                            az_list_destory(&cli_ctx->reply_list);
                        if (cli_ctx->session_list != NULL)
                            az_list_destory(&cli_ctx->session_list);
                        az_writelog(AZ_LOG_ERROR, "Az ftp: server create client failed");
                    }
                }
            }
        }
    }
    epoll_ctl(ser_ctx->listen_epfd, EPOLL_CTL_DEL, az_socket_get_fd(ser_ctx->listen_fd), &ev);

    az_writelog(AZ_LOG_DEBUG, "Az ftp: server end ...");
    //停止所有client
    if (az_atomic_read(&ser_ctx->client_num) > 0)
    {
        flag = az_list_ergodic_start(ser_ctx->client_list, AZ_LIST_HEAD);
        if (flag == AZ_OK)
        {
            for (cli_ctx = az_list_ergodic_getnd(ser_ctx->client_list, NULL); cli_ctx != NULL; cli_ctx = az_list_ergodic_getnd(ser_ctx->client_list, NULL))
                az_atomic_set(&cli_ctx->stat, AZ_FTP_CLIENT_SERCLOSE);

            az_list_ergodic_end(ser_ctx->client_list);
        }
    }
    while (az_atomic_read(&ser_ctx->client_num) > 0)
        az_msleep(10);

    az_atomic_set(&trans_ctx.run, AZ_FALSE);
    if (!ser_ctx->cnf.simplify)
    {
        az_waite_thread(&th_recv);
        az_waite_thread(&th_send);
    }
    az_writelog(AZ_LOG_DEBUG, "Az ftp: server end OK");

    return AZ_OK;
ERR:
    epoll_ctl(ser_ctx->listen_epfd, EPOLL_CTL_DEL, az_socket_get_fd(ser_ctx->listen_fd), &ev);
    az_atomic_set(&ser_ctx->run, AZ_FALSE);
    az_atomic_set(&trans_ctx.run, AZ_FALSE);
    if (!ser_ctx->cnf.simplify)
    {
        if (th_recv)
            az_waite_thread(&th_recv);
        if (th_send)
            az_waite_thread(&th_send);
    }
    return AZ_ERROR;
}

static int _az_ftp_server_recv_handle(void *data)
{
    int flag = 0;
    int num = 0;
    int loop = 0;
    int ev_count = 0;
    int last_count = 0;
    int recv_len = 0;
    //struct epoll_event ev;
    struct epoll_event *events = NULL;
    az_ftp_client cli_ctx = NULL;
    az_ftp_msg cmd = NULL;
    az_ftp_trans_ctx ctx = NULL;

    if (data == NULL)
        return AZ_ERROR;
    ctx = (az_ftp_trans_ctx)data;

    az_writelog(AZ_LOG_DEBUG, "Az ftp: recv thread start run ...");
    while (az_atomic_read(&ctx->run))
    {
        last_count = ev_count;
        ev_count = az_atomic_read(ctx->client_num);
        if (ev_count > 0)
        {
            if (events == NULL)
            {
                events = (struct epoll_event *)az_mpcalloc(ctx->mp, sizeof(struct epoll_event)*ev_count);
                if (events == NULL)
                {
                    az_writelog(AZ_LOG_ERROR, "ftp recv hand: alloc epoll events memory [size:%lu] failed", sizeof(struct epoll_event)*ev_count);
                    continue;
                }
            }
            else
            {
                struct epoll_event *tmp = NULL;

                tmp = (struct epoll_event *)az_mprealloc(ctx->mp, (void **)&events, sizeof(struct epoll_event)*ev_count);
                if (tmp == NULL)
                {
                    az_writelog(AZ_LOG_ERROR, "ftp recv hand: realloc epoll events memory [size:%lu] failed", sizeof(struct epoll_event)*ev_count);
                    ev_count = last_count;
                }
                else
                    events = tmp;
            }

            num = epoll_wait(ctx->recv_epfd, events, ev_count, 500);
            if (num <= 0)
                continue;
            for (loop = 0; loop < num; loop++)
            {
                cli_ctx = az_list_findnd(ctx->client_list, AZ_LIST_HEAD, events[loop].data.fd);
                if ((events[loop].events&EPOLLIN) && cli_ctx)
                {
                    do
                    {
                        recv_len = az_recv(cli_ctx->client_fd, cli_ctx->recv_buf + cli_ctx->data_len, 2 * 1024 * 1024 - cli_ctx->data_len, 0);
                        if (recv_len == AZ_ERROR)
                        {
                            az_atomic_set(&cli_ctx->stat, AZ_FTP_CLIENT_LINKERR);
                            az_writelog(AZ_LOG_ERROR, "Az ftp: client [%s:%d] ctrl link recv err", cli_ctx->netinfo.remote_ip, cli_ctx->netinfo.remote_port);
                        }
                        else if (recv_len == 0)
                        {
                            az_atomic_set(&cli_ctx->stat, AZ_FTP_CLIENT_CLOSE);
                            az_writelog(AZ_LOG_DEBUG, "Az ftp: client [%s:%d] ctrl link closed", cli_ctx->netinfo.remote_ip, cli_ctx->netinfo.remote_port);
                        }
                        else if (recv_len > 0)
                        {
                            cli_ctx->data_len += recv_len;
                        REPARSER:
                            flag = az_ftp_command_parser(ctx->mp, cli_ctx->recv_buf, 2 * 1024 * 1024, &cli_ctx->data_len, &cmd);
                            if (flag != AZ_ERROR)
                                az_list_insert(cli_ctx->cmd_list, AZ_LIST_TAIL, 0, &cmd, sizeof(az_ftp_msg));
                            if (flag == AZ_AGAIN)
                                goto REPARSER;
                            if (flag == AZ_ERROR)
                                az_writelog(AZ_LOG_ERROR, "Az ftp: parser client msg failed");
                        }
                    } while (recv_len > 0);
                }
            }
        }
        else
            az_msleep(500);
    }

    return AZ_OK;
}

static int _az_ftp_server_send_handle(void *data)
{
    int flag = 0;
    int num = 0;
    //int loop = 0;
    struct epoll_event ev;
    struct epoll_event events[1];
    az_ftp_client cli_ctx = NULL;
    az_ftp_msg reply = NULL;
    az_ftp_trans_ctx ctx = NULL;

    if (data == NULL)
        return AZ_ERROR;
    ctx = (az_ftp_trans_ctx)data;

    az_writelog(AZ_LOG_DEBUG, "Az ftp: send thread start run ...");
    while (az_atomic_read(&ctx->run))
    {
        if (az_atomic_read(ctx->client_num) > 0)
        {
            flag = az_list_ergodic_start(ctx->client_list, AZ_LIST_HEAD);
            if (flag == AZ_OK)
            {
                for (cli_ctx = az_list_ergodic_getnd(ctx->client_list, NULL); cli_ctx != NULL; cli_ctx = az_list_ergodic_getnd(ctx->client_list, NULL))
                {
                    if (az_list_size(cli_ctx->reply_list) > 0)
                    {
                        int send_len = 0;
                        int data_len = 0;

                        flag = az_list_get(cli_ctx->reply_list, AZ_LIST_HEAD, &reply, NULL);
                        if (flag != AZ_OK || reply == NULL)
                        {
                            continue;
                        }

                        ev.data.fd = az_socket_get_fd(cli_ctx->client_fd);  //设置要处理的事件类型
                        ev.events = EPOLLOUT;
                        flag = epoll_ctl(ctx->send_epfd, EPOLL_CTL_ADD, az_socket_get_fd(cli_ctx->client_fd), &ev);
                        if (flag != 0)
                        {
                            az_writelog(AZ_LOG_ERROR, "FTP send: send fd add epoll event error!");
                            continue;
                        }
                        do
                        {
                            num = epoll_wait(ctx->send_epfd, events, 1, 50);
                            if (num > 0 && events[0].data.fd == az_socket_get_fd(cli_ctx->client_fd))
                            {
                                const char *send_data = NULL;

                                send_data = az_ftp_msg_to_str(reply);
                                data_len = az_strlen(send_data);

                                flag = az_send(cli_ctx->client_fd, send_data + send_len, data_len - send_len, 0);
                                if (flag == AZ_ERROR)
                                {
                                    az_atomic_set(&cli_ctx->stat, AZ_FTP_CLIENT_LINKERR);
                                    break;
                                }
                                else if (flag == 0)
                                {
                                    az_atomic_set(&cli_ctx->stat, AZ_FTP_CLIENT_CLOSE);
                                    break;
                                }
                                else
                                    send_len += flag;
                            }
                        } while (send_len < data_len);
                        az_list_pop(cli_ctx->reply_list, AZ_LIST_HEAD, NULL, NULL);

                        az_ftp_msg_free(&reply);
                        epoll_ctl(ctx->send_epfd, EPOLL_CTL_DEL, az_socket_get_fd(cli_ctx->client_fd), &ev);
                    }
                }
                az_list_ergodic_end(ctx->client_list);
            }
        }
        az_msleep(1);
    }

    return AZ_OK;
}

static void _az_ftp_client(void *data)
{
    int flag = 0;
    az_ftp_client ctx = NULL;
    az_ftp_msg cmd = NULL;
    struct epoll_event ev;

    if (data == NULL)
        return;
    ctx = (az_ftp_client)data;

    if (ctx->simplify)
    {
        ctx->ser_recv_epfd = epoll_create(1);
        if (ctx->ser_recv_epfd < 0)
        {
            az_writelog(AZ_LOG_ERROR, "ftp client: create epoll fd failed");
            return;
        }
        ev.data.fd = az_socket_get_fd(ctx->client_fd);  //设置要处理的事件类型
        ev.events = EPOLLIN | EPOLLET;
        flag = epoll_ctl(ctx->ser_recv_epfd, EPOLL_CTL_ADD, az_socket_get_fd(ctx->client_fd), &ev);
        if (flag != 0)
        {
            az_atomic_set(&ctx->stat, AZ_FTP_CLIENT_ERR);
            return;
        }
    }
    else
    {
        ev.data.fd = az_socket_get_fd(ctx->client_fd);  //设置要处理的事件类型
        ev.events = EPOLLIN | EPOLLET;
        flag = epoll_ctl(ctx->ser_recv_epfd, EPOLL_CTL_ADD, az_socket_get_fd(ctx->client_fd), &ev);
        if (flag != 0)
        {
            az_atomic_set(&ctx->stat, AZ_FTP_CLIENT_ERR);
            return;
        }
    }

    az_ftp_response(ctx, AZ_FTP_SER_READY, "welcome use az ftp server");
    while (az_atomic_read(&ctx->stat) == AZ_FTP_CLIENT_RUN)
    {
        if (ctx->simplify)
        {
            int num = 0;
            int recv_len = 0;
            struct epoll_event events[1];
            
            num = epoll_wait(ctx->ser_recv_epfd, events, 1, 500);
            if (num > 0 && (events[0].events&EPOLLIN) && events[0].data.fd == az_socket_get_fd(ctx->client_fd))
            {
                do
                {
                    recv_len = az_recv(ctx->client_fd, ctx->recv_buf + ctx->data_len, 2 * 1024 * 1024 - ctx->data_len, 0);
                    if (recv_len == AZ_ERROR)
                    {
                        az_atomic_set(&ctx->stat, AZ_FTP_CLIENT_LINKERR);
                        az_writelog(AZ_LOG_ERROR, "Az ftp: client [%s:%d] ctrl link recv err", ctx->netinfo.remote_ip, ctx->netinfo.remote_port);
                    }
                    else if (recv_len == 0)
                    {
                        az_atomic_set(&ctx->stat, AZ_FTP_CLIENT_CLOSE);
                        az_writelog(AZ_LOG_DEBUG, "Az ftp: client [%s:%d] ctrl link closed", ctx->netinfo.remote_ip, ctx->netinfo.remote_port);
                    }
                    else if (recv_len > 0)
                    {
                        ctx->data_len += recv_len;
                    REPARSER:
                        flag = az_ftp_command_parser(ctx->mp, ctx->recv_buf, 2 * 1024 * 1024, &ctx->data_len, &cmd);
                        if (flag != AZ_ERROR)
                        {
                            az_ftp_cmdexec(ctx, cmd);
                            //az_ftp_response(ctx->mp, ctx->reply_list, AZ_FTP_CMD_OK, NULL);
                            az_ftp_msg_free(&cmd);
                        }
                        if (flag == AZ_AGAIN)
                            goto REPARSER;
                        if (flag == AZ_ERROR)
                            az_writelog(AZ_LOG_ERROR, "Az ftp: parser client msg failed");
                    }
                } while (recv_len > 0);
            }
        }
        else
        {
            flag = az_list_pop(ctx->cmd_list, AZ_LIST_HEAD, &cmd, NULL);
            if (flag != AZ_OK || cmd == NULL)
            {
                az_msleep(100);
                continue;
            }
            az_ftp_cmdexec(ctx, cmd);
            //az_ftp_response(ctx->mp, ctx->reply_list, AZ_FTP_CMD_OK, NULL);
            az_ftp_msg_free(&cmd);
        }
    }
}

static void _az_ftp_client_exit(void *data)
{
    int flag = 0;
    az_ftp_client ctx = NULL;
    az_ftp_session sess = NULL;
    struct epoll_event ev;
    az_atomic_t *client_num = NULL;

    if (data == NULL)
        return;
    ctx = (az_ftp_client)data;

    //停止控制链接接收数据
    if (ctx->ser_recv_epfd >= 0)
    {
        epoll_ctl(ctx->ser_recv_epfd, EPOLL_CTL_DEL, az_socket_get_fd(ctx->client_fd), &ev);
        if (ctx->simplify)
            close(ctx->ser_recv_epfd);
    }

    //这里停止所有的session
    if (az_list_size(ctx->session_list) > 0)
    {
        flag = az_list_ergodic_start(ctx->session_list, AZ_LIST_HEAD);
        if (flag == AZ_OK)
        {
            for (sess = az_list_ergodic_getnd(ctx->session_list, NULL); sess != NULL; sess = az_list_ergodic_getnd(ctx->session_list, NULL))
                az_atomic_set(&sess->abort, AZ_TRUE);
            az_list_ergodic_end(ctx->session_list);
        }
        else
            az_list_reset(ctx->session_list);
    }
    while (az_list_size(ctx->session_list) > 0)
        az_msleep(100);

    //判断停止状态发送停止服务响应

    //等待所有响应发送完毕
    if (az_atomic_read(&ctx->stat) != AZ_FTP_CLIENT_LINKERR)
    {
        while (az_list_size(ctx->reply_list) > 0)
            az_msleep(100);
    }

    //销毁
    az_taskp_destory(&ctx->tp);
    az_list_destory(&ctx->session_list);
    az_list_destory(&ctx->cmd_list);
    az_list_destory(&ctx->reply_list);
    az_close_socket(&ctx->client_fd);
    az_memp_destory(ctx->mp);
    //移除client
    az_writelog(AZ_LOG_DEBUG, "client [%s:%d] is exited", ctx->netinfo.remote_ip, ctx->netinfo.remote_port);
    client_num = &((az_ftp_server)(ctx->ser_ctx))->client_num;
    az_list_delnd(((az_ftp_server)(ctx->ser_ctx))->client_list, (void **)&ctx);
    az_atomic_dec(client_num);
}
