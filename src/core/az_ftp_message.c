#include"az_ftp_message.h"

#define set_cmd_index(n, str, msg) \
{ \
    int loop = 0; \
    int len = 0; \
    len = sizeof(string_##n) / sizeof(*string_##n); \
    msg->cmd_index = FTP_CMD_UNKNOWN; \
    for (loop = 0; loop < len; loop++) \
    { \
        if (az_strcasecmp(string_##n[loop].cmd, str) == 0) \
        { \
            msg->cmd_index = string_##n[loop].index; \
            break; \
        } \
    } \
}

typedef struct az_ftp_cmd_index_s
{
    const char *cmd;
    int index;
}az_ftp_cmd_index_t,*az_ftp_cmd_index;

static az_ftp_cmd_index_t string_A[] = {
    { "ACCT", FTP_CMD_ACCT }, 
    { "APPE", FTP_CMD_APPE }, 
    { "ALLO", FTP_CMD_ALLO }, 
    { "ABOR", FTP_CMD_ABOR }
};

static az_ftp_cmd_index_t string_C[] = {
    { "CWD", FTP_CMD_CWD }, 
    { "CDUP", FTP_CMD_CDUP }
};

static az_ftp_cmd_index_t string_D[] = {
    { "DELE", FTP_CMD_DELE }
};

static az_ftp_cmd_index_t string_H[] = {
    { "HELP" , FTP_CMD_HELP }
};

static az_ftp_cmd_index_t string_L[] = {
    { "LIST", FTP_CMD_LIST }
};

static az_ftp_cmd_index_t string_M[] = {
    { "MODE", FTP_CMD_MODE },
    { "MKD", FTP_CMD_MKD }
};

static az_ftp_cmd_index_t string_N[] = {
    { "NLST", FTP_CMD_NLST },
    { "NOOP", FTP_CMD_NOOP }
};

static az_ftp_cmd_index_t string_P[] = {
    { "PASS", FTP_CMD_PASS },
    { "PORT", FTP_CMD_PORT },
    { "PASV", FTP_CMD_PASV },
    { "PWD", FTP_CMD_PWD }
};

static az_ftp_cmd_index_t string_Q[] = {
    { "QUIT", FTP_CMD_QUIT }
};

static az_ftp_cmd_index_t string_R[] = {
    { "REIN", FTP_CMD_REIN },
    { "RETR", FTP_CMD_RETR },
    { "REST", FTP_CMD_REST },
    { "RNFR", FTP_CMD_RNFR },
    { "RNTO", FTP_CMD_RNTO },
    { "RMD", FTP_CMD_RMD }
};

static az_ftp_cmd_index_t string_S[] = {
    { "SMNT", FTP_CMD_SMNT },
    { "STRU", FTP_CMD_STRU },
    { "STOR", FTP_CMD_STOR },
    { "STOU", FTP_CMD_STOU },
    { "SITE", FTP_CMD_SITE },
    { "SYST", FTP_CMD_SYST },
    { "STAT", FTP_CMD_STAT }
};

static az_ftp_cmd_index_t string_T[] = {
    { "TYPE", FTP_CMD_TYPE }
};

static az_ftp_cmd_index_t string_U[] = {
    { "USER", FTP_CMD_USER }
};

static void _az_ftp_replace_alllws(char *buf);

az_ftp_msg az_ftp_msg_create(az_memp pool)
{
    az_ftp_msg tmp = NULL;

    if (pool == NULL)
        return NULL;

    tmp = (az_ftp_msg)az_mpcalloc(pool, sizeof(az_ftp_msg_t));
    if (tmp == NULL)
        return NULL;
    tmp->mp = pool;

    return tmp;
}

const char* az_ftp_msg_to_str(az_ftp_msg msg)
{
    int len = 0;
    int loop = 0;
    char cmd_str[AZ_FTP_COMMAND_LEN] = { 0 };

    if (msg == NULL)
        return NULL;

    if (msg_is_reply(msg))
    {
        len += snprintf(NULL, 0, "%d ", msg->code);
        len += az_strlen(msg->reason);
    }
    else
    {
        switch (msg->cmd_index)
        {
        case FTP_CMD_USER:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "USER");
            break;
        case FTP_CMD_PASS:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "PASS");
            break;
        case FTP_CMD_ACCT:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "ACCT");
            break;
        case FTP_CMD_CWD:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "CWD");
            break;
        case FTP_CMD_CDUP:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "CDUP");
            break;
        case FTP_CMD_SMNT:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "SMNT");
            break;
        case FTP_CMD_REIN:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "REIN");
            break;
        case FTP_CMD_QUIT:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "QUIT");
            break;
        case FTP_CMD_PORT:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "PORT");
            break;
        case FTP_CMD_PASV:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "PASV");
            break;
        case FTP_CMD_TYPE:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "TYPE");
            break;
        case FTP_CMD_STRU:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "STRU");
            break;
        case FTP_CMD_MODE:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "MODE");
            break;
        case FTP_CMD_RETR:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "RETR");
            break;
        case FTP_CMD_STOR:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "STOR");
            break;
        case FTP_CMD_STOU:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "STOU");
            break;
        case FTP_CMD_APPE:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "APPE");
            break;
        case FTP_CMD_ALLO:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "ALLO");
            break;
        case FTP_CMD_REST:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "REST");
            break;
        case FTP_CMD_RNFR:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "RNFR");
            break;
        case FTP_CMD_RNTO:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "RNTO");
            break;
        case FTP_CMD_ABOR:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "ABOR");
            break;
        case FTP_CMD_DELE:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "DELE");
            break;
        case FTP_CMD_RMD:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "RMD");
            break;
        case FTP_CMD_MKD:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "MKD");
            break;
        case FTP_CMD_PWD:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "PWD");
            break;
        case FTP_CMD_LIST:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "LIST");
            break;
        case FTP_CMD_NLST:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "NLST");
            break;
        case FTP_CMD_SITE:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "SITE");
            break;
        case FTP_CMD_SYST:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "SYST");
            break;
        case FTP_CMD_STAT:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "STAT");
            break;
        case FTP_CMD_HELP:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "HELP");
            break;
        case FTP_CMD_NOOP:
            len += snprintf(cmd_str, AZ_FTP_COMMAND_LEN, "%s", "NOOP");
            break;
        default:
            return NULL;
            break;
        }

        if (msg->argc > 0)
        {
            for (loop = 0; loop < msg->argc; loop++)
                len += snprintf(NULL, 0, " %s", msg->argv[loop]);
        }
    }
    len += 3;

    if (msg->str == NULL)
    {
        msg->str = (char *)az_mpcalloc(msg->mp, len);
        if (msg->str == NULL)
            return NULL;
    }
    else
    {
        char *tmp = NULL;
        tmp = (char *)az_mprealloc(msg->mp, (void **)&msg->str, len);
        if (tmp == NULL)
            return NULL;
        msg->str = tmp;
    }

    if (msg_is_reply(msg))
        snprintf(msg->str, len, "%d %s\r\n", msg->code, msg->reason);
    else
    {
        int offset = 0;
        offset = snprintf(msg->str, len, "%s", cmd_str);
        if (msg->argc > 0)
        {
            for (loop = 0; loop < msg->argc; loop++)
                offset += snprintf(msg->str + offset, len - offset, " %s", msg->argv[loop]);
        }
        snprintf(msg->str + offset, len - offset, "\r\n");
    }

    return msg->str;
}

void az_ftp_msg_free(az_ftp_msg *msg)
{
    int loop = 0;

    if (*msg == NULL)
        return;

    if ((*msg)->argv != NULL)
    {
        for (loop = 0; loop < (*msg)->argc; loop++)
            if ((*msg)->argv[loop] != NULL)
                az_mpfree((*msg)->mp, (void **)&(*msg)->argv[loop]);
        az_mpfree((*msg)->mp, (void **)&(*msg)->argv);
    }
    if ((*msg)->reason != NULL)
        az_mpfree((*msg)->mp, (void **)&(*msg)->reason);
    if ((*msg)->str != NULL)
        az_mpfree((*msg)->mp, (void **)&(*msg)->str);

    az_mpfree((*msg)->mp, (void **)msg);
}

int az_ftp_command_parser(az_memp pool, char *recv_buf, int buf_len, int *data_len, az_ftp_msg *cmd)
{
    int ret = AZ_ERROR;
    az_ftp_msg tmp_msg = NULL;
    int offset = 0;
    char *tmp_str = NULL;
    char *cmd_end = NULL;
    char *tmp_end = NULL;

    if (pool == NULL || recv_buf == NULL || buf_len == 0 || data_len == NULL || *data_len == 0 || cmd == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "00000000000000000000000000000000");
        return AZ_ERROR;
    }

    *cmd = NULL;
    for (tmp_str = recv_buf; *tmp_str != '\0'; tmp_str++)
    {
        if (*tmp_str < 65 || (*tmp_str > 90 && *tmp_str < 97) || *tmp_str>122)
            continue;
        else
            break;
    }

    cmd_end = az_strsstr(tmp_str, "\r\n");
    if (cmd_end == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "22222222222222222222222222");
        return AZ_ERROR;
    }

    tmp_msg = az_ftp_msg_create(pool);
    if (tmp_msg == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "111111111111111111111111");
        goto ERR;
    }

    _az_ftp_replace_alllws(tmp_str);
    *cmd_end = '\0';
    tmp_end = az_strschr(tmp_str, ' ', false);
    if (tmp_end != NULL)
        *tmp_end = '\0';
    if (*tmp_str >= 97 && *tmp_str <= 122)
        *tmp_str -= 32;

    switch (*tmp_str)
    {
    case 'A':
        set_cmd_index(A, tmp_str, tmp_msg)
        break;
    case 'C':
        set_cmd_index(C, tmp_str, tmp_msg)
        break;
    case 'D':
        set_cmd_index(D, tmp_str, tmp_msg)
        break;
    case 'H':
        set_cmd_index(H, tmp_str, tmp_msg)
        break;
    case 'L':
        set_cmd_index(L, tmp_str, tmp_msg)
        break;
    case 'M':
        set_cmd_index(M, tmp_str, tmp_msg)
        break;
    case 'N':
        set_cmd_index(N, tmp_str, tmp_msg)
        break;
    case 'P':
        set_cmd_index(P, tmp_str, tmp_msg)
        break;
    case 'Q':
        set_cmd_index(Q, tmp_str, tmp_msg)
        break;
    case 'R':
        set_cmd_index(R, tmp_str, tmp_msg)
        break;
    case 'S':
        set_cmd_index(S, tmp_str, tmp_msg)
        break;
    case 'T':
        set_cmd_index(T, tmp_str, tmp_msg)
        break;
    case 'U':
        set_cmd_index(U, tmp_str, tmp_msg)
        break;
    default:
        tmp_msg->cmd_index = FTP_CMD_UNKNOWN;
        break;
    }

GET_ARGV:
    if (tmp_end != NULL)
    {
        *tmp_end = ' ';
        tmp_str = ++tmp_end;
        for (; *tmp_str != '\0'; tmp_str++)
            if (*tmp_str != ' ')
                break;
    }
    else
        tmp_str = cmd_end;

    if (*tmp_str != '\0')
    {
        if (tmp_msg->argv == NULL)
        {
            tmp_msg->argv = (char **)az_mpcalloc(tmp_msg->mp, sizeof(char *));
            if (tmp_msg->argv == NULL)
            {
                az_writelog(AZ_LOG_ERROR, "333333333333333333333333333333");
                goto ERR;
            }
        }
        else
        {
            char **tmp = NULL;
            tmp = (char **)az_mprealloc(tmp_msg->mp, (void **)&tmp_msg->argv, sizeof(char *)*(tmp_msg->argc + 1));
            if (tmp == NULL)
            {
                az_writelog(AZ_LOG_ERROR, "4444444444444444444444444444444");
                goto ERR;
            }
            tmp_msg->argv = tmp;
        }

        tmp_end = az_strschr(tmp_str, ' ', false);
        if (tmp_end == NULL)
            tmp_end = cmd_end;

        //az_writelog(AZ_LOG_DEBUG, "argv len = %d", (sizeof(char)*(tmp_end - tmp_str) + 1));
        tmp_msg->argv[tmp_msg->argc] = (char *)az_mpcalloc(tmp_msg->mp, (sizeof(char)*(tmp_end - tmp_str) + 1));
        if (tmp_msg->argv[tmp_msg->argc] == NULL)
        {
            az_writelog(AZ_LOG_ERROR, "55555555555555555555555555555555");
            goto ERR;
        }
        az_strncpy(tmp_msg->argv[tmp_msg->argc], (sizeof(char)*(tmp_end - tmp_str) + 1), tmp_str, tmp_end - tmp_str);
        tmp_msg->argc++;

        if (*tmp_end != '\0')
            goto GET_ARGV;
    }

    ret = AZ_OK;
END:
    *cmd_end = '\r';
    cmd_end += 2;
    offset = cmd_end - recv_buf;
    *data_len -= offset;
    if (*data_len <= 0)
        *data_len = 0;
    else
    {
        Az_Memmove(recv_buf, recv_buf + offset, *data_len);
        recv_buf[*data_len] = '\0';
        if (az_strsstr(recv_buf, "\r\n") != NULL)
            ret = AZ_AGAIN;
    }
    Az_Memzero(recv_buf + (*data_len), buf_len - (*data_len));
    *cmd = tmp_msg;

    return ret;
ERR:
    *cmd_end = '\r';
    if (tmp_msg != NULL)
        az_ftp_msg_free(&tmp_msg);
    return AZ_ERROR;
}

int az_ftp_reply_parser(az_memp pool, char *recv_buf, int buf_len, int *data_len, az_ftp_msg *cmd)
{
    int rep_code = 0;
    int offset = 0;
    static bool nfirst = false;
    char *tmp_str = NULL;
    char *rep_end = NULL;
    az_ftp_msg tmp_msg = NULL;
    bool end_flag = false;
    int ret = 1;

    if (pool == NULL || recv_buf == NULL || data_len == NULL || *data_len == 0 || cmd == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "00000000000000000000000000000000");
        return AZ_ERROR;
    }
    if (nfirst && *cmd == NULL)
    {
        nfirst = false;
        return AZ_ERROR;
    }
    else if (nfirst)
        tmp_msg = *cmd;
    else if (!nfirst)
        *cmd = NULL;

    if (tmp_msg == NULL)
    {
        tmp_msg = az_ftp_msg_create(pool);
        if (tmp_msg == NULL)
        {
            az_writelog(AZ_LOG_ERROR, "111111111111111111111111");
            return AZ_ERROR;
        }
    }

    tmp_str = recv_buf;
AGAIN:
    rep_end = az_strsstr(tmp_str, "\r\n");
    if (rep_end == NULL && tmp_str == recv_buf)
        goto ERR;
    else if (rep_end == NULL)
        goto END;

    rep_code = atoi(tmp_str);
    if (rep_code >= 100 && rep_code <= 600)
    {
        if (nfirst)
        {
            char *tmp_res = NULL;
            if (tmp_str[3] == ' ' && rep_code == tmp_msg->code)
            {
                tmp_str += 4;
                end_flag = true;
            }

            tmp_res = (char *)az_mprealloc(tmp_msg->mp, (void **)&tmp_msg->reason, az_strlen(tmp_msg->reason) + (rep_end - tmp_str) + 1);
            if (tmp_res == NULL)
            {
                ret = AZ_ERROR;
                goto ERR;//?
            }
            tmp_msg->reason = tmp_res;

            az_strncpy(tmp_msg->reason + az_strlen(tmp_msg->reason), az_strlen(tmp_msg->reason) + (rep_end - tmp_str) + 1, tmp_str, rep_end - tmp_str);
        }
        else
        {
            tmp_msg->code = rep_code;
            if (tmp_str[3] == '-')
                nfirst = true;
            else if (tmp_str[3] == ' ')
                end_flag = true;
            else
            {
                ret = AZ_ERROR;
                goto END;
            }

            tmp_str += 4;
            tmp_msg->reason = (char *)az_mpcalloc(tmp_msg->mp, rep_end - tmp_str + 1);
            if (tmp_msg->reason == NULL)
            {
                ret = AZ_ERROR;
                goto ERR;//?
            }
            az_strncpy(tmp_msg->reason, rep_end - tmp_str + 1, tmp_str, rep_end - tmp_str);
        }
    }
    else if(nfirst)
    {
        char *tmp_res = NULL;
        tmp_res = (char *)az_mprealloc(tmp_msg->mp, (void **)&tmp_msg->reason, az_strlen(tmp_msg->reason) + (rep_end - tmp_str) + 1);
        if (tmp_res == NULL)
        {
            ret = AZ_ERROR;
            goto ERR;//?
        }
        tmp_msg->reason = tmp_res;

        az_strncpy(tmp_msg->reason + az_strlen(tmp_msg->reason), az_strlen(tmp_msg->reason) + (rep_end - tmp_str) + 1, tmp_str, rep_end - tmp_str);
    }
    tmp_str = rep_end + 2;
    if (!end_flag && *tmp_str != '\0')
        goto AGAIN;

END:
    if (end_flag)
    {
        ret = AZ_OK;
        nfirst = false;
    }
    if (ret == AZ_ERROR)
    {
        nfirst = false;
        az_ftp_msg_free(&tmp_msg);
    }
    if (rep_end == NULL)
        offset = tmp_str - recv_buf;
    else
        offset = rep_end - recv_buf + 2;
    *data_len -= offset;
    if (*data_len <= 0)
        *data_len = 0;
    else
    {
        Az_Memmove(recv_buf, recv_buf + offset, *data_len);
        recv_buf[*data_len] = '\0';
        if (az_strsstr(recv_buf, "\r\n") != NULL)
            ret = AZ_AGAIN;
    }
    Az_Memzero(recv_buf + (*data_len), buf_len - (*data_len));
    *cmd = tmp_msg;

    return ret;
ERR:
    if (tmp_msg != NULL)
        az_ftp_msg_free(&tmp_msg);
    nfirst = false;
    *cmd = NULL;
    return ret;
}

az_ftp_msg az_ftp_make_cmd(az_memp pool, az_ftp_cmd cmd, const char *argv)
{
    az_ftp_msg tmp = NULL;
    int len = 0;

    if (pool == NULL)
        return NULL;

    tmp = az_ftp_msg_create(pool);
    if (tmp == NULL)
        return NULL;

    tmp->cmd_index = cmd;
    if (argv != NULL && *argv != '\0')
        if (az_ftp_msg_add_argv(tmp, argv) != AZ_OK)
            goto ERR;

    return tmp;
ERR:
    if (tmp != NULL)
        az_ftp_msg_free(&tmp);
    return NULL;
}

az_ftp_msg az_ftp_make_reply(az_memp pool, int code, const char *res)
{
    az_ftp_msg tmp = NULL;
    int len = 0;

    if (pool == NULL || code < 100 || code >= 600)
        return NULL;

    tmp = az_ftp_msg_create(pool);
    if (tmp == NULL)
        return NULL;

    if (res == NULL || *res == '\0')
        res = _az_ftp_get_reason(code);

    tmp->code = code;
    //if (code == AZ_FTP_CREATE_OK)
    //{
    //    va_list ap;
    //    char *str = NULL;
    //    va_start(ap, res);
    //    if (ap != NULL)
    //    {
    //        str = va_arg(ap, char *);
    //        len = snprintf(NULL, 0, "\"%s\" %s", str, res);
    //        tmp->reason = (char *)az_mpcalloc(tmp->mp, len + 1);
    //        if (tmp->reason == NULL)
    //        {
    //            va_end(ap);
    //            goto ERR;
    //        }
    //        snprintf(tmp->reason, len + 1, "\"%s\" %s", str, res);
    //        va_end(ap);
    //    }
    //}
    if (tmp->reason == NULL)
    {
        len = snprintf(NULL, 0, "%s", res);
        tmp->reason = (char *)az_mpcalloc(tmp->mp, len + 1);
        if (tmp->reason == NULL)
            goto ERR;
        snprintf(tmp->reason, len + 1, "%s", res);
    }

    return tmp;
ERR:
    if (tmp != NULL)
        az_ftp_msg_free(&tmp);
    return NULL;
}

az_ftp_cmd az_ftp_msg_get_cmd(az_ftp_msg cmd)
{
    if (cmd == NULL)
        return AZ_ERROR;
    if (msg_is_reply(cmd))
        return AZ_ERROR;

    return cmd->cmd_index;
}

int az_ftp_msg_get_argc(az_ftp_msg cmd)
{
    if (cmd == NULL)
        return AZ_ERROR;
    
    if (msg_is_reply(cmd))
        return AZ_ERROR;

    return cmd->argc;
}

const char* az_ftp_msg_get_argv(az_ftp_msg cmd, int index)
{
    if (cmd == NULL)
        return NULL;
    if (msg_is_reply(cmd))
        return NULL;
    if (index > cmd->argc)
        return NULL;

    return cmd->argv[index - 1];
}

int az_ftp_msg_add_argv(az_ftp_msg cmd, const char *argv)
{
    if (cmd == NULL || argv == NULL || *argv == '\0')
        return AZ_ERROR;

    if (cmd->argc == 0)
    {
        cmd->argv = (char **)az_mpcalloc(cmd->mp, sizeof(char *));
        if (cmd->argv == NULL)
            return AZ_NO_MEMORY;

        cmd->argv[cmd->argc] = (char *)az_mpcalloc(cmd->mp, az_strlen(argv) + 1);
        if (cmd->argv[cmd->argc] == NULL)
        {
            az_mpfree(cmd->mp, (void **)&cmd->argv);
            return AZ_NO_MEMORY;
        }
        az_strncpy(cmd->argv[cmd->argc], az_strlen(argv) + 1, argv, az_strlen(argv));
        cmd->argc++;
    }
    else
    {
        char **tmp = NULL;
        tmp = (char **)az_mprealloc(cmd->mp, (void **)&cmd->argv, sizeof(char *)*(cmd->argc + 1));
        if (tmp == NULL)
            return AZ_NO_MEMORY;
        cmd->argv = tmp;

        cmd->argv[cmd->argc] = (char *)az_mpcalloc(cmd->mp, az_strlen(argv) + 1);
        if (cmd->argv[cmd->argc] == NULL)
            return AZ_NO_MEMORY;
        az_strncpy(cmd->argv[cmd->argc], az_strlen(argv) + 1, argv, az_strlen(argv));
        cmd->argc++;
    }

    return AZ_OK;
}

int az_ftp_msg_get_code(az_ftp_msg reply)
{
    if (reply == NULL)
        return AZ_ERROR;
    if (!msg_is_reply(reply))
        return AZ_ERROR;
    return reply->code;
}

const char* az_ftp_msg_get_res(az_ftp_msg reply)
{
    if (reply == NULL)
        return NULL;
    if (!msg_is_reply(reply))
        return NULL;

    return (const char *)reply->reason;
}

static void _az_ftp_replace_alllws(char *buf)
{
    char *tmp = buf;
    if (buf == NULL)
        return;

    for (; tmp[0] != '\0'; tmp++)
    {
        if (('\0' == tmp[0]) || ('\0' == tmp[1]))
            return;
        if (('\r' == tmp[0]) && ('\n' == tmp[1]))
            return;				//end of message
        if (('\r' == tmp[0]) || ('\n' == tmp[0]) || ('\t' == tmp[0]))
            tmp[0] = ' ';
    }
}
