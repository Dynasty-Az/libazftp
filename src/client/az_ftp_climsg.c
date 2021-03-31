#include"az_ftp_include.h"
/*
az_ret az_cli_send_cmd(az_ftp_client cli, az_ftp_cmd type, const char *argv)
{
    az_ftp_msg cmd = NULL;
    const char *send_data = NULL;
    int flag = 0;

    if (cli == NULL)
        return AZ_ERROR;
    if (az_atomic_read(&cli->state) != AZ_FTP_CLIENT_RUN)
        return AZ_ERROR;

    cmd = az_ftp_make_cmd(cli->mp, type, argv);
    if (cmd == NULL)
        goto ERR;

    send_data = az_ftp_msg_to_str(cmd);
    if (send_data == NULL)
        goto ERR;

    flag = az_send(cli->ctl_fd, send_data, az_strlen(send_data), 0);
    if (flag == AZ_ERROR || flag != az_strlen(send_data))
    {
        az_atomic_set(&cli->state, AZ_FTP_CLIENT_LINKERR);
        goto ERR;
    }
    else if (flag == 0)
    {
        az_atomic_set(&cli->state, AZ_FTP_CLIENT_SERCLOSE);
        goto ERR;
    }
    az_ftp_msg_free(&cmd);

    return AZ_OK;
ERR:
    if (cmd != NULL)
        az_ftp_msg_free(&cmd);
    return AZ_ERROR;
}

az_ftp_msg az_cli_waite_reply(az_ftp_client cli)
{
    az_ftp_msg reply = NULL;

    if (cli == NULL)
        return NULL;

    while (az_atomic_read(&cli->state) == AZ_FTP_CLIENT_RUN)
    {
        az_list_pop(cli->reply_list, AZ_LIST_HEAD, &reply, NULL);
        if (reply != NULL)
            break;
        az_msleep(10);
    }

    return reply;
}
*/
