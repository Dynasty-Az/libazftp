#include"az_ftp_include.h"

int az_ftp_response(az_ftp_client client, int code, const char *res)
{
    az_ftp_msg reply_d = NULL;
    char text[1024] = { 0 };

    if (client == NULL || code < 100 || code > 600)
        return AZ_ERROR;

    reply_d = az_ftp_make_reply(client->mp, code, res);
    if (reply_d == NULL)
        return AZ_ERROR;

    snprintf(text, 1024, "%s", az_ftp_msg_to_str(reply_d));
    text[az_strlen(text) - 2] = '\0';
    az_writelog(AZ_LOG_DEBUG, "client [%s:%d] send reply :%s", client->netinfo.remote_ip, client->netinfo.remote_port, text);

    if (client->simplify)
    {
        int data_len = 0;
        int flag = 0;
        const char *send_data = NULL;

        send_data = az_ftp_msg_to_str(reply_d);
        data_len = az_strlen(send_data);

        flag = az_send(client->client_fd, send_data, data_len, 0);
        if (flag == AZ_ERROR || flag != data_len)
            az_atomic_set(&client->stat, AZ_FTP_CLIENT_LINKERR);
        else if (flag == 0)
            az_atomic_set(&client->stat, AZ_FTP_CLIENT_CLOSE);

        az_ftp_msg_free(&reply_d);
    }
    else
    {
        az_list_insert(client->reply_list, AZ_LIST_TAIL, 0, &reply_d, sizeof(az_ftp_msg));
        while (az_list_size(client->reply_list) > 0)
            az_msleep(10);
    }

    return AZ_OK;
}
