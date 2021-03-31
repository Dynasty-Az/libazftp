#include<azftp/az_ftp_client.h>

int main(int argc, char *argv[])
{
    az_memp pool = NULL;
    char *list = NULL;
    az_ftp_client ftp_client = NULL;

    printf("connect %s:%s\n", argv[1], argv[2]);

    pool = az_memp_create(1024, false);
    if (pool == NULL)
        return 1;

    ftp_client = az_ftp_client_open(argv[1], atoi(argv[2]), 1, true);
    if (ftp_client == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "open ftp client err");
        return 1;
    }

    if (az_ftp_client_login(ftp_client, "qiao", "123456", NULL) != AZ_OK)
        az_writelog(AZ_LOG_ERROR, "ftp client login err");
    else
        az_writelog(AZ_LOG_INFO, "ftp client login OK");

    az_writelog(AZ_LOG_DEBUG, "pwd: %s", az_ftp_client_pwd(ftp_client));

    az_ftp_client_cwd(ftp_client, "lampp");

    az_ftp_client_list(pool, ftp_client, NULL, &list);
    printf("%s\n", list);

    az_ftp_client_nlist(pool, ftp_client, NULL, &list);
    printf("%s\n", list);

    az_sleep(5);

    az_ftp_client_close(&ftp_client);
    az_memp_destory(pool);
    return 0;
}
