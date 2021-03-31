#include<libazftpcnf.h>
#include<azftp/az_ftp_server.h>
#include<azctools/az_getopt.h>

static struct option az_ftpser_lopt[] = {
    { "config", required_argument, NULL, 'c' },
    { "version", no_argument, NULL, 'v' },
    { "help", no_argument, NULL, 'h' },
    { 0, 0, 0, 0 }
};

static char *param_info[] = {
    "{config file path}",
    "",
    ""
};

static char *help_info[] = {
    "Az ftp server config info file path, default (/etc/azftp.cnf)",
    "Show version information",
    "Display help information"
};

static void _az_print_help_info(void);

int main(int argc, char *argv[])
{
    az_ret flag = 0;
    int op_index = 0;
    az_ftp_server server = NULL;
    az_ftp_config_t ftp_cnf = { 0 };
    struct stat statbuf;
    char cnf_path[AZ_FTP_PATH_MAX_LEN] = { "/etc/azftp.cnf" };
    az_stime_t build_time = { 0 };
#if defined(__az_windows_32__) || defined(__az_windows_64__)
#else
    int sig = 0;
    sigset_t mask;
    siginfo_t sig_info = { 0 };
    struct timespec del_t = { 0 };
#endif

    while ((flag = az_getopt_long(argc, argv, ":c:vh", az_ftpser_lopt, &op_index)) != -1)
    {
        switch (flag)
        {
        case 'c'://config file path
            //printf("az_optarg: %s\n", az_optarg);
            if (az_optarg == NULL || *az_optarg == '-')
            {
                if (argv[az_optind - 1][0] == '-'&&argv[az_optind - 1][1] == '-')
                    printf("  Option ' \033[;31m%s\033[0m\033[0m' requires an argument\n", argv[az_optind - 1]);
                else
                    printf("  Option '\033[;31m-%c\033[0m' requires an argument\n", argv[az_optind - 1][1]);
                goto ERR;
            }
            else if (stat(az_optarg, &statbuf) != 0 || !(S_IFMT & statbuf.st_mode))
            {
                int offset = 1;

                if (az_strcmp(az_optarg, argv[az_optind - offset]) == 0)
                    offset++;

                if (argv[az_optind - offset][0] == '-'&&argv[az_optind - offset][1] == '-')
                    printf("  Option '\033[;31m%s\033[0m' argument ", argv[az_optind - offset]);
                else
                    printf("  Option '\033[;31m-%c\033[0m' argument ", argv[az_optind - offset][1]);
                printf("[ \033[;34m%s\033[0m ] is not a file path\n", az_optarg);
                goto ERR;
            }
            else
                az_strncpy(cnf_path, AZ_FTP_PATH_MAX_LEN, az_optarg, az_strlen(az_optarg));
            break;
        case 'v':
#ifdef AZ_BUILD_TIME
            az_local_date(&build_time, AZ_BUILD_TIME);
            printf("  Version: %d.%d.%d  (build time: %04d/%02d/%02d %02d:%02d:%02d)\n", AZ_MAJOR_VERSION, AZ_MINOR_VERSION, AZ_RELEASE_VERSION, build_time.year, build_time.month, build_time.day, build_time.hour, build_time.min, build_time.sec);
#else
            printf("  Version: %d.%d.%d\n", AZ_MAJOR_VERSION, AZ_MINOR_VERSION, AZ_RELEASE_VERSION);
#endif
#ifdef AZ_PREFIX_PATH
            printf("  Prefix path: %s\n", AZ_PREFIX_PATH);
#endif
            printf("  Base for %s\n", PACKAGE_STRING);
            printf("  Project home: %s\n", PROJECT_HOME_URL);
            printf("  Bug report: %s\n", PACKAGE_BUGREPORT);
            return 0;
            break;
        case 'h'://help
            _az_print_help_info();
            return 0;
            break;
        case ':':
            printf("  Option '\033[;31m%s\033[0m' requires an argument\n", argv[az_optind - 1]);
            goto ERR;
            break;
        case '?':
            if (az_optopt != 0)
                printf("  Not supported option: \033[;31m-%c\033[0m\n", (char)az_optopt);
            else
                printf("  Not supported option: \033[;31m%s\033[0m\n", argv[az_optind - 1]);
            printf("\tCan use '--help' or '-h' option view command help\n");
            goto ERR;
            break;
        default:
            break;
        }
    }

    flag = az_ftp_load_cnf(cnf_path, &ftp_cnf);
    if (flag != AZ_OK)
    {
        az_writelog(AZ_LOG_ERROR, "load ftp cnf info failed");
        return 1;
    }

    server = az_ftp_server_init(&ftp_cnf);
    if (server == NULL)
    {
        az_writelog(AZ_LOG_ERROR, "init ftp server failed");
        return 1;
    }

#if defined(__az_windows_32__) || defined(__az_windows_64__)
#else
    sigfillset(&mask);
    sigdelset(&mask, SIGABRT);
    sigdelset(&mask, SIGFPE);
    sigdelset(&mask, SIGILL);
    sigdelset(&mask, SIGCONT);
    sigdelset(&mask, SIGTSTP);
    sigdelset(&mask, SIGTTIN);
    sigdelset(&mask, SIGTTOU);
    sigdelset(&mask, SIGWINCH);
    sigprocmask(SIG_BLOCK, &mask, NULL); //设置信号屏蔽
#endif

    flag = az_ftp_server_run(server);
    if (flag != AZ_OK)
    {
        az_writelog(AZ_LOG_ERROR, "start ftp server failed");
        goto ERR;
    }

    while (az_ftp_server_stat(server))
    {
#if defined(__az_windows_32__) || defined(__az_windows_64__)
        az_sleep(1);
#else
        del_t.tv_sec = 1;
        sig = sigtimedwait(&mask, &sig_info, &del_t);
        if (sig == -1 && errno == EAGAIN)
            continue;
        else if (sig == SIGINT)
        {
            fprintf(stderr, "catched signal CTRL+C, exit\n");
            break;
        }
        else if (sig != SIGPIPE)
        {
            fprintf(stderr, "catched signal [%d] , exit\n", sig);
            break;
        }
#endif
    }

    az_ftp_server_destory(&server);
    return 0;
ERR:
    if (server != NULL)
        az_ftp_server_destory(&server);
    return 2;
}

static void _az_print_help_info(void)
{
    int loop = 0;

    printf("    Options:\n\n");

    for (loop = 0; az_ftpser_lopt[loop].name != NULL || az_ftpser_lopt[loop].has_arg != 0 || az_ftpser_lopt[loop].flag != NULL || az_ftpser_lopt[loop].val != 0; loop++)
    {
        if (*param_info[loop] != '\0' && az_strlen(param_info[loop]) < 16)
            printf("\t-%c, --%s\t%s\t\t%s\n", (char)az_ftpser_lopt[loop].val, az_ftpser_lopt[loop].name, param_info[loop], help_info[loop]);
        else if (*param_info[loop] != '\0')
            printf("\t-%c, --%s\t%s\t%s\n", (char)az_ftpser_lopt[loop].val, az_ftpser_lopt[loop].name, param_info[loop], help_info[loop]);
        else
            printf("\t-%c, --%s\t\t\t\t%s\n", (char)az_ftpser_lopt[loop].val, az_ftpser_lopt[loop].name, help_info[loop]);
    }
}
