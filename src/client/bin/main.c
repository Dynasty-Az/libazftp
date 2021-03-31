//#define TEST_UTF8 1
//#define TEST_PARSER_CMD 1
//#define TEST_INPUT 1

#include<libazftpcnf.h>
#include<azftp/az_ftp_client.h>
#include<azctools/az_getopt.h>
#include<azctools/az_cmd.h>
#include<azctools/az_utf8_str.h>
#include<termios.h>
#include<term.h>
#include<locale.h>
#include"cmd_histroy.h"

static struct option az_ftpcli_lopt[] = {
    { "user", required_argument, NULL, 'u' },
    { "passwd", required_argument, NULL, 'p' },
    { "host", required_argument, NULL, 'h' },
    { "worker", required_argument, NULL, 'w' },
    { "version", no_argument, NULL, 'v' },
    { "help", no_argument, NULL, 'H' },
    { 0, 0, 0, 0 }
};

static char *param_info[] = {
    "{user name}",
    "{password}",
    "{ip[:port]}",
    "{trans worker num}",
    "",
    ""
};

static char *help_info[] = {
    "Ftp user name, default (guest)",
    "Ftp password",
    "Ftp service host, port is optional (default: 21)",
    "Ftp client trans worker thread num, default (1)",
    "Show version information",
    "Display help information"
};

#define AZ_COM_WIN_HEIGHT (__get_term_lines())

#define AZ_RED_WORD_COLOR 1
#define AZ_BLUE_WORD_COLOR 2
#define AZ_YELLOW_WORD_COLOR 3
#define AZ_GREEN_WORD_COLOR 4
#define AZ_MAGENTA_WORD_COLOR 5
#define AZ_BLUE_BK_COLOR 6
#define AZ_CYAN_WORD_COLOR 7

typedef struct termios termios_t, *termios_p;

typedef struct az_display_ctx_s
{
    bool win_init;
    bool enable_color;
    int cursor_x;
    int cursor_y;
    termios_t org_info;
    termios_t new_info;
}az_display_ctx_t, *az_display_ctx;

typedef struct az_main_ctx_s
{
    az_atomic_t run;
    az_memp mp;
    char *user_name;
    char *pwd;
    az_ftp_login_status login_stat;
    az_ftp_client ftp_client;
    cmd_histroy histroy;
    int worker_num;

    az_display_ctx_t display_ctx;
}az_main_ctx_t, *az_main_ctx;

typedef struct az_file_info_s
{
    bool is_dir;
    char auth[11];
    char user[64];
    char group[64];
    off_t size;
    char mouth[5];
    char day[3];
    char time[6];
    char name[256];
}az_file_info_t, *az_file_info;

typedef struct az_file_list_s
{
    int list_num;
    az_file_info node;
}az_file_list_t, *az_file_list;

/* Information about filling a column.  */
typedef struct az_column_info_s
{
    int valid_len;
    int line_len;
    int *col_arr;
}az_column_info_t, *az_column_info;
/* The minimum width of a colum is 3: 1 character for the name and 2
for the separating white space.  */
#define MIN_COLUMN_WIDTH 3

static void _az_print_help_info(void);
static az_ret _az_init_windows(az_main_ctx ctx, const char *ser_ip, const int ser_port);
static void _az_destory_windows(az_main_ctx ctx);
static az_ret __get_cursor_position(int *line, int *col);
static void __set__cursor_position(int line, int col);
static void __backspace_key(int width);
static void __delete_key(int width);
static void __delete_end(void);
#define __delete_line() __delete_lines(1)
static void __delete_lines(int num);
static void __eraser_line(int line);
static void __beep(void);
static void __clear(void);
#define AZ_FN_KEY(n) AZ_F##n##_KEY = 0410+(n)
typedef enum az_esckey_e
{
    AZ_UNKNOWN_KEY = 0,
    AZ_ESCAPE_KEY = 27,
    AZ_DOWN_KEY = 0402,
    AZ_UP_KEY = 0403,
    AZ_LEFT_KEY = 0404,
    AZ_RIGHT_KEY = 0405,
    AZ_HOME_KEY = 0406,
    AZ_BACKSPACE_KEY = 0407,
    AZ_FN_KEY(1),
    AZ_FN_KEY(2),
    AZ_FN_KEY(3),
    AZ_FN_KEY(4),
    AZ_FN_KEY(5),
    AZ_FN_KEY(6),
    AZ_FN_KEY(7),
    AZ_FN_KEY(8),
    AZ_FN_KEY(9),
    AZ_FN_KEY(10),
    AZ_FN_KEY(11),
    AZ_FN_KEY(12),
    AZ_DELETE_C_KEY = 0512,
    AZ_NEXT_PAGE_KEY = 0522,
    AZ_PREV_PAGE_KEY = 0523,
    AZ_ENTER_KEY = 0527,
    AZ_KEY_MAX,
}az_esckey;
static int __escape_seq(uint8_t data[4], int data_size, bool timeout);
static inline int __get_term_cols(void);
static inline int __get_term_lines(void);
static int __get_str_width(az_memp mp, char *str);
static void __az_win_printf(az_memp pool, az_display_ctx display_ctx, const char *fmt, ...);
static int _az_input_command_th(void *data);
static const char* __az_get_last_dir(az_main_ctx ctx);
static az_ret __az_parser_file_list(az_memp pool, const char *buf, az_file_list list, bool all);
static inline void __az_print_file_list(az_main_ctx ctx, az_file_list list, bool ex, bool readable);
static int ___az_compar(const void *src1, const void *src2);
static int ___az_compar_cmd(const void *src1, const void *src2);
static az_column_info __init_column_info(az_memp pool, int *max_idx);
static void __free_column_info(az_memp pool, az_column_info *info, int max_idx);
static inline void ___indent(az_main_ctx ctx, int from, int to);
static void __az_show_list(az_main_ctx ctx, az_file_list list);
static int __az_cmd_to_strary(az_main_ctx ctx, az_cmd_info cmd_list, char ***ary);
static void __az_show_cmd_list(az_main_ctx ctx, char **cmd_list, int list_num);
static void __az_show_list_ex(az_main_ctx ctx, az_file_list list, bool readable);
static az_utf8 __az_gets(az_memp pool, az_main_ctx ctx, bool show);
static void __az_show_trans_status(az_main_ctx ctx);
static void __az_print_trans_status(az_main_ctx ctx, int cursor_x, az_file_session stat, size_t index, size_t total);

static az_ret az_client_clear(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_login(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_logout(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_pwd(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_cd(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_ls(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_mkdir(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_remove(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_rename(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_histroy(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_upload(az_main_ctx ctx, const az_cmd cmd);
static az_ret az_client_download(az_main_ctx ctx, const az_cmd cmd);

static az_cmd_info_t az_client_cmd[] = {
    { "clear", NULL, (az_cmd_callback)az_client_clear, NULL, 0 },
    { "login", ":u:p:", (az_cmd_callback)az_client_login, NULL, 1 },
    { "logout", NULL, (az_cmd_callback)az_client_logout, NULL, 2 },
    { "pwd", NULL, (az_cmd_callback)az_client_pwd, NULL, 3 },
    { "ls", ":lah", (az_cmd_callback)az_client_ls, NULL, 4 },
    { "cd", NULL, (az_cmd_callback)az_client_cd, NULL, 5 },
    { "mkdir", ":p", (az_cmd_callback)az_client_mkdir, NULL, 6 },
    { "rm", ":rf", (az_cmd_callback)az_client_remove, NULL, 7 },
    { "rename", NULL, (az_cmd_callback)az_client_rename, NULL, 8 },
    { "upload", NULL, (az_cmd_callback)az_client_upload, NULL, 9 },
    { "dnload", NULL, (az_cmd_callback)az_client_download, NULL, 10 },
    { "exit", NULL, (az_cmd_callback)az_client_logout, NULL, 11 },
    { "histroy", NULL, (az_cmd_callback)az_client_histroy, NULL, 12 },
    { 0, 0, 0, 0, 0 }
};

static az_alias_info_t az_client_alias[] = {
    {"ll", "ls -l"},
    {0, 0}
};

#define CMD_HISTROY_CACHE_PATH "/var/cache/azftpcli"
#define CMD_HISTROY_CACHE_NAME "cmd_histroy"

#ifdef TEST_UTF8
int main(int argc, char *argv[])
{
    char input[1500] = { 0 };
    int in_len = 0;
    az_memp pool = NULL;
    az_utf8 a = NULL;
    az_utf8 b = NULL;

    pool = az_memp_create(AZ_MEM_POOL_DEFAULT_SIZE, false);

    a = az_utf8_create(pool, 64, NULL);
    b = az_utf8_create(pool, 64, NULL);

    az_utf8_add(a, "mkdir ccc vvv");
    az_utf8_insert(b, az_utf8_len(b, 0), a, 0);

    printf("a: %s\n", az_utf8_tostr(a, 0));
    printf("b: %s\n", az_utf8_tostr(b, 0));

    az_memp_destory(pool);
    return 0;
}
#else
int main(int argc, char *argv[])
{
    int flag = 0;
    int loop = 0;
    int op_index = 0;
    char ser_ip[AZ_IPV4_ADDRESS_STRING_LEN] = { 0 };
    int ser_port = 0;
    int worker_num = 1;
    az_stime_t build_time = { 0 };
    az_main_ctx_t main_ctx = { 0 };
    az_thread th_cmd = NULL;
#if defined(__az_windows_32__) || defined(__az_windows_64__)
#else
    int sig = 0;
    sigset_t mask;
    siginfo_t sig_info = { 0 };
    struct timespec del_t = { 0 };
#endif

    setlocale(LC_ALL, "");
    main_ctx.mp = az_memp_create(AZ_MEM_POOL_DEFAULT_SIZE, false);
    if (main_ctx.mp == NULL)
    {
        printf("  Create memory pool \033[;31mfailed\033[0m\n");
        return 1;
    }

    while ((flag = az_getopt_long(argc, argv, ":u:p:h:w:vH", az_ftpcli_lopt, &op_index)) != -1)
    {
        switch (flag)
        {
        case 'u'://user name
            //printf("az_optarg: %s\n", az_optarg);
            if (az_optarg == NULL || *az_optarg == '-')
            {
                if (argv[az_optind - 1][0] == '-'&&argv[az_optind - 1][1] == '-')
                    printf("  Option ' \033[;31m%s\033[0m' requires an argument\n", argv[az_optind - 1]);
                else
                    printf("  Option '\033[;31m-%c\033[0m' requires an argument\n", argv[az_optind - 1][1]);
                goto RET_ERR;
            }
            else
            {
                main_ctx.user_name = (char *)az_mpcalloc(main_ctx.mp, az_strlen(az_optarg) + 1);
                if (main_ctx.user_name == NULL)
                {
                    printf("  Alloc user name memory [size: %u] from pool \033[;31mfailed\033[0m\n", az_strlen(az_optarg) + 1);
                    goto RET_ERR;
                }
                az_strncpy(main_ctx.user_name, az_strlen(az_optarg) + 1, az_optarg, az_strlen(az_optarg));
            }
            break;
        case 'p'://password
                 //printf("az_optarg: %s\n", az_optarg);
            if (az_optarg == NULL || *az_optarg == '-')
            {
                if (argv[az_optind - 1][0] == '-'&&argv[az_optind - 1][1] == '-')
                    printf("  Option ' \033[;31m%s\033[0m' requires an argument\n", argv[az_optind - 1]);
                else
                    printf("  Option '\033[;31m-%c\033[0m' requires an argument\n", argv[az_optind - 1][1]);
                goto RET_ERR;
            }
            else
            {
                main_ctx.pwd = (char *)az_mpcalloc(main_ctx.mp, az_strlen(az_optarg) + 1);
                if (main_ctx.pwd == NULL)
                {
                    printf("  Alloc password memory [size: %u] from pool \033[;31mfailed\033[0m\n", az_strlen(az_optarg) + 1);
                    goto RET_ERR;
                }
                az_strncpy(main_ctx.pwd, az_strlen(az_optarg) + 1, az_optarg, az_strlen(az_optarg));
            }
            break;
        case 'h'://server host
            //printf("az_optarg: %s\n", az_optarg);
            if (az_optarg == NULL || *az_optarg == '-')
            {
                if (argv[az_optind - 1][0] == '-'&&argv[az_optind - 1][1] == '-')
                    printf("  Option ' \033[;31m%s\033[0m' requires an argument\n", argv[az_optind - 1]);
                else
                    printf("  Option '\033[;31m-%c\033[0m' requires an argument\n", argv[az_optind - 1][1]);
                goto RET_ERR;
            }
            else
            {
                char *port = NULL;
                int ip_len = az_strlen(az_optarg);

                port = az_strschr(az_optarg, ':', false);
                if (port != NULL)
                {
                    ip_len = port - az_optarg;
                    ser_port = atoi(++port);
                }
                az_strncpy(ser_ip, AZ_IPV4_ADDRESS_STRING_LEN, az_optarg, ip_len);
                if (ser_port <= 0)
                    ser_port = 21;

                if (az_check_ipv4(ser_ip) != AZ_OK)
                {
                    int offset = 1;
                    if (az_strcmp(az_optarg, argv[az_optind - offset]) == 0)
                        offset++;

                    if (argv[az_optind - offset][0] == '-'&&argv[az_optind - offset][1] == '-')
                        printf("  Option '\033[;31m%s\033[0m' argument ", argv[az_optind - offset]);
                    else
                        printf("  Option '\033[;31m-%c\033[0m' argument ", argv[az_optind - offset][1]);
                    printf("[ \033[;34m%s\033[0m ] is not a ipv4 address\n", ser_ip);
                    goto RET_ERR;
                }
                if (ser_port <= 0 || ser_port > 65535)
                {
                    int offset = 1;
                    if (az_strcmp(az_optarg, argv[az_optind - offset]) == 0)
                        offset++;

                    if (argv[az_optind - offset][0] == '-'&&argv[az_optind - offset][1] == '-')
                        printf("  Option '\033[;31m%s\033[0m' argument ", argv[az_optind - offset]);
                    else
                        printf("  Option '\033[;31m-%c\033[0m' argument ", argv[az_optind - offset][1]);
                    printf("[ \033[;34m%d\033[0m ] is not a port range\n", ser_port);
                    goto RET_ERR;
                }
            }
            break;
        case 'w'://worker num
            //printf("az_optarg: %s\n", az_optarg);
            if (az_optarg == NULL || *az_optarg == '-')
            {
                if (argv[az_optind - 1][0] == '-'&&argv[az_optind - 1][1] == '-')
                    printf("  Option ' \033[;31m%s\033[0m' requires an argument\n", argv[az_optind - 1]);
                else
                    printf("  Option '\033[;31m-%c\033[0m' requires an argument\n", argv[az_optind - 1][1]);
                goto RET_ERR;
            }
            else
            {
                worker_num = atoi(az_optarg);
                if (worker_num <= 0)
                    worker_num = 1;
                if (worker_num > __get_term_lines() / 3)
                    worker_num = __get_term_lines() / 3;
            }
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
        case 'H'://help
            _az_print_help_info();
            return 0;
            break;
        case ':':
            printf("  Option '\033[;31m%s\033[0m' requires an argument\n", argv[az_optind - 1]);
            goto RET_ERR;
            break;
        case '?':
            if (az_optopt != 0)
                printf("  Not supported option: \033[;31m-%c\033[0m\n", (char)az_optopt);
            else
                printf("  Not supported option: \033[;31m%s\033[0m\n", argv[az_optind - 1]);
            printf("\tCan use '--help' or '-H' option view command help\n");
            goto RET_ERR;
            break;
        default:
            break;
        }
    }

#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
    if (*ser_ip == '\0')
    {
        printf("  Please use '--host' or '-h' option set ftp server host\n");
        goto RET_ERR;
    }
    main_ctx.worker_num = worker_num;
    main_ctx.ftp_client = az_ftp_client_open(ser_ip, ser_port, main_ctx.worker_num, false);
    if (main_ctx.ftp_client == NULL)
    {
        printf("Open ftp client connect to [%s:%d] failed\n", ser_ip, ser_port);
        goto RET_ERR;
    }
    if (main_ctx.user_name != NULL)
    {
        if (az_ftp_client_login(main_ctx.ftp_client, main_ctx.user_name, main_ctx.pwd, NULL) != AZ_OK)
            printf("User [%s] login ftp server failed\n", main_ctx.user_name);
        else
        {
            char file_name[128] = { 0 };
            printf("User [%s] login ftp server OK\n", main_ctx.user_name);
            main_ctx.login_stat = AZ_FTP_OKLOGIN;

            snprintf(file_name, 128, "%s_%s", CMD_HISTROY_CACHE_NAME, main_ctx.user_name);
            main_ctx.histroy = _create_histroy_ctx(CMD_HISTROY_CACHE_PATH, file_name);
            if (main_ctx.histroy == NULL)
            {
                printf(" create histroy cache failed.\n");
                goto RET_ERR;
            }
        }
    }
#else
    printf("user name: %s\n", main_ctx.user_name);
    printf("pwd: %s\n", main_ctx.pwd);
    printf("server ip: %s\n", ser_ip);
    printf("server port: %d\n", ser_port);
    printf("worker num: %d\n", worker_num);

    main_ctx.histroy = _create_histroy_ctx(CMD_HISTROY_CACHE_PATH, CMD_HISTROY_CACHE_NAME);
    if (main_ctx.histroy == NULL)
        goto RET_ERR;
#endif

    if (_az_init_windows(&main_ctx, ser_ip, ser_port) != AZ_OK)
        goto RET_ERR;

    for (loop = 0; az_client_cmd[loop].cmd != 0 || az_client_cmd[loop].opt != 0 || az_client_cmd[loop].cb != 0 || az_client_cmd[loop].data != 0 || az_client_cmd[loop].val != 0; loop++)
        az_client_cmd[loop].data = &main_ctx;

    az_atomic_set(&main_ctx.run, AZ_TRUE);
    th_cmd = az_create_thread(main_ctx.mp, "cmd", 0, false, true, _az_input_command_th, &main_ctx);
    if (th_cmd == NULL)
    {
        printf(" Create cmd thread failed\n");
        goto RET_ERR;
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
#if (defined(TEST_PARSER_CMD)||defined(TEST_INPUT))
    while (az_atomic_read(&main_ctx.run))
#else
    while (az_ftp_client_stat(main_ctx.ftp_client) == AZ_FTP_CLIENT_RUN && az_atomic_read(&main_ctx.run))
#endif
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
            fprintf(stderr, "catched signal SIGINT, exit\n");
            break;
        }
        else if (sig == SIGTERM)
        {
            fprintf(stderr, "catched signal SIGTERM, exit\n");
            break;
        }
        else if (sig != SIGPIPE)
        {
            fprintf(stderr, "catched signal [%d] , exit\n", sig);
            break;
        }
#endif
    }

    az_atomic_set(&main_ctx.run, AZ_FALSE);
    az_waite_thread(&th_cmd);
    _free_histroy_ctx(&main_ctx.histroy);
    _az_destory_windows(&main_ctx);
    az_ftp_client_close(&main_ctx.ftp_client);
    az_memp_destory(main_ctx.mp);
    printf("Bye\n");
    return 0;
RET_ERR:
    _az_destory_windows(&main_ctx);
    az_atomic_set(&main_ctx.run, AZ_FALSE);
    if (th_cmd != NULL)
        az_waite_thread(&th_cmd);
    if (main_ctx.ftp_client != NULL)
        az_ftp_client_close(&main_ctx.ftp_client);
    if (main_ctx.histroy != NULL)
        _free_histroy_ctx(&main_ctx.histroy);
    if (main_ctx.mp != NULL)
        az_memp_destory(main_ctx.mp);
    return 2;
}
#endif

static void _az_print_help_info(void)
{
    int loop = 0;

    printf("    Options:\n\n");

    for (loop = 0; az_ftpcli_lopt[loop].name != NULL || az_ftpcli_lopt[loop].has_arg != 0 || az_ftpcli_lopt[loop].flag != NULL || az_ftpcli_lopt[loop].val != 0; loop++)
    {
        if (*param_info[loop] != '\0' && az_strlen(param_info[loop]) < 16)
            printf("\t-%c, --%s\t%s\t\t%s\n", (char)az_ftpcli_lopt[loop].val, az_ftpcli_lopt[loop].name, param_info[loop], help_info[loop]);
        else if (*param_info[loop] != '\0')
            printf("\t-%c, --%s\t%s\t%s\n", (char)az_ftpcli_lopt[loop].val, az_ftpcli_lopt[loop].name, param_info[loop], help_info[loop]);
        else
            printf("\t-%c, --%s\t\t\t\t%s\n", (char)az_ftpcli_lopt[loop].val, az_ftpcli_lopt[loop].name, help_info[loop]);
    }
}

static az_ret _az_init_windows(az_main_ctx ctx, const char *ser_ip, const int ser_port)
{
    //int flag = 0;
    char content[128] = { 0 };
    int len = 0;
    char *line = NULL;
    int err = 0;

    if (ctx == NULL)
        return AZ_ERROR;

    ctx->display_ctx.win_init = false;
    ctx->display_ctx.enable_color = false;

    if (tcgetattr(fileno(stdin), &ctx->display_ctx.org_info) != 0)
        return AZ_ERROR;
    ctx->display_ctx.new_info = ctx->display_ctx.org_info;
    ctx->display_ctx.new_info.c_lflag &= ~ICANON;  //终端使用非标准模式
    ctx->display_ctx.new_info.c_lflag &= ~ECHO;      //关闭回显
    ctx->display_ctx.new_info.c_lflag &= ~ISIG;           //关闭特殊功能键信号映射
    ctx->display_ctx.new_info.c_cc[VMIN] = 0;           //单次读取字节数
    ctx->display_ctx.new_info.c_cc[VTIME] = 1;          //读取超时时间，单位100ms
    if (tcsetattr(fileno(stdin), TCSANOW, &ctx->display_ctx.new_info) != 0)
        return AZ_ERROR;
    ctx->display_ctx.win_init = true;

    setupterm(NULL, fileno(stdout), &err);
    if (err != 1)
        goto RET_ERR;
    if (tigetnum("colors") < 8)
        ctx->display_ctx.enable_color = false;
    else
        ctx->display_ctx.enable_color = true;

    if (__get_cursor_position(&ctx->display_ctx.cursor_x, &ctx->display_ctx.cursor_y) != AZ_OK)
        goto RET_ERR;
#if (defined(TEST_PARSER_CMD)||defined(TEST_INPUT))
    len = snprintf(content, 128, "test parser cmd  -   []");
    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s\n\n", content);
#else
    len = snprintf(content, 128, "Connect to ftp server  -  [%s:%d]", ser_ip, ser_port);
    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s\n\n", content);
    *content = '\0';
    if (az_ftp_client_serhello(ctx->ftp_client) != NULL)
    {
        int loop = 0;
        len = az_strlen(az_ftp_client_serhello(ctx->ftp_client));
        for (loop = 0; loop < len + 8; loop++)
            az_strcatchr(content, 128, '=');
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s\n\n", content);
        __az_win_printf(ctx->mp, &ctx->display_ctx, "    %s\n\n", az_ftp_client_serhello(ctx->ftp_client));
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s\n\n", content);
    }
#endif

#if (defined(TEST_PARSER_CMD)||defined(TEST_INPUT))
    len = snprintf(content, 128, "test cmd>> ");
#else
    if (ctx->login_stat == AZ_FTP_OKLOGIN)
        len = snprintf(content, 128, "$-%s@ftpc %s>> ", ctx->user_name, __az_get_last_dir(ctx));
    else
        len = snprintf(content, 128, "login as: ");
#endif
    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", content);

    return AZ_OK;
RET_ERR:
    if (ctx->display_ctx.win_init)
        tcsetattr(fileno(stdin), TCSANOW, &ctx->display_ctx.org_info);
    return AZ_ERROR;
}

static void _az_destory_windows(az_main_ctx ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->display_ctx.win_init == false)
        return;
    tcsetattr(fileno(stdin), TCSANOW, &ctx->display_ctx.org_info);
}

#define AZ_ASCII_BACKSPACE_KEY 8
#define AZ_ASCII_TAB_KEY 9
#define AZ_ASCII_ENTER_KEY 10
#define AZ_ASCII_ESCAPE_KEY 27
#define AZ_ASCII_DELETE_KEY 127
#define AZ_ASCII_CTRL_C_KEY 3
#define AZ_ASCII_CTRL_D_KEY 4
#define AZ_ASCII_CTRL_K_KEY 11
#define AZ_ASCII_CTRL_L_KEY 12
#define AZ_ASCII_CTRL_U_KEY 21
#define AZ_HISTORY_MAX_COUNT 100

static int _az_input_command_th(void *data)
{
    az_ret flag = 0;
    char *ret = NULL;
    az_main_ctx ctx = NULL;
    int com_c_index = 0;
    int com_len = 0;
    int com_size = 0;
    az_utf8 prefix = NULL;
    az_utf8 input = NULL;
    az_utf8 parser_buf = NULL;
    int key = 0;
    int key_size = 0;
    uint8_t key_buf[7] = { 0 };
    bool trans_flag = false;
    bool Ident_flag = false;
    bool multiline_flag = false;
    az_stime_t push_key = { 0 };
    az_stime_t last_push_key = { 0 };
    int word_width = 0;
    az_utf8_node_t word = { 0 };
    bool tab_flag = false;
    int histroy_index = 0;

    if (data == NULL)
        return -1;
    ctx = (az_main_ctx)data;

    input = az_utf8_create(ctx->mp, com_size, NULL);
    if (input == NULL)
        return -1;
    parser_buf= az_utf8_create(ctx->mp, com_size, NULL);
    if (parser_buf == NULL)
        return -1;
    prefix = az_utf8_create(ctx->mp, 64, NULL);
    if (prefix == NULL)
        return -1;

#if defined TEST_PARSER_CMD || defined TEST_INPUT
    az_utf8_format(prefix, 0, "test cmd>> ");
#else
    if (ctx->login_stat == AZ_FTP_OKLOGIN)
        az_utf8_format(prefix, 0, "$-%s@ftpc %s>> ", ctx->user_name, __az_get_last_dir(ctx));
    else if (ctx->login_stat == AZ_FTP_DEALLOGIN)
        az_utf8_format(prefix, 0, "password: ");
    else
        az_utf8_format(prefix, 0, "login as: ");
#endif

    com_size = __get_term_cols();
    histroy_index = _histroy_size(ctx->histroy);
    while (az_atomic_read(&ctx->run))
    {
        key = fgetc(stdin);
        if (key < 0)
        {
            if (trans_flag)
            {
                az_get_date(&push_key);
                if (az_time_difference(&last_push_key, &push_key) >= 50)//按键间隔是否超时
                {
                    //这里识别转义序列
                    key = __escape_seq(key_buf, key_size, true);
                    if (key >= 0 && key != AZ_UNKNOWN_KEY)
                    {
                        Ident_flag = true;
                        goto TRANS_FLAG;
                    }
                    __az_win_printf(ctx->mp, &ctx->display_ctx, " Err: unknown escape sequence: \\E%s\n", (char *)&key_buf[1]);
                    trans_flag = false;
                    Ident_flag = false;
                    Az_Memzero(key_buf, 7);
                    key_size = 0;
                }
            }
            continue;
        }
        az_get_date(&push_key);

        if (!trans_flag && key > 31 && key != 127)//普通输入
        {
            flag = az_utf8_ndadd_chr(&word, key);
            if (flag == AZ_ERROR)
                Az_Memzero(&word, sizeof(az_utf8_node_t));
            else if (flag == AZ_OK)
            {
                if (ctx->login_stat != AZ_FTP_DEALLOGIN)
                    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", (char *)word.data);
                if (com_c_index != com_len)
                {
                    int old_x = ctx->display_ctx.cursor_x;
                    int old_y = ctx->display_ctx.cursor_y;
                    az_utf8_insert_nd(input, com_c_index, &word);
                    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, com_c_index + 1));
                    ctx->display_ctx.cursor_x = old_x;
                    ctx->display_ctx.cursor_y = old_y;
                    __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                }
                else
                    az_utf8_insert_nd(input, com_c_index, &word);
                com_len++;
                com_c_index++;
                tab_flag = false;
                Az_Memzero(&word, sizeof(az_utf8_node_t));
            }
        }
        else if(trans_flag)//输入转义序列
        {
            key_buf[key_size] = key;
            key_size++;
            if (key_size == 6)
            {
                __az_win_printf(ctx->mp, &ctx->display_ctx, " Err: unknown escape sequence: \\E%s\n", (char *)&key_buf[1]);
                trans_flag = false;
                Ident_flag = false;
                Az_Memzero(key_buf, 7);
                key_size = 0;
            }
            else//这里识别转义序列
            {
                key = __escape_seq(key_buf, key_size, false);
                if (key >= 0 && key != AZ_UNKNOWN_KEY)
                {
                    Ident_flag = true;
                    goto TRANS_FLAG;
                }
            }
        }
        else//输入功能键
        {
            az_cmd cmd = NULL;
            az_utf8_node aaaaa = NULL;
            size_t loop = 0;
        TRANS_FLAG:
            switch (key)
            {
            case AZ_ASCII_ESCAPE_KEY://esc
                if (Ident_flag)
                {
                    //__az_win_printf(ctx->mp, &ctx->display_ctx, " Esc key\n");
                    __beep();
                }
                else
                {
                    trans_flag = true;
                    key_buf[0] = key;
                    key_buf[1] = '\0';
                    key_size = 1;
                }
                break;
            case AZ_ASCII_TAB_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Tab key\n");
                if (com_len > 0 && !multiline_flag)
                {
                    int num = 0;
                    char **cmd = NULL;

                    num = az_find_cmd(ctx->mp, az_client_cmd, az_utf8_tostr(input, 0), &cmd);
                    if (num <= 0)
                        __beep();
                    else if (num == 1)
                    {
                        az_utf8 tmp_cmd = az_utf8_create(ctx->mp, 0, cmd[0]);

                        az_utf8_strcatstr(input, tmp_cmd, com_len);
                        az_utf8_strcatwrd(input, (uint8_t *)" ");
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, com_len));
                        com_len = az_utf8_len(input, 0);
                        com_c_index = com_len;

                        az_utf8_free(&tmp_cmd);
                    }
                    else
                    {
                        if (tab_flag)
                        {
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
                            __az_show_cmd_list(ctx, cmd, num);
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(prefix, 0));
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, 0));
                        }
                        else
                            tab_flag = true;
                    }

                    if (cmd != NULL)
                        az_mpfree(ctx->mp, (void **)&cmd);
                }
                else if (!multiline_flag)
                {
                    int num = 0;
                    char **cmd = NULL;

                    num = __az_cmd_to_strary(ctx, az_client_cmd, &cmd);
                    if (num > 0)
                    {
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
                        __az_show_cmd_list(ctx, cmd, num);
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(prefix, 0));
                    }
                    else
                        __beep();

                    if (cmd != NULL)
                        az_mpfree(ctx->mp, (void **)&cmd);
                }
                else
                    __beep();
                break;
            case AZ_ASCII_ENTER_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Enter key\n");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");

#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                if (ctx->login_stat == AZ_FTP_OKLOGIN && com_len > 0)
#else
                if(com_len > 0)
#endif
                {
                    const char *end_flag = az_utf8_get_wrd(input, com_len - 1);
                    if (*end_flag == '\\')
                    {
                        multiline_flag = true;
                        az_utf8_del_nd(input, com_len - 1);
                    }
                    else
                        multiline_flag = false;
                }
#if defined TEST_PARSER_CMD || defined TEST_INPUT
                __az_win_printf(ctx->mp, &ctx->display_ctx, "input: %s (%d)\n", az_utf8_tostr(input, 0), az_utf8_len(input, 0));
#endif
                az_utf8_insert(parser_buf, az_utf8_len(parser_buf, 0), input, 0);
                az_utf8_clear(input);
                com_len = 0;
                com_c_index = 0;
                tab_flag = false;

                if (!multiline_flag)
                {
                    const char *str = NULL;
#ifdef TEST_INPUT
                    __az_win_printf(ctx->mp, &ctx->display_ctx, " Cmd: %s (%d)\n", az_utf8_tostr(parser_buf, 0), az_utf8_len(parser_buf, 0));
                    _insert_histroy(ctx->histroy, parser_buf);
#elif defined TEST_PARSER_CMD
                    __az_win_printf(ctx->mp, &ctx->display_ctx, " Cmd: %s\n", az_utf8_tostr(parser_buf, 0));
                    if (az_utf8_len(parser_buf, 0) > 0)
                    {
                        cmd = az_parser_cmd(ctx->mp, az_client_cmd, az_client_alias, az_utf8_tostr(parser_buf, 0));
                        if (cmd == NULL)
                        {
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "Command parser err!\n");
                            __beep();
                        }
                        else
                        {
                            int loop = 0;

                            __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd index: %d\n", cmd->index);
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd name: %s\n", cmd->cmd_name);
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd val: %d\n", cmd->parse_val);
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd argc: %d\n", cmd->argc);
                            if (cmd->argc > 0)
                            {
                                for (loop = 0; loop < cmd->argc; loop++)
                                    __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd [%d] argv: %s\n", loop, cmd->argv[loop]);
                            }
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd opt num: %d\n", cmd->opt_num);
                            if (cmd->opt_num > 0)
                            {
                                for (loop = 0; loop < cmd->opt_num; loop++)
                                {
                                    __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd opt[%d] val: %c\n", loop, cmd->opt[loop].val);
                                    if (cmd->opt[loop].param != NULL)
                                        __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd opt[%d] par: %s\n", loop, cmd->opt[loop].param);
                                }
                            }
                            __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd err opt num: %d\n", cmd->err_num);
                            if (cmd->err_num > 0)
                            {
                                for (loop = 0; loop < cmd->err_num; loop++)
                                {
                                    __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd err opt[%d] val: %c\n", loop, cmd->err_opt[loop].val);
                                    if (cmd->err_opt[loop].param != NULL)
                                        __az_win_printf(ctx->mp, &ctx->display_ctx, "cmd err opt[%d] par: %s\n", loop, cmd->err_opt[loop].param);
                                }
                            }
                        }
                        _insert_histroy(ctx->histroy, parser_buf);
                    }
#else
                    if (az_utf8_len(parser_buf, 0) > 0 && ctx->login_stat == AZ_FTP_NOLOGIN)
                    {
                        ctx->user_name = (char *)az_mpcalloc(ctx->mp, az_utf8_size(parser_buf, 0) + 1);
                        if (ctx->user_name == NULL)
                            break;//??????
                        az_strncpy(ctx->user_name, az_utf8_size(parser_buf, 0) + 1, az_utf8_tostr(parser_buf, 0), az_utf8_size(parser_buf, 0));
                        ctx->login_stat = AZ_FTP_DEALLOGIN;
                    }
                    else if (ctx->login_stat == AZ_FTP_DEALLOGIN)
                    {
                        if (az_utf8_len(parser_buf, 0) > 0)
                        {
                            ctx->pwd = (char *)az_mpcalloc(ctx->mp, az_utf8_size(parser_buf, 0) + 1);
                            if (ctx->pwd == NULL)
                                break;//??????
                            az_strncpy(ctx->pwd, az_utf8_size(parser_buf, 0) + 1, az_utf8_tostr(parser_buf, 0), az_utf8_size(parser_buf, 0));
                        }
                        if (az_ftp_client_login(ctx->ftp_client, ctx->user_name, ctx->pwd, NULL) == AZ_OK)
                        {
                            char file_name[128] = { 0 };
                            ctx->login_stat = AZ_FTP_OKLOGIN;
                            __az_win_printf(ctx->mp, &ctx->display_ctx, " Login success.\n");

                            if (ctx->histroy != NULL)
                                _free_histroy_ctx(&ctx->histroy);
                            snprintf(file_name, 128, "%s_%s", CMD_HISTROY_CACHE_NAME, ctx->user_name);
                            ctx->histroy = _create_histroy_ctx(CMD_HISTROY_CACHE_PATH, file_name);
                            if (ctx->histroy == NULL)
                                __az_win_printf(ctx->mp, &ctx->display_ctx, " create histroy cache failed.\n");
                        }
                        else
                        {
                            ctx->login_stat = AZ_FTP_NOLOGIN;
                            __az_win_printf(ctx->mp, &ctx->display_ctx, " User name or password err!\n");
                        }
                    }
                    else if (az_utf8_len(parser_buf, 0) > 0 && ctx->login_stat == AZ_FTP_OKLOGIN)
                    {
                        const char *ret = az_exec_cmd(ctx->mp, az_client_cmd, az_client_alias, az_utf8_tostr(parser_buf, 0));
                        if (ret != NULL)
                            __az_win_printf(ctx->mp, &ctx->display_ctx, " Exec cmd err: %s\n", ret);
                        _insert_histroy(ctx->histroy, parser_buf);
                    }
#endif
                    az_utf8_clear(parser_buf);
                    histroy_index = _histroy_size(ctx->histroy);
                }

#if defined TEST_PARSER_CMD || defined TEST_INPUT
                if (multiline_flag)
                    az_utf8_format(prefix, 0, "  -->> ");
                else
                    az_utf8_format(prefix, 0, "test cmd>> ");
#else
                if (ctx->login_stat == AZ_FTP_OKLOGIN && multiline_flag)
                    az_utf8_format(prefix, 0, "  -->> ");
                else if(ctx->login_stat == AZ_FTP_OKLOGIN)
                    az_utf8_format(prefix, 0, "$-%s@ftpc %s>> ", ctx->user_name, __az_get_last_dir(ctx));
                else if (ctx->login_stat == AZ_FTP_DEALLOGIN)
                    az_utf8_format(prefix, 0, "password: ");
                else
                    az_utf8_format(prefix, 0, "login as: ");
#endif
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(prefix, 0));
                break;
            case AZ_DOWN_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Down key\n");
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                if (ctx->login_stat == AZ_FTP_OKLOGIN && !multiline_flag)
#else
                if (!multiline_flag)
#endif
                {
                    const az_utf8_t *hist = NULL;

                    if (ctx->histroy == NULL || histroy_index == _histroy_size(ctx->histroy))
                    {
                        __beep();
                        break;
                    }
                    histroy_index++;

                    while (com_c_index > 0)
                    {
                        az_utf8_node tmp_word = NULL;
                        com_c_index--;
                        tmp_word = az_utf8_get(input, com_c_index);
                        ctx->display_ctx.cursor_y -= tmp_word->print_width;
                        if (ctx->display_ctx.cursor_y < 0)
                        {
                            int line = 0;
                            int offset = 0;

                            ctx->display_ctx.cursor_x--;
                            offset = az_utf8_pwidth(input, 0) - az_utf8_pwidth(input, com_c_index) + az_utf8_pwidth(prefix, 0);
                            line = offset / __get_term_cols();
                            if (line == 0)
                            {
                                if (__get_term_cols() - offset <= 1)
                                    ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                                else
                                    ctx->display_ctx.cursor_y = offset;
                            }
                            else
                            {
                                if (__get_term_cols() - (offset - line*__get_term_cols()) <= 1)
                                    ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                                else
                                    ctx->display_ctx.cursor_y = offset - line*__get_term_cols();
                            }
                        }
                    }
                    az_utf8_clear(input);
                    com_len = 0;
                    tab_flag = false;
                    __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                    __delete_end();

                    hist = _get_histroy(ctx->histroy, histroy_index);
                    if (hist != NULL)
                    {
                        az_utf8_copy(input, 0, (az_utf8)hist, 0);
                        com_len = az_utf8_len(input, 0);
                        com_c_index = com_len;
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, 0));
                    }
                    else
                        __beep();
                }
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                else
                    __beep();
#endif
                break;
            case AZ_UP_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Up key\n");
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                if (ctx->login_stat == AZ_FTP_OKLOGIN && !multiline_flag)
#else
                if (!multiline_flag)
#endif
                {
                    const az_utf8_t *hist = NULL;

                    if (ctx->histroy == NULL || histroy_index == 0)
                    {
                        __beep();
                        break;
                    }
                    histroy_index--;

                    while (com_c_index > 0)
                    {
                        az_utf8_node tmp_word = NULL;
                        com_c_index--;
                        tmp_word = az_utf8_get(input, com_c_index);
                        ctx->display_ctx.cursor_y -= tmp_word->print_width;
                        if (ctx->display_ctx.cursor_y < 0)
                        {
                            int line = 0;
                            int offset = 0;

                            ctx->display_ctx.cursor_x--;
                            offset = az_utf8_pwidth(input, 0) - az_utf8_pwidth(input, com_c_index) + az_utf8_pwidth(prefix, 0);
                            line = offset / __get_term_cols();
                            if (line == 0)
                            {
                                if (__get_term_cols() - offset <= 1)
                                    ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                                else
                                    ctx->display_ctx.cursor_y = offset;
                            }
                            else
                            {
                                if (__get_term_cols() - (offset - line*__get_term_cols()) <= 1)
                                    ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                                else
                                    ctx->display_ctx.cursor_y = offset - line*__get_term_cols();
                            }
                        }
                    }
                    az_utf8_clear(input);
                    com_len = 0;
                    tab_flag = false;
                    __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                    __delete_end();

                    hist = _get_histroy(ctx->histroy, histroy_index);
                    if (hist != NULL)
                    {
                        az_utf8_copy(input, 0, (az_utf8)hist, 0);
                        com_len = az_utf8_len(input, 0);
                        com_c_index = com_len;
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, 0));
                    }
                    else
                        __beep();
                }
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                else
                    __beep();
#endif
                break;
            case AZ_LEFT_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Left key\n");
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                if (ctx->login_stat != AZ_FTP_DEALLOGIN)
#endif
                {
                    az_utf8_node tmp_word = NULL;
                    if (com_c_index - 1 < 0)
                    {
                        __beep();
                        break;
                    }
                    com_c_index--;
                    tab_flag = false;
                    tmp_word = az_utf8_get(input, com_c_index);
                    ctx->display_ctx.cursor_y -= tmp_word->print_width;
                    if (ctx->display_ctx.cursor_y < 0)
                    {
                        int line = 0;
                        int offset = 0;

                        ctx->display_ctx.cursor_x--;
                        offset = az_utf8_pwidth(input, 0) - az_utf8_pwidth(input, com_c_index) + az_utf8_pwidth(prefix, 0);
                        line = offset / __get_term_cols();
                        if (line == 0)
                        {
                            if (__get_term_cols() - offset <= 1)
                                ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                            else
                                ctx->display_ctx.cursor_y = offset;
                        }
                        else
                        {
                            if (__get_term_cols() - (offset - line*__get_term_cols()) <= 1)
                                ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                            else
                                ctx->display_ctx.cursor_y = offset - line*__get_term_cols();
                        }
                    }
                    __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                }
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                else
                    __beep();
#endif
                break;
            case AZ_RIGHT_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Right key\n");
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                if (ctx->login_stat != AZ_FTP_DEALLOGIN)
#endif
                {
                    az_utf8_node tmp_word = NULL;
                    if (com_c_index == com_len)
                    {
                        __beep();
                        break;
                    }
                    tmp_word = az_utf8_get(input, com_c_index);
                    ctx->display_ctx.cursor_y += tmp_word->print_width;
                    tmp_word = az_utf8_get(input, com_c_index + 1);
                    if (ctx->display_ctx.cursor_y >= __get_term_cols())
                    {
                        ctx->display_ctx.cursor_x++;
                        ctx->display_ctx.cursor_y = 0;
                    }
                    else if (tmp_word != NULL && ctx->display_ctx.cursor_y + tmp_word->print_width > __get_term_cols())
                    {
                        ctx->display_ctx.cursor_x++;
                        ctx->display_ctx.cursor_y = 0;
                    }
                    __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                    com_c_index++;
                    tab_flag = false;
                }
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                else
                    __beep();
#endif
                break;
            case AZ_HOME_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Home key\n");
                __beep();
                break;
            case AZ_ASCII_BACKSPACE_KEY:
            case AZ_BACKSPACE_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " BackSpace key\n");
                {
                    az_utf8_node tmp_word = NULL;
                    if (com_c_index == 0)
                    {
                        __beep();
                        break;
                    }

                    com_c_index--;
                    tmp_word = az_utf8_get(input, com_c_index);
                    ctx->display_ctx.cursor_y -= tmp_word->print_width;
                    if (ctx->display_ctx.cursor_y < 0)
                    {
                        int line = 0;
                        int offset = 0;

                        ctx->display_ctx.cursor_x--;
                        offset = az_utf8_pwidth(input, 0) - az_utf8_pwidth(input, com_c_index) + az_utf8_pwidth(prefix, 0);
                        line = offset / __get_term_cols();
                        if (line == 0)
                        {
                            if (__get_term_cols() - offset <= 1)
                                ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                            else
                                ctx->display_ctx.cursor_y = offset;
                        }
                        else
                        {
                            if (__get_term_cols() - (offset - line*__get_term_cols()) <= 1)
                                ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                            else
                                ctx->display_ctx.cursor_y = offset - line*__get_term_cols();
                        }
                    }
                    __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);

                    if (com_c_index + 1 == com_len)
                        __delete_key(tmp_word->print_width);
                    else
                    {
                        int old_x = ctx->display_ctx.cursor_x;
                        int old_y = ctx->display_ctx.cursor_y;
                        __delete_end();
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, com_c_index + 1));
                        ctx->display_ctx.cursor_x = old_x;
                        ctx->display_ctx.cursor_y = old_y;
                        __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                    }

                    az_utf8_del_nd(input, com_c_index);
                    com_len--;
                    tab_flag = false;
                }
                break;
            case AZ_ASCII_DELETE_KEY:
            case AZ_DELETE_C_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Delete key\n");
                {
                    if (com_c_index == com_len)
                    {
                        __beep();
                        break;
                    }
                    __delete_end();
                    if (com_c_index + 1 < com_len)
                    {
                        int old_x = ctx->display_ctx.cursor_x;
                        int old_y = ctx->display_ctx.cursor_y;
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, com_c_index + 1));
                        ctx->display_ctx.cursor_x = old_x;
                        ctx->display_ctx.cursor_y = old_y;
                        __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                    }
                    az_utf8_del_nd(input, com_c_index);
                    com_len--;
                    tab_flag = false;
                }
                break;
            case AZ_ASCII_CTRL_C_KEY:
                __az_win_printf(ctx->mp, &ctx->display_ctx, "\n Ctrl^C, exit\n");
                az_atomic_set(&ctx->run, AZ_FALSE);
                break;
            case AZ_ASCII_CTRL_D_KEY:
                __az_win_printf(ctx->mp, &ctx->display_ctx, "\n Ctrl^D, logout\n");
                az_atomic_set(&ctx->run, AZ_FALSE);
                break;
            case AZ_ASCII_CTRL_K_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, "\n Ctrl^K\n");
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                if (ctx->login_stat == AZ_FTP_OKLOGIN)
#endif
                {
                    if (com_c_index == com_len)
                    {
                        __beep();
                        break;
                    }
                    az_utf8_del_len(input, com_c_index, az_utf8_len(input, 0) - com_c_index);
                    __delete_end();
                    com_len = az_utf8_len(input, 0);
                    com_c_index = com_len;
                    tab_flag = false;
                }
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                else
                    __beep();
#endif
                break;
            case AZ_ASCII_CTRL_L_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, "\n Ctrl^L\n");
                {
                    int old_y = 0;
                    old_y = ctx->display_ctx.cursor_y;
                    __clear();
                    ctx->display_ctx.cursor_x = 0;
                    ctx->display_ctx.cursor_y = 0;
#if defined TEST_PARSER_CMD || defined TEST_INPUT
                    if (multiline_flag)
                        az_utf8_format(prefix, 0, "  -->> ");
                    else
                        az_utf8_format(prefix, 0, "test cmd>> ");
#else
                    if (ctx->login_stat == AZ_FTP_OKLOGIN && multiline_flag)
                        az_utf8_format(prefix, 0, "  -->> ");
                    else if(ctx->login_stat == AZ_FTP_OKLOGIN)
                        az_utf8_format(prefix, 0, "$-%s@ftpc %s>> ", ctx->user_name, __az_get_last_dir(ctx));
                    else if (ctx->login_stat == AZ_FTP_DEALLOGIN)
                        az_utf8_format(prefix, 0, "password: ");
                    else
                        az_utf8_format(prefix, 0, "login as: ");
#endif
                    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(prefix, 0));
                    if (com_len > 0)
                    {
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, 0));
                        ctx->display_ctx.cursor_y = old_y;
                        __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                    }
                    else
                    {
                        az_utf8_clear(input);
                        com_len = 0;
                        com_c_index = 0;
                        tab_flag = false;
                    }
                }
                break;
            case AZ_ASCII_CTRL_U_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, "\n Ctrl^U\n");
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                if (ctx->login_stat == AZ_FTP_OKLOGIN)
#endif
                {
                    int del_len = 0;
                    int old_x = 0;
                    int old_y = 0;

                    if (com_c_index == 0)
                    {
                        __beep();
                        break;
                    }

                    while (com_c_index > 0)
                    {
                        az_utf8_node tmp_word = NULL;
                        com_c_index--;
                        tmp_word = az_utf8_get(input, com_c_index);
                        ctx->display_ctx.cursor_y -= tmp_word->print_width;
                        if (ctx->display_ctx.cursor_y < 0)
                        {
                            int line = 0;
                            int offset = 0;

                            ctx->display_ctx.cursor_x--;
                            offset = az_utf8_pwidth(input, 0) - az_utf8_pwidth(input, com_c_index) + az_utf8_pwidth(prefix, 0);
                            line = offset / __get_term_cols();
                            if (line == 0)
                            {
                                if (__get_term_cols() - offset <= 1)
                                    ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                                else
                                    ctx->display_ctx.cursor_y = offset;
                            }
                            else
                            {
                                if (__get_term_cols() - (offset - line*__get_term_cols()) <= 1)
                                    ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                                else
                                    ctx->display_ctx.cursor_y = offset - line*__get_term_cols();
                            }
                        }
                        del_len++;
                    }
                    az_utf8_del_len(input, 0, del_len);
                    com_len -= del_len;
                    __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                    __delete_end();
                    if (com_len > 0)
                    {
                        old_x = ctx->display_ctx.cursor_x;
                        old_y = ctx->display_ctx.cursor_y;
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(input, 0));
                        ctx->display_ctx.cursor_x = old_x;
                        ctx->display_ctx.cursor_y = old_y;
                        __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                    }
                    tab_flag = false;
                }
#if !defined TEST_PARSER_CMD && !defined TEST_INPUT
                else
                    __beep();
#endif
                break;
            case AZ_UNKNOWN_KEY:
#if defined TEST_PARSER_CMD || defined TEST_INPUT
                __az_win_printf(ctx->mp, &ctx->display_ctx, " Err: unknown escape sequence: \\E%s\n", (char *)&key_buf[1]);
#else
                __beep();
#endif
                break;
            default:
#if defined TEST_PARSER_CMD || defined TEST_INPUT
                __az_win_printf(ctx->mp, &ctx->display_ctx, " Unknown key: %d\n", key);
#else
                __beep();
#endif
                break;
            }

            if (trans_flag && Ident_flag)//已经识别了转义序列的功能键
            {
                trans_flag = false;
                Ident_flag = false;
                Az_Memzero(key_buf, 7);
                key_size = 0;
            }
        }
        last_push_key = push_key;
    }

    return 0;
}

static az_ret __get_cursor_position(int *line, int *col)
{
    int x = 0;
    int y = 0;
    printf("\033[6n");
    fflush(stdout);

    az_msleep(100);

    if (scanf("\033[%d;%dR", &x, &y) != 2)
        return AZ_ERROR;

    *line = x - 1;
    *col = y - 1;

    return AZ_OK;
}

static void __set__cursor_position(int line, int col)
{
    char *cmd = NULL;
    char *exec_cmd = NULL;

    cmd = tigetstr("cup");
    exec_cmd = tparm(cmd, line, col);
    putp(exec_cmd);
}

static void __backspace_key(int width)
{
    char *cmd = NULL;
    char *exec_cmd = NULL;

    cmd = tigetstr("cub");
    exec_cmd = tparm(cmd, width);
    putp(exec_cmd);
    cmd = tigetstr("dch");
    exec_cmd = tparm(cmd, width);
    putp(exec_cmd);
}

static void __delete_key(int width)
{
    char *cmd = NULL;
    char *exec_cmd = NULL;

    cmd = tigetstr("dch");
    exec_cmd = tparm(cmd, width);
    putp(exec_cmd);
}

static void __delete_end(void)
{
    char *cmd = NULL;
    cmd = tigetstr("ed");
    putp(cmd);
}

static void __delete_lines(int num)
{
    char* cmd = NULL;
    char* exec_cmd = NULL;

    cmd = tigetstr("dl");
    exec_cmd = tparm(cmd, num);
    putp(exec_cmd);
}

static void __eraser_line(int line)
{
    char* cmd = NULL;
    __set__cursor_position(line, 0);
    cmd = tigetstr("el");
    putp(cmd);
}

static void __beep(void)
{
    char *cmd = NULL;
    cmd = tigetstr("bel");
    putp(cmd);
}

static void __clear(void)
{
    char *cmd = NULL;
    char *exec_cmd = NULL;

    cmd = tigetstr("clear");
    putp(cmd);
}

static int __escape_seq(uint8_t data[4], int data_size, bool timeout)
{
    az_esckey key = AZ_UNKNOWN_KEY;

    if (data == NULL || data_size < 1)
        return -1;
    if (data[0] != AZ_ASCII_ESCAPE_KEY)
        return -1;
    if (!timeout && data_size == 1)
        return AZ_UNKNOWN_KEY;

    switch (data_size)
    {
    case 1:
        key = AZ_ESCAPE_KEY;
        break;
    case 2:
        break;
    case 3:
        if (data[1] == 91 && data[2] == 66)
            key = AZ_DOWN_KEY;
        else if (data[1] == 91 && data[2] == 65)
            key = AZ_UP_KEY;
        else if (data[1] == 91 && data[2] == 68)
            key = AZ_LEFT_KEY;
        else if (data[1] == 91 && data[2] == 67)
            key = AZ_RIGHT_KEY;
        else if (data[1] == 79 && data[2] == 80)
            key = AZ_F1_KEY;
        else if (data[1] == 79 && data[2] == 81)
            key = AZ_F2_KEY;
        else if (data[1] == 79 && data[2] == 82)
            key = AZ_F3_KEY;
        else if (data[1] == 79 && data[2] == 83)
            key = AZ_F4_KEY;
        break;
    case 4:
        if (data[1] == 91 && data[2] == 49 && data[3] == 126)
            key = AZ_HOME_KEY;
        else if (data[1] == 91 && data[2] == 51 && data[3] == 126)
            key = AZ_DELETE_C_KEY;
        else if (data[1] == 91 && data[2] == 53 && data[3] == 126)
            key = AZ_PREV_PAGE_KEY;
        else if (data[1] == 91 && data[2] == 54 && data[3] == 126)
            key = AZ_NEXT_PAGE_KEY;
        break;
    case 5:
        if (data[1] == 91 && data[2] == 49 && data[3] == 53 && data[4] == 126)
            key = AZ_F5_KEY;
        else if (data[1] == 91 && data[2] == 49 && data[3] == 55 && data[4] == 126)
            key = AZ_F6_KEY;
        else if (data[1] == 91 && data[2] == 49 && data[3] == 56 && data[4] == 126)
            key = AZ_F7_KEY;
        else if (data[1] == 91 && data[2] == 49 && data[3] == 57 && data[4] == 126)
            key = AZ_F8_KEY;
        else if (data[1] == 91 && data[2] == 50 && data[3] == 48 && data[4] == 126)
            key = AZ_F9_KEY;
        else if (data[1] == 91 && data[2] == 50 && data[3] == 49 && data[4] == 126)
            key = AZ_F10_KEY;
        else if (data[1] == 91 && data[2] == 50 && data[3] == 51 && data[4] == 126)
            key = AZ_F11_KEY;
        else if (data[1] == 91 && data[2] == 50 && data[3] == 52 && data[4] == 126)
            key = AZ_F12_KEY;
        break;
    default:
        return -1;
    }
    return key;
}

static inline int __get_term_cols(void)
{
#if defined __az_windows_32__ || defined __az_windows_64__
    return 0;
#else
    struct winsize size;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    return size.ws_col;
#endif
}

static inline int __get_term_lines(void)
{
#if defined __az_windows_32__ || defined __az_windows_64__
    return 0;
#else
    struct winsize size;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    return size.ws_row;
#endif
}

static void __az_win_printf(az_memp pool, az_display_ctx display_ctx, const char *fmt, ...)
{
    int loop = 0;
    char *str = NULL;
    int str_len = 0;
    int print_len = 0;
    char tmp_flag = 0;
    va_list ap;

    if (pool == NULL
        || display_ctx->cursor_x < 0 || display_ctx->cursor_x >= __get_term_lines()
        || display_ctx->cursor_y < 0 || display_ctx->cursor_y >= __get_term_cols()
        || fmt == NULL || *fmt == '\0')
        return;

    va_start(ap, fmt);
    str_len = vsnprintf(str, 0, fmt, ap);
    va_end(ap);
    if (str_len <= 0)
        return;
    str = (char *)az_mpcalloc(pool, str_len + 1);
    if (str == NULL)
        return;
    va_start(ap, fmt);
    vsnprintf(str, str_len + 1, fmt, ap);
    va_end(ap);

    while (print_len < str_len)
    {
        for (; loop < str_len; loop++)
        {
            if (str[loop] == '\t' || str[loop] == '\r' || str[loop] == '\n')
            {
                tmp_flag = str[loop];
                str[loop] = '\0';
                break;
            }
        }

        if (print_len < loop)
        {
            size_t index = 0;
            az_utf8 tmp = NULL;
            size_t count = 0;
            az_utf8_node node = NULL;
            tmp = az_utf8_create(pool, 0, &str[print_len]);
            if (tmp == NULL)
                print_len += az_strlen(&str[print_len]);
            else
            {
                count = az_utf8_len(tmp, 0);
                while (index < count)
                {
                    node = az_utf8_get(tmp, index);
                    if (display_ctx->cursor_y + node->print_width > __get_term_cols())
                    {
                        display_ctx->cursor_x++;
                        if (display_ctx->cursor_x == AZ_COM_WIN_HEIGHT)
                        {
                            display_ctx->cursor_x = AZ_COM_WIN_HEIGHT - 1;
                            printf("\n");
                        }
                        display_ctx->cursor_y = 0;
                    }
                    __set__cursor_position(display_ctx->cursor_x, display_ctx->cursor_y);
                    printf("%s", (char *)node->data);
                    display_ctx->cursor_y += node->print_width;
                    if (display_ctx->cursor_y == __get_term_cols())
                    {
                        display_ctx->cursor_x++;
                        if (display_ctx->cursor_x == AZ_COM_WIN_HEIGHT)
                        {
                            display_ctx->cursor_x = AZ_COM_WIN_HEIGHT - 1;
                            printf("\n");
                        }
                        display_ctx->cursor_y = 0;
                        __set__cursor_position(display_ctx->cursor_x, display_ctx->cursor_y);
                    }
                    index++;
                }
                print_len += az_utf8_size(tmp, 0);
                az_utf8_free(&tmp);
            }
        }

        if (tmp_flag == '\t')
        {
            if (display_ctx->cursor_y > __get_term_cols() - 5)
            {
                display_ctx->cursor_x++;
                if (display_ctx->cursor_x == AZ_COM_WIN_HEIGHT)
                {
                    display_ctx->cursor_x = AZ_COM_WIN_HEIGHT - 1;
                    printf("\n");
                }
                display_ctx->cursor_y = 0;
            }
            else
                display_ctx->cursor_y += (4 - display_ctx->cursor_y % 4);
        }
        else if (tmp_flag == '\r')
            display_ctx->cursor_y = 0;
        else if (tmp_flag == '\n')
        {
            display_ctx->cursor_x++;
            if (display_ctx->cursor_x == AZ_COM_WIN_HEIGHT)
            {
                display_ctx->cursor_x = AZ_COM_WIN_HEIGHT - 1;
                printf("\n");
            }
            display_ctx->cursor_y = 0;
        }
        if (tmp_flag != 0)
        {
            tmp_flag = 0;
            print_len++;
        }
        loop++;
    }

    az_mpfree(pool, (void **)&str);
    fflush(stdout);
}

static az_ret az_client_clear(az_main_ctx ctx, const az_cmd cmd)
{
    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    __clear();
    ctx->display_ctx.cursor_x = 0;
    ctx->display_ctx.cursor_y = 0;

    return AZ_OK;
}

static az_ret az_client_login(az_main_ctx ctx, const az_cmd cmd)
{
    char *user = NULL;
    char *pwd = NULL;
    char *tmp_user = NULL;
    char *tmp_pwd = NULL;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    if (!az_cmd_has_opt(cmd, 'u', &user))
        return AZ_ERROR;
    if (az_strcmp(user, ctx->user_name) == 0)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " User [%s] is already logged.\n", ctx->user_name);
        return AZ_OK;
    }
    az_cmd_has_opt(cmd, 'p', &pwd);

    tmp_user = (char *)az_mpcalloc(ctx->mp, az_strlen(user) + 1);
    if (tmp_user == NULL)
        return AZ_ERROR;
    if (pwd != NULL)
    {
        tmp_pwd = (char *)az_mpcalloc(ctx->mp, az_strlen(pwd) + 1);
        if (tmp_pwd == NULL)
        {
            az_mpfree(ctx->mp, (void **)&tmp_user);
            return AZ_ERROR;
        }
    }

    if (az_ftp_client_login(ctx->ftp_client, user, pwd, NULL) == AZ_OK)
    {
        char *tmp = NULL;
        char file_name[128] = { 0 };

        ctx->login_stat = AZ_FTP_OKLOGIN;
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Login success.\n");
        if (ctx->histroy != NULL)
            _free_histroy_ctx(&ctx->histroy);
        snprintf(file_name, 128, "%s_%s", CMD_HISTROY_CACHE_NAME, ctx->user_name);
        ctx->histroy = _create_histroy_ctx(CMD_HISTROY_CACHE_PATH, file_name);
        if (ctx->histroy == NULL)
            __az_win_printf(ctx->mp, &ctx->display_ctx, " create histroy cache failed.\n");

        az_mpfree(ctx->mp, (void **)&ctx->user_name);
        if (ctx->pwd != NULL)
            az_mpfree(ctx->mp, (void **)&ctx->pwd);
        ctx->user_name = tmp_user;
        az_strncpy(ctx->user_name, az_strlen(user) + 1, user, az_strlen(user));
        if (pwd != NULL)
        {
            ctx->pwd = tmp_pwd;
            az_strncpy(ctx->pwd, az_strlen(pwd) + 1, pwd, az_strlen(pwd));
        }
    }
    else
    {
        ctx->login_stat = AZ_FTP_NOLOGIN;
        __az_win_printf(ctx->mp, &ctx->display_ctx, " User name or password err!\n");
        if (tmp_user != NULL)
            az_mpfree(ctx->mp, (void **)&tmp_user);
        if (tmp_pwd != NULL)
            az_mpfree(ctx->mp, (void **)&tmp_pwd);
    }

    return AZ_OK;
}

static az_ret az_client_logout(az_main_ctx ctx, const az_cmd cmd)
{
    if (ctx == NULL)
        return AZ_ERROR;

    if (ctx->login_stat == AZ_FTP_OKLOGIN)
    {
        if (az_ftp_client_logout(ctx->ftp_client) == AZ_OK)
        {
            ctx->login_stat = AZ_FTP_NOLOGIN;
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Logout ok\n");
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Exit\n");
            az_msleep(500);
            az_atomic_set(&ctx->run, AZ_FALSE);
        }
        else
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Logout failed!\n");
    }
    else
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Exit\n");
        az_msleep(500);
        az_atomic_set(&ctx->run, AZ_FALSE);
    }

    return AZ_OK;
}

static az_ret az_client_pwd(az_main_ctx ctx, const az_cmd cmd)
{
    const char *pwd = NULL;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    pwd = az_ftp_client_pwd(ctx->ftp_client);
    if (pwd == NULL)
        return AZ_ERROR;
    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s\n", pwd);
    return AZ_OK;
}

static az_ret az_client_cd(az_main_ctx ctx, const az_cmd cmd)
{
    static char *last_dir = NULL;
    const char *pwd = NULL;
    char *tmp_last = last_dir;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    //__az_win_printf(ctx->mp, ctx->display_ctx.com_win, &ctx->display_ctx.cursor_x, &ctx->display_ctx.cursor_y, "1---last: %s\n", last_dir);
    //__az_refresh_win(&ctx->display_ctx, ctx->display_ctx.com_win);

    pwd = az_ftp_client_pwd(ctx->ftp_client);
    if (pwd == NULL)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, "pwd failed\n");
        return AZ_OK;
    }
    if (az_strcmp(pwd, last_dir) != 0)
    {
        tmp_last = (char *)az_mpcalloc(ctx->mp, az_strlen(pwd) + 1);
        if (tmp_last == NULL)
        {
            __az_win_printf(ctx->mp, &ctx->display_ctx, "alloc last dir cache failed\n");
            return AZ_OK;
        }
        az_strncpy(tmp_last, az_strlen(pwd) + 1, pwd, az_strlen(pwd));
    }

    if (cmd->argc == 0)
    {
        if (az_strcmp(pwd, "/") != 0 && az_ftp_client_cwd(ctx->ftp_client, "/") != AZ_OK)
        {
            __az_win_printf(ctx->mp, &ctx->display_ctx, "cd to [/] failed\n");
            goto CWD_ERR;
        }
    }
    else if (cmd->argc > 0)
    {
        if (az_strcmp(cmd->argv[0], ".") == 0)
        {
        }
        else if(az_strcmp(cmd->argv[0], "-") == 0)
        {
            if (az_strcmp(pwd, last_dir) != 0 && az_ftp_client_cwd(ctx->ftp_client, last_dir) != AZ_OK)
            {
                __az_win_printf(ctx->mp, &ctx->display_ctx, "cd to [%s] failed\n", last_dir);
                goto CWD_ERR;
            }
        }
        else if (az_strcmp(cmd->argv[0], "..") == 0)
        {
            if (az_ftp_client_cdup(ctx->ftp_client) != AZ_OK)
            {
                __az_win_printf(ctx->mp, &ctx->display_ctx, "cd to [..] failed\n");
                goto CWD_ERR;
            }
        }
        else if (az_strcmp(cmd->argv[0], pwd) != 0)
        {
            if (az_ftp_client_cwd(ctx->ftp_client, cmd->argv[0]) != AZ_OK)
            {
                __az_win_printf(ctx->mp, &ctx->display_ctx, "cd to [%s] failed\n", cmd->argv[0]);
                goto CWD_ERR;
            }
        }
    }
    if (tmp_last != last_dir)
    {
        az_mpfree(ctx->mp, (void **)&last_dir);
        last_dir = tmp_last;
    }
    //__az_win_printf(ctx->mp, ctx->display_ctx.com_win, &ctx->display_ctx.cursor_x, &ctx->display_ctx.cursor_y, "2---last: %s\n", last_dir);
    //__az_refresh_win(&ctx->display_ctx, ctx->display_ctx.com_win);
    return AZ_OK;
CWD_ERR:
    az_mpfree(ctx->mp, (void **)&tmp_last);
    return AZ_OK;
}

static az_ret az_client_mkdir(az_main_ctx ctx, const az_cmd cmd)
{
    int loop = 0;
    az_ret flag = 0;
    bool round = false;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    if (cmd->argc == 0)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Missing path to create\n");
        return AZ_OK;
    }

    round = az_cmd_has_opt(cmd, 'p', NULL);

    for (loop = 0; loop < cmd->argc; loop++)
    {
        if (round)
        {
            int loop2 = 0;
            int len = az_strlen(cmd->argv[loop]);

            if (cmd->argv[loop][len - 1] == '/')
                cmd->argv[loop][len - 1] = '\0';

            for (loop2 = 0; loop2 < len; loop2++)
            {
                if (cmd->argv[loop][loop2] != '/')
                    continue;
                cmd->argv[loop][loop2] = '\0';
                flag = az_ftp_client_mkdir(ctx->ftp_client, cmd->argv[loop]);
                if (flag != AZ_OK)
                {
                    __az_win_printf(ctx->mp, &ctx->display_ctx, " Creeate path [%s] failed.\n", cmd->argv[loop]);
                    cmd->argv[loop][loop2] = '/';
                    break;
                }
                cmd->argv[loop][loop2] = '/';
            }
            flag = az_ftp_client_mkdir(ctx->ftp_client, cmd->argv[loop]);
            if (flag != AZ_OK)
            {
                __az_win_printf(ctx->mp, &ctx->display_ctx, " Creeate path [%s] failed.\n", cmd->argv[loop]);
                break;
            }
        }
        else
        {
            flag = az_ftp_client_mkdir(ctx->ftp_client, cmd->argv[loop]);
            if (flag != AZ_OK)
            {
                __az_win_printf(ctx->mp, &ctx->display_ctx, " Creeate path [%s] failed.\n", cmd->argv[loop]);
                break;
            }
        }
    }

    return AZ_OK;
}

static az_ret az_client_remove(az_main_ctx ctx, const az_cmd cmd)
{
    bool force = false;
    bool dir = false;
    bool is_dir = false;
    int loop = 0;
    az_ret flag = 0;
    char *list_buf = NULL;
    az_file_list_t list = { 0 };
    char rm_flag = 'n';

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;
    if (cmd->argc == 0)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Missing path to remove\n");
        return AZ_OK;
    }
    force = az_cmd_has_opt(cmd, 'f', NULL);
    if (force)
        rm_flag = 'y';
    dir = az_cmd_has_opt(cmd, 'r', NULL);

    for (loop = 0; loop < cmd->argc; loop++)
    {
        flag = az_ftp_client_list(ctx->mp, ctx->ftp_client, cmd->argv[loop], &list_buf);
        if (flag != AZ_OK)
        {
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Remove path [%s] not exist\n", cmd->argv[loop]);
            break;
        }
        __az_parser_file_list(ctx->mp, list_buf, &list, true);
        if (list.list_num != 1 || az_strcmp(cmd->argv[loop], list.node[0].name) != 0)
            is_dir = true;
        else
            is_dir = false;
        if (!dir && is_dir)
        {
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Remove path [%s] is directory\n", cmd->argv[loop]);
            break;
        }
        if (!force)
        {
            az_utf8 input = NULL;

            if (is_dir)
                __az_win_printf(ctx->mp, &ctx->display_ctx, "delete directory [%s] (Y/n) ?", cmd->argv[loop]);
            else
                __az_win_printf(ctx->mp, &ctx->display_ctx, "delete normal file [%s] (Y/n) ?", cmd->argv[loop]);

            input = __az_gets(ctx->mp, ctx, true);
            //__az_win_printf(ctx->mp, &ctx->display_ctx, "input = %s\n", az_utf8_tostr(input, 0));
            if (az_utf8_len(input, 0) > 0)
            {
                if (az_strcmp(az_utf8_tostr(input, 0), "^C") == 0)
                    rm_flag = -1;
                else if (az_strcasecmp(az_utf8_tostr(input, 0), "Y") == 0)
                    rm_flag = 'y';
                else if (az_strcasecmp(az_utf8_tostr(input, 0), "yes") == 0)
                    rm_flag = 'y';
                else
                    rm_flag = 'n';
            }

            az_utf8_free(&input);
        }
        //__az_win_printf(ctx->mp, &ctx->display_ctx, "rm_flag = %c\n", rm_flag);
        if (rm_flag < 0)
            break;
        if (rm_flag == 'y')
        {
            if (is_dir)
                flag = az_ftp_client_rmd(ctx->ftp_client, cmd->argv[loop]);
            else
                flag = az_ftp_client_delete(ctx->ftp_client, cmd->argv[loop]);
            if (flag != AZ_OK)
                __az_win_printf(ctx->mp, &ctx->display_ctx, " delete [%s] failed\n", cmd->argv[loop]);
        }

        az_mpfree(ctx->mp, (void **)&list_buf);
        if (list.node != NULL)
            az_mpfree(ctx->mp, (void **)&list.node);
    }

    if (list_buf != NULL)
        az_mpfree(ctx->mp, (void **)&list_buf);
    if (list.node != NULL)
        az_mpfree(ctx->mp, (void **)&list.node);
    return AZ_OK;
}

static az_ret az_client_rename(az_main_ctx ctx, const az_cmd cmd)
{
    az_ret flag = 0;
    char *list_buf = NULL;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    if (cmd->argc < 2)
    {
        if (cmd->argc == 0)
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Missing path for rename\n");
        else
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Missing new path to rename\n");
        return AZ_OK;
    }

    flag = az_ftp_client_list(ctx->mp, ctx->ftp_client, cmd->argv[0], &list_buf);
    if (flag != AZ_OK)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Rename old path [%s] not exist\n", cmd->argv[0]);
        return AZ_OK;
    }
    az_mpfree(ctx->mp, (void **)&list_buf);
    flag = az_ftp_client_list(ctx->mp, ctx->ftp_client, cmd->argv[1], &list_buf);
    if (flag == AZ_OK)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Rename new path [%s] is existed\n", cmd->argv[1]);
        az_mpfree(ctx->mp, (void **)&list_buf);
        return AZ_OK;
    }

    flag = az_ftp_client_rename(ctx->ftp_client, cmd->argv[0], cmd->argv[1]);
    if (flag != AZ_OK)
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Rename [%s] to [%s] failed\n", cmd->argv[0], cmd->argv[1]);

    return AZ_OK;
}

static az_ret az_client_ls(az_main_ctx ctx, const az_cmd cmd)
{
    bool ex = false;
    bool all = false;
    bool readable = false;
    az_ret flag = 0;
    char *list_buf = NULL;
    az_file_list_t list = { 0 };

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    ex = az_cmd_has_opt(cmd, 'l', NULL);
    all = az_cmd_has_opt(cmd, 'a', NULL);
    readable = az_cmd_has_opt(cmd, 'h', NULL);
    if (cmd->argc == 0)
        flag = az_ftp_client_list(ctx->mp, ctx->ftp_client, NULL, &list_buf);
    else
        flag = az_ftp_client_list(ctx->mp, ctx->ftp_client, cmd->argv[0], &list_buf);
    if (flag != AZ_OK)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Get dir list failed\n");
        return AZ_OK;
    }

    __az_parser_file_list(ctx->mp, list_buf, &list, all);
    __az_print_file_list(ctx, &list, ex, readable);

    az_mpfree(ctx->mp, (void **)&list_buf);
    if (list.node != NULL)
        az_mpfree(ctx->mp, (void **)&list.node);
    return AZ_OK;
}

static az_ret az_client_histroy(az_main_ctx ctx, const az_cmd cmd)
{
    int loop = 0;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;
    if (ctx->histroy == NULL)
        return AZ_OK;

    __az_win_printf(ctx->mp, &ctx->display_ctx, " Total: %d\n", _histroy_size(ctx->histroy));
    for (loop = 0; loop < _histroy_size(ctx->histroy); loop++)
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%d: %s\n", loop + 1, az_utf8_tostr((az_utf8)_get_histroy(ctx->histroy, loop), 0));

    return AZ_OK;
}

static az_ret az_client_upload(az_main_ctx ctx, const az_cmd cmd)
{
    az_ret flag = AZ_OK;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    if (cmd->argc == 0)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Missing path for upload\n");
        return AZ_OK;
    }

#if defined(__az_windows_32__) || defined(__az_windows_64__)
    flag = _access(cmd->argv[0], _A_NORMAL);
#else
    flag = access(cmd->argv[0], F_OK);
#endif
    if (flag != 0)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Local path [%s] is not exit\n", cmd->argv[0]);
        return AZ_OK;
    }

    if (cmd->argc == 1)
        flag = az_ftp_client_upload(ctx->ftp_client, cmd->argv[0], "./", 0);
    else
        flag = az_ftp_client_upload(ctx->ftp_client, cmd->argv[0], cmd->argv[1], 0);
    if (flag != AZ_OK)
    {
        if (cmd->argc == 1)
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Upload [%s] to [%s] failed\n", cmd->argv[0], az_ftp_client_pwd(ctx->ftp_client));
        else
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Upload [%s] to [%s] failed\n", cmd->argv[0], cmd->argv[1]);
        return AZ_OK;
    }
    __az_show_trans_status(ctx);
    return AZ_OK;
}

static az_ret az_client_download(az_main_ctx ctx, const az_cmd cmd)
{
    az_ret flag = AZ_OK;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;

    if (cmd->argc == 0)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " Missing path for download\n");
        return AZ_OK;
    }

    if (cmd->argc == 1)
        flag = az_ftp_client_download(ctx->ftp_client, cmd->argv[0], "./", 0);
    else
        flag = az_ftp_client_download(ctx->ftp_client, cmd->argv[0], cmd->argv[1], 0);
    if (flag != AZ_OK)
    {
        if (cmd->argc == 1)
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Download [%s] to [.] failed\n", cmd->argv[0]);
        else
            __az_win_printf(ctx->mp, &ctx->display_ctx, " Download [%s] to [%s] failed\n", cmd->argv[0], cmd->argv[1]);
        return AZ_OK;
    }
    __az_show_trans_status(ctx);

    return AZ_OK;
}

static void __az_show_trans_status(az_main_ctx ctx)
{
    size_t trans_num = 0;
    size_t end_num = 0;
    az_file_session *trans_ary = NULL;
    int loop = 0;
    int ary_size = 0;
    int ary_num = 0;

    if (ctx == NULL)
        return;

    trans_num = az_ftp_client_trans_size(ctx->ftp_client);
    if (trans_num == 0)
        return;
    ary_size = trans_num > ctx->worker_num ? ctx->worker_num : trans_num;
    trans_ary = (az_file_session*)az_mpcalloc(ctx->mp, sizeof(az_file_session) * ary_size);
    if (trans_ary == NULL)
        return;

    for (loop = 0; loop < ary_size; loop++)
    {
        trans_ary[loop] = az_ftp_client_trans_get_index(ctx->ftp_client, loop);
        __az_print_trans_status(ctx, ctx->display_ctx.cursor_x, trans_ary[loop], 0, 0);
        __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
    }
    ary_num = ary_size;
    ctx->display_ctx.cursor_x -= ary_num;

    while (az_ftp_client_trans_size(ctx->ftp_client) > 0)
    {
        for (loop = 0; loop < ary_size; loop++)
        {
            if (trans_ary[loop] != NULL && (az_atomic_read(&trans_ary[loop]->trans_state) == AZ_TRANS_END
                || az_atomic_read(&trans_ary[loop]->trans_state) == AZ_TRANS_ABORT
                || az_atomic_read(&trans_ary[loop]->trans_state) == AZ_TRANS_ERR))
            {
                end_num++;
                __az_print_trans_status(ctx, ctx->display_ctx.cursor_x, trans_ary[loop], end_num, trans_num);
                __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");

                az_ftp_client_trans_del(ctx->ftp_client, &trans_ary[loop]);
                if (az_ftp_client_trans_size(ctx->ftp_client) >= ary_size)
                    trans_ary[loop] = az_ftp_client_trans_get_index(ctx->ftp_client, ary_size - 1);
                else
                    ary_num--;
            }
        }

        for (loop = 0; loop < ary_size; loop++)
        {
            if (trans_ary[loop] != NULL)
            {
                __az_print_trans_status(ctx, ctx->display_ctx.cursor_x, trans_ary[loop], 0, 0);
                __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
            }
        }
        ctx->display_ctx.cursor_x -= ary_num;
        az_msleep(30);
    }
    az_mpfree(ctx->mp, (void**)&trans_ary);
}

#define AZ_KB_OFFSET (1024)
#define AZ_MB_OFFSET (1024*1024)
#define AZ_GB_OFFSET (1024*1024*1024)
#define AZ_STATUS_WIDTH_MAX 39
#define AZ_STATUS_SIZE_START_Y (__get_term_cols()-AZ_STATUS_WIDTH_MAX)
#define AZ_STATUS_RATE_START_Y (AZ_STATUS_SIZE_START_Y+17)
#define AZ_STATUS_STAT_START_Y (AZ_STATUS_RATE_START_Y+8)
#define AZ_STATUS_SPEED_START_Y (AZ_STATUS_STAT_START_Y+3)
static void __az_print_trans_status(az_main_ctx ctx, int cursor_x, az_file_session stat, size_t index, size_t total)
{
    az_utf8 file_name = NULL;
    int progress_w = 0;
    char* pro = NULL;
    int64_t speed = 0;
    int64_t up_down_len = 0;

    if (ctx == NULL || cursor_x < 0 || cursor_x >= __get_term_lines() || stat == NULL)
        return;

    up_down_len = az_atomic64_read(&stat->up_down_len);
    speed = az_atomic64_read(&stat->speed);

    file_name = az_utf8_create(ctx->mp, 0, NULL);
    if (file_name == NULL)
        return;
    if (stat->trans_type == AZ_FTP_UPLOAD)
    {
        if (total == 0)
            az_utf8_format(file_name, 0, "%s", stat->local_path);
        else
            az_utf8_format(file_name, 0, "(%lu/%lu) %s", index, total, stat->local_path);
    }
    else
    {
        if (total == 0)
            az_utf8_format(file_name, 0, "%s", stat->remote_path);
        else
            az_utf8_format(file_name, 0, "(%lu/%lu) %s", index, total, stat->remote_path);
    }
    progress_w = __get_term_cols() - AZ_STATUS_WIDTH_MAX - az_utf8_pwidth(file_name, 0) - 6;
    if (progress_w > 10)
    {
        int pro_len = 0;
        pro = (char*)az_mpcalloc(ctx->mp, progress_w + 1);
        if (pro == NULL)
            goto END;
        if (stat->file_size <= 0)
            pro_len = progress_w;
        else
            pro_len = progress_w * up_down_len / stat->file_size;
        Az_Memset(pro, '=', pro_len);
        if (stat->file_size > 0 && progress_w * up_down_len % stat->file_size > 0)
            az_strcatchr(pro, progress_w, '-');
        az_strcatchr(pro, progress_w, '>');
    }

    ctx->display_ctx.cursor_x = cursor_x;
    ctx->display_ctx.cursor_y = 0;
    __eraser_line(ctx->display_ctx.cursor_x);
    //文件名
    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", az_utf8_tostr(file_name, 0));
    //进度条
    if (progress_w > 10)
    {
        ctx->display_ctx.cursor_y = az_utf8_pwidth(file_name, 0) + 2;
        __az_win_printf(ctx->mp, &ctx->display_ctx, "[");
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", pro);
        ctx->display_ctx.cursor_y = AZ_STATUS_SIZE_START_Y - 3;
        __az_win_printf(ctx->mp, &ctx->display_ctx, "]");
    }
    //文件大小
    ctx->display_ctx.cursor_y = AZ_STATUS_SIZE_START_Y;
    if (stat->file_size < 1024)//B
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lldB/%ldB", up_down_len, stat->file_size);
    else if (stat->file_size / AZ_KB_OFFSET < 1024)//KB
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%.1fK/%.1fK", up_down_len / (float)AZ_KB_OFFSET, stat->file_size / (float)AZ_KB_OFFSET);
    else if (stat->file_size / AZ_MB_OFFSET < 1024)//MB
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%.1fM/%.1fM", up_down_len / (float)AZ_MB_OFFSET, stat->file_size / (float)AZ_MB_OFFSET);
    else//GB
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%.1fG/%.1fG", up_down_len / (float)AZ_GB_OFFSET, stat->file_size / (float)AZ_GB_OFFSET);
    //百分比
    ctx->display_ctx.cursor_y = AZ_STATUS_RATE_START_Y;
    if (stat->file_size <= 0)
        __az_win_printf(ctx->mp, &ctx->display_ctx, "100.0");
    else
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%.1f", up_down_len / (float)stat->file_size * 100);
    //完成状态
    ctx->display_ctx.cursor_y = AZ_STATUS_STAT_START_Y;
    if (az_atomic_read(&stat->trans_state) == AZ_TRANS_WAITE)
    {
        printf("\033[1m");
        __az_win_printf(ctx->mp, &ctx->display_ctx, "W");
        printf("\033[0m");
    }
    else if (az_atomic_read(&stat->trans_state) == AZ_TRANS_RUNNING)
    {
        printf("\033[1;5m");
        if (ctx->display_ctx.enable_color)
            printf("\033[32m");
        __az_win_printf(ctx->mp, &ctx->display_ctx, "T");
        printf("\033[0m");
    }
    else if (az_atomic_read(&stat->trans_state) == AZ_TRANS_END)
    {
        printf("\033[1m");
        if (ctx->display_ctx.enable_color)
            printf("\033[34m");
        __az_win_printf(ctx->mp, &ctx->display_ctx, "D");
        printf("\033[0m");
    }
    else if (az_atomic_read(&stat->trans_state) == AZ_TRANS_ABORT)
    {
        printf("\033[1m");
        if (ctx->display_ctx.enable_color)
            printf("\033[33m");
        __az_win_printf(ctx->mp, &ctx->display_ctx, "A");
        printf("\033[0m");
    }
    else
    {
        printf("\033[1m");
        if (ctx->display_ctx.enable_color)
            printf("\033[31m");
        __az_win_printf(ctx->mp, &ctx->display_ctx, "E");
        printf("\033[0m");
    }
    //速度
    ctx->display_ctx.cursor_y = AZ_STATUS_SPEED_START_Y;
    if (speed < 1024)//B
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%0.1fB/s", speed);
    else if (speed / AZ_KB_OFFSET < 1024)//KB
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%0.1fK/s", speed / (float)AZ_KB_OFFSET);
    else if (speed / AZ_MB_OFFSET < 1024)//MB
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%0.1fM/s", speed / (float)AZ_MB_OFFSET);
    else//GB
        __az_win_printf(ctx->mp, &ctx->display_ctx, "%0.1fG/s", speed / (float)AZ_GB_OFFSET);

END:
    if (pro != NULL)
        az_mpfree(ctx->mp, (void**)&pro);
    if (file_name != NULL)
        az_utf8_free(&file_name);
    return;
}

static az_utf8 __az_gets(az_memp pool, az_main_ctx ctx, bool show)
{
    az_ret flag = 0;
    az_utf8 tmp = NULL;
    int key = 0;
    int key_size = 0;
    uint8_t key_buf[7] = { 0 };
    az_stime_t push_key = { 0 };
    az_stime_t last_push_key = { 0 };
    bool trans_flag = false;
    bool Ident_flag = false;
    az_utf8_node_t word = { 0 };
    int prefix_width = ctx->display_ctx.cursor_y;

    if (pool == NULL || ctx == NULL)
        return NULL;

    tmp = az_utf8_create(pool, 8, NULL);
    if (tmp == NULL)
        return NULL;

    while (az_atomic_read(&ctx->run))
    {
        key = fgetc(stdin);
        if (key < 0)
        {
            if (trans_flag)
            {
                az_get_date(&push_key);
                if (az_time_difference(&last_push_key, &push_key) >= 50)//按键间隔是否超时
                {
                    //这里识别转义序列
                    key = __escape_seq(key_buf, key_size, true);
                    if (key >= 0 && key != AZ_UNKNOWN_KEY)
                    {
                        Ident_flag = true;
                        goto TRANS_FLAG;
                    }
                    __beep();
                    trans_flag = false;
                    Ident_flag = false;
                    Az_Memzero(key_buf, 7);
                    key_size = 0;
                }
            }
            continue;
        }
        az_get_date(&push_key);

        if (!trans_flag && key > 31 && key != 127)
        {
            flag = az_utf8_ndadd_chr(&word, key);
            if (flag == AZ_ERROR)
                Az_Memzero(&word, sizeof(az_utf8_node_t));
            else if (flag == AZ_OK)
            {
                if (show)
                    __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", (char *)word.data);
                az_utf8_strcatnd(tmp, &word);
                Az_Memzero(&word, sizeof(az_utf8_node_t));
            }
        }
        else if (trans_flag)
        {
            key_buf[key_size] = key;
            key_size++;
            if (key_size == 6)
            {
                __beep();
                trans_flag = false;
                Ident_flag = false;
                Az_Memzero(key_buf, 7);
                key_size = 0;
            }
            else//这里识别转义序列
            {
                key = __escape_seq(key_buf, key_size, false);
                if (key >= 0 && key != AZ_UNKNOWN_KEY)
                {
                    Ident_flag = true;
                    goto TRANS_FLAG;
                }
            }
        }
        else
        {
        TRANS_FLAG:
            switch (key)
            {
            case AZ_ASCII_ESCAPE_KEY://esc
                if (Ident_flag)
                {
                    //__az_win_printf(ctx->mp, &ctx->display_ctx, " Esc key\n");
                    __beep();
                }
                else
                {
                    trans_flag = true;
                    key_buf[0] = key;
                    key_buf[1] = '\0';
                    key_size = 1;
                }
                break;
            //case AZ_ASCII_TAB_KEY:
            //    //__az_win_printf(ctx->mp, &ctx->display_ctx, " Tab key\n");
            //    __beep();
            //    break;
            case AZ_ASCII_ENTER_KEY:
                //__az_win_printf(ctx->mp, &ctx->display_ctx, " Enter key\n");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
                goto END;
                break;
            case AZ_ASCII_BACKSPACE_KEY:
            case AZ_BACKSPACE_KEY:
                {
                    az_utf8_node tmp_word = NULL;
                    size_t com_c_index = az_utf8_len(tmp, 0);
                    if (com_c_index == 0)
                    {
                        __beep();
                        break;
                    }

                    com_c_index--;
                    if (show)
                    {
                        tmp_word = az_utf8_get(tmp, com_c_index);
                        ctx->display_ctx.cursor_y -= tmp_word->print_width;
                        if (ctx->display_ctx.cursor_y < 0)
                        {
                            int line = 0;
                            int offset = 0;

                            ctx->display_ctx.cursor_x--;
                            offset = az_utf8_pwidth(tmp, 0) - tmp_word->print_width + prefix_width;
                            line = offset / __get_term_cols();
                            if (line == 0)
                            {
                                if (__get_term_cols() - offset <= 1)
                                    ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                                else
                                    ctx->display_ctx.cursor_y = offset;
                            }
                            else
                            {
                                if (__get_term_cols() - (offset - line*__get_term_cols()) <= 1)
                                    ctx->display_ctx.cursor_y = __get_term_cols() - 1;
                                else
                                    ctx->display_ctx.cursor_y = offset - line*__get_term_cols();
                            }
                        }
                        __set__cursor_position(ctx->display_ctx.cursor_x, ctx->display_ctx.cursor_y);
                        __delete_key(tmp_word->print_width);
                    }
                    az_utf8_del_nd(tmp, com_c_index);
                }
                break;
            case AZ_ASCII_CTRL_C_KEY:
                __az_win_printf(ctx->mp, &ctx->display_ctx, "^C\n");
                az_utf8_clear(tmp);
                az_utf8_add(tmp, "^C");
                goto END;
                break;
            //case AZ_ASCII_CTRL_D_KEY:
            //    __az_win_printf(ctx->mp, &ctx->display_ctx, "\n ^D, logout\n");
            //    __beep();
            //    break;
            default:
                __beep();
                break;
            }

            if (trans_flag && Ident_flag)//已经识别了转义序列的功能键
            {
                trans_flag = false;
                Ident_flag = false;
                Az_Memzero(key_buf, 7);
                key_size = 0;
            }
        }

        last_push_key = push_key;
    }
END:
    return tmp;
ERR:
    if (tmp != NULL)
        az_utf8_free(&tmp);
    return NULL;
}

static az_ret __az_parser_file_list(az_memp pool, const char *buf, az_file_list list, bool all)
{
    int list_num = 0;
    az_file_info node_tmp = NULL;
    const char *start = NULL;
    const char *end = NULL;
    az_file_info_t info = { 0 };

    if (pool == NULL || buf == NULL || *buf == '\0' || list == NULL)
        return AZ_ERROR;

    for (start = buf, end = az_strsstr(start, "\r\n"); end != NULL; start = end + 2, end = az_strsstr(start, "\r\n"))
    {
        Az_Memzero(&info, sizeof(az_file_info_t));
        sscanf(start, "%[^'\t'| ]%*['\t'| ]%[^'\t'| ]%*['\t'| ]%[^'\t'| ]%*['\t'| ]%lld%*['\t'| ]%[^'\t'| ]%*['\t'| ]%[^'\t'| ]%*['\t'| ]%[^'\t'| ]%*['\t'| ]%[^'\r'|'\n']", info.auth, info.user, info.group, &info.size, info.mouth, info.day, info.time, info.name);
        if (*info.auth == '\0' || *info.user == '\0' || *info.group == '\0' || *info.mouth == '\0' || *info.day == '\0' || *info.time == '\0' || *info.name == '\0')
            continue;
        if (!all && *info.name == '.')
            continue;

        if (*info.auth == 'd')
            info.is_dir = true;
        else
            info.is_dir = false;
        if (node_tmp == NULL)
        {
            node_tmp = (az_file_info)az_mpcalloc(pool, sizeof(az_file_info_t));
            if (node_tmp == NULL)
                goto RET_ERR;
        }
        else
        {
            az_file_info tmp = NULL;
            tmp = (az_file_info)az_mprealloc(pool, (void **)&node_tmp, sizeof(az_file_info_t)*(list_num + 1));
            if (tmp == NULL)
                goto RET_ERR;
            node_tmp = tmp;
        }
        Az_Memcpy(&node_tmp[list_num], &info, sizeof(az_file_info_t));
        list_num++;
    }

    list->list_num = list_num;
    list->node = node_tmp;
    qsort(list->node, list->list_num, sizeof(az_file_info_t), ___az_compar);

    return AZ_OK;
RET_ERR:
    if (node_tmp != NULL)
        az_mpfree(pool, (void **)&node_tmp);
    return AZ_ERROR;
}

static int ___az_compar(const void *src1, const void *src2)
{
    return strcoll(((az_file_info)src1)->name, ((az_file_info)src2)->name);
}

static az_column_info __init_column_info(az_memp pool, int *max_idx)
{
    int i;
    az_column_info tmp = NULL;

    if (pool == NULL || max_idx == NULL)
        return NULL;

    *max_idx = __get_term_cols() / MIN_COLUMN_WIDTH;
    if (*max_idx == 0)
        *max_idx = 1;

    tmp = (az_column_info)az_mpcalloc(pool, sizeof(az_column_info_t) * (*max_idx));
    if (tmp == NULL)
        return NULL;

    for (i = 0; i < (*max_idx); ++i)
    {
        int j;

        tmp[i].valid_len = 1;
        tmp[i].line_len = (i + 1) * MIN_COLUMN_WIDTH;

        tmp[i].col_arr = (int *)az_mpcalloc(pool, sizeof(int) * (i + 1));
        if (tmp[i].col_arr == NULL)
            goto RET_ERR;

        for (j = 0; j <= i; ++j)
            tmp[i].col_arr[j] = MIN_COLUMN_WIDTH;
    }

    return tmp;
RET_ERR:
    if (tmp != NULL)
    {
        for (i = 0; i < (*max_idx); i++)
            if (tmp[i].col_arr != NULL)
                az_mpfree(pool, (void **)&tmp[i].col_arr);
        az_mpfree(pool, (void **)&tmp);
    }
    return NULL;
}

static void __free_column_info(az_memp pool, az_column_info *info, int max_idx)
{
    int loop = 0;
    if (pool == NULL || info == NULL || (*info) == NULL || max_idx <= 0)
        return;

    for (loop = 0; loop < max_idx; loop++)
        if ((*info)[loop].col_arr != NULL)
            az_mpfree(pool, (void **)&(*info)[loop].col_arr);
    az_mpfree(pool, (void **)info);
}

static inline void ___indent(az_main_ctx ctx, int from, int to)
{
    while (from < to)
    {
        __az_win_printf(ctx->mp, &ctx->display_ctx, " ");
        from++;
    }
}

static inline void __az_print_file_list(az_main_ctx ctx, az_file_list list, bool ex, bool readable)
{
    if (ex)
        __az_show_list_ex(ctx, list, readable);
    else
        __az_show_list(ctx, list);
}

static void __az_show_list(az_main_ctx ctx, az_file_list list)
{
    az_column_info line_fmt = NULL;
    az_column_info col_info = NULL;
    int filesno = 0;            /* Index into files. */
    int row = 0;                /* Current row. 当前行*/
    int max_name_length = 0;    /* Length of longest file name + frills.最长文件名的长度+褶边。 */
    int name_length = 0;        /* Length of each file name + frills. 每个文件名的长度+褶边。*/
    int pos = 0;            /* Current character column. 当前字符列。*/
    int cols = 0;            /* Number of files across. 文件数。*/
    int rows = 0;            /* Maximum number of files down. 已关闭的最大文件数。*/
    int max_cols = 0;
    int max_idx = 0;

    if (ctx == NULL || list == NULL || list->list_num == 0)
        return;

    col_info = __init_column_info(ctx->mp, &max_idx);
    if (col_info == NULL)
        return;
    /* Normally the maximum number of columns is determined by the
    screen width.  But if few files are available this might limit it
    as well.  通常，最大列数由屏幕宽度决定。但如果可用的文件很少，这也可能会限制它。*/
    max_cols = max_idx > list->list_num ? list->list_num : max_idx;

    /* Compute the maximum number of possible columns.  计算可能的最大列数。*/
    for (filesno = 0; filesno < list->list_num; ++filesno)
    {
        int i;

        name_length = az_strlen(list->node[filesno].name);
        for (i = 0; i < max_cols; ++i)
        {
            if (col_info[i].valid_len)
            {
                int idx = filesno / ((list->list_num + i) / (i + 1));
                int real_length = name_length + (idx == i ? 0 : 2);
                if (real_length > col_info[i].col_arr[idx])
                {
                    col_info[i].line_len += (real_length - col_info[i].col_arr[idx]);
                    col_info[i].col_arr[idx] = real_length;
                    col_info[i].valid_len = col_info[i].line_len < __get_term_cols();
                }
            }
        }
    }

    /* Find maximum allowed columns.  查找允许的最大列数。*/
    for (cols = max_cols; cols > 1; --cols)
    {
        if (col_info[cols - 1].valid_len)
            break;
    }
    line_fmt = &col_info[cols - 1];

    /* Calculate the number of rows that will be in each column except possibly
    for a short column on the right.  计算每列中的行数，可能除了右侧的短列。*/
    rows = list->list_num / cols + (list->list_num % cols != 0);
    for (row = 0; row < rows; row++)
    {
        int col = 0;
        filesno = row;
        pos = 0;
        /* Print the next row.  */
        while (1)
        {
            if (list->node[filesno].is_dir)
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[34m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[filesno].name);
                printf("\033[0m");
            }
            else if (*list->node[filesno].auth == 'l')
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[36m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[filesno].name);
                printf("\033[0m");
            }
            else if (az_strschr(list->node[filesno].auth, 'x', false) != NULL)
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[32m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[filesno].name);
                printf("\033[0m");
            }
            else
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[filesno].name);

            name_length = az_strlen(list->node[filesno].name);
            max_name_length = line_fmt->col_arr[col++];

            filesno += rows;
            if (filesno >= list->list_num)
                break;

            ___indent(ctx, pos + name_length, pos + max_name_length);
            pos += max_name_length;
        }
        __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
    }

    __free_column_info(ctx->mp, &col_info, max_idx);
}

static int __az_cmd_to_strary(az_main_ctx ctx, az_cmd_info cmd_list, char ***ary)
{
    int size = 0;
    int loop = 0;
    char **out = NULL;

    if (ctx == NULL || cmd_list == NULL || ary == NULL)
        return 0;

    for (size = 0; cmd_list[size].cmd != 0 || cmd_list[size].opt != 0 || cmd_list[size].cb != 0 || cmd_list[size].data != 0 || cmd_list[size].val != 0; size++)
        ;
    if (size <= 0)
        return 0;

    out = (char **)az_mpcalloc(ctx->mp, sizeof(char *) * (size + 1));
    if (out == NULL)
        goto ERR;

    for (loop = 0; loop < size; loop++)
        out[loop] = (char *)cmd_list[loop].cmd;
    *ary = out;

    return size;
ERR:
    if (out != NULL)
        az_mpfree(ctx->mp, (void **)&out);
    return -1;
}

static int ___az_compar_cmd(const void *src1, const void *src2)
{
    return strcoll((char *)src1, (char *)src2);
}

static void __az_show_cmd_list(az_main_ctx ctx, char **cmd_list, int list_num)
{
    az_column_info line_fmt = NULL;
    az_column_info col_info = NULL;
    int filesno = 0;            /* Index into files. */
    int row = 0;                /* Current row. 当前行*/
    int max_name_length = 0;    /* Length of longest file name + frills.最长文件名的长度+褶边。 */
    int name_length = 0;        /* Length of each file name + frills. 每个文件名的长度+褶边。*/
    int pos = 0;            /* Current character column. 当前字符列。*/
    int cols = 0;            /* Number of files across. 文件数。*/
    int rows = 0;            /* Maximum number of files down. 已关闭的最大文件数。*/
    int max_cols = 0;
    int max_idx = 0;

    if (ctx == NULL || list_num <= 0 || cmd_list == NULL || cmd_list[0] == NULL)
        return;

    qsort(cmd_list, list_num, sizeof(char *), ___az_compar_cmd);

    col_info = __init_column_info(ctx->mp, &max_idx);
    if (col_info == NULL)
        return;
    /* Normally the maximum number of columns is determined by the
    screen width.  But if few files are available this might limit it
    as well.  通常，最大列数由屏幕宽度决定。但如果可用的文件很少，这也可能会限制它。*/
    max_cols = max_idx > list_num ? list_num : max_idx;

    /* Compute the maximum number of possible columns.  计算可能的最大列数。*/
    for (filesno = 0; filesno < list_num; ++filesno)
    {
        int i;

        name_length = az_strlen(cmd_list[filesno]);
        for (i = 0; i < max_cols; ++i)
        {
            if (col_info[i].valid_len)
            {
                int idx = filesno / ((list_num + i) / (i + 1));
                int real_length = name_length + (idx == i ? 0 : 2);
                if (real_length > col_info[i].col_arr[idx])
                {
                    col_info[i].line_len += (real_length - col_info[i].col_arr[idx]);
                    col_info[i].col_arr[idx] = real_length;
                    col_info[i].valid_len = col_info[i].line_len < __get_term_cols();
                }
            }
        }
    }

    /* Find maximum allowed columns.  查找允许的最大列数。*/
    for (cols = max_cols; cols > 1; --cols)
    {
        if (col_info[cols - 1].valid_len)
            break;
    }
    line_fmt = &col_info[cols - 1];

    /* Calculate the number of rows that will be in each column except possibly
    for a short column on the right.  计算每列中的行数，可能除了右侧的短列。*/
    rows = list_num / cols + (list_num % cols != 0);
    for (row = 0; row < rows; row++)
    {
        int col = 0;
        filesno = row;
        pos = 0;
        /* Print the next row.  */
        while (1)
        {
            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", cmd_list[filesno]);

            name_length = az_strlen(cmd_list[filesno]);
            max_name_length = line_fmt->col_arr[col++];

            filesno += rows;
            if (filesno >= list_num)
                break;

            ___indent(ctx, pos + name_length, pos + max_name_length);
            pos += max_name_length;
        }
        __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
    }

    __free_column_info(ctx->mp, &col_info, max_idx);
}

static void __az_show_list_ex(az_main_ctx ctx, az_file_list list, bool readable)
{
    int loop = 0;
    int max_user_wide = 0;
    int max_group_wide = 0;
    int max_size_wide = 0;

    if (ctx == NULL || list == NULL || list->list_num == 0)
        return;

    for (loop = 0; loop < list->list_num; loop++)
    {
        int size_len = 0;

        if (az_strlen(list->node[loop].user) > max_user_wide)
            max_user_wide = az_strlen(list->node[loop].user);
        if (az_strlen(list->node[loop].group) > max_group_wide)
            max_group_wide = az_strlen(list->node[loop].group);
        if (readable)
        {
            if (list->node[loop].size < 10)//B
                size_len = 1;
            else if (list->node[loop].size < 100)//B
                size_len = 2;
            else if (list->node[loop].size < 1024)//B
                size_len = 3;
            else if (list->node[loop].size / AZ_KB_OFFSET < 1024)//KB
            {
                if (list->node[loop].size / AZ_KB_OFFSET < 10)
                    size_len = 2;
                else if (list->node[loop].size / AZ_KB_OFFSET < 100)
                    size_len = 3;
                else
                    size_len = 4;
                if (list->node[loop].size % AZ_KB_OFFSET > 0)
                    size_len += 2;
            }
            else if (list->node[loop].size / AZ_MB_OFFSET < 1024)//MB
            {
                if (list->node[loop].size / AZ_MB_OFFSET < 10)
                    size_len = 2;
                else if (list->node[loop].size / AZ_MB_OFFSET < 100)
                    size_len = 3;
                else
                    size_len = 4;
                if (list->node[loop].size % AZ_MB_OFFSET > 0)
                    size_len += 2;
            }
            else//GB
            {
                size_len = snprintf(NULL, 0, "%lldG", list->node[loop].size / AZ_GB_OFFSET);
                if (list->node[loop].size % AZ_GB_OFFSET > 0)
                    size_len += 2;
            }
        }
        else
            size_len = snprintf(NULL, 0, "%lld", list->node[loop].size);
        if (size_len > max_size_wide)
            max_size_wide = size_len;
    }

    if (max_user_wide + max_group_wide + max_size_wide + 28 > __get_term_cols())
    {
        for (loop = 0; loop < list->list_num; loop++)
        {
            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s %s %s ", list->node[loop].auth, list->node[loop].user, list->node[loop].group);
            if (readable)
            {
                if (list->node[loop].size < 1024)//B
                    __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld", list->node[loop].size);
                else if (list->node[loop].size / AZ_KB_OFFSET < 1024)//KB
                {
                    off_t inte = list->node[loop].size / AZ_KB_OFFSET;
                    off_t dec = list->node[loop].size % AZ_KB_OFFSET;

                    if (dec > 0)
                    {
                        dec /= 100;
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld.%lldK", inte, dec);
                    }
                    else
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lldK", inte);
                }
                else if (list->node[loop].size / AZ_MB_OFFSET < 1024)//MB
                {
                    off_t inte = list->node[loop].size / AZ_MB_OFFSET;
                    off_t dec = list->node[loop].size % AZ_MB_OFFSET;

                    if (dec > 0)
                    {
                        dec /= 100000;
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld.%lldM", inte, dec);
                    }
                    else
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lldM", inte);
                }
                else//GB
                {
                    off_t inte = list->node[loop].size / AZ_GB_OFFSET;
                    off_t dec = list->node[loop].size % AZ_GB_OFFSET;

                    if (dec > 0)
                    {
                        dec /= 100000000;
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld.%lldG", inte, dec);
                    }
                    else
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lldG", inte);
                }
            }
            else
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld", list->node[loop].size);

            __az_win_printf(ctx->mp, &ctx->display_ctx, " %s %s %s ", list->node[loop].mouth, list->node[loop].day, list->node[loop].time);
            if (list->node[loop].is_dir)
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[34m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].name);
                printf("\033[0m");
            }
            else if (*list->node[loop].auth == 'l')
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[36m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].name);
                printf("\033[0m");
            }
            else if (az_strschr(list->node[loop].auth, 'x', false) != NULL)
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[32m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].name);
                printf("\033[0m");
            }
            else
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].name);

            __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
        }
    }
    else
    {
        int user_start = 0;
        int group_start = 0;
        int size_end = 0;
        int mouth_start = 0;
        int day_end = 0;
        int time_end = 0;

        user_start = 11;
        group_start = user_start + max_user_wide + 1;
        size_end = group_start + max_group_wide + 1 + max_size_wide;
        mouth_start = size_end + 1;
        day_end = mouth_start + 6;
        time_end = day_end + 6;

        for (loop = 0; loop < list->list_num; loop++)
        {
            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].auth);
            ctx->display_ctx.cursor_y = user_start;
            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].user);
            ctx->display_ctx.cursor_y = group_start;
            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].group);

            if (readable)
            {
                if (list->node[loop].size < 1024)//B
                {
                    ctx->display_ctx.cursor_y = size_end - snprintf(NULL, 0, "%lld", list->node[loop].size);
                    __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld", list->node[loop].size);
                }
                else if (list->node[loop].size / AZ_KB_OFFSET < 1024)//KB
                {
                    off_t inte = list->node[loop].size / AZ_KB_OFFSET;
                    off_t dec = list->node[loop].size % AZ_KB_OFFSET;

                    if (dec > 0)
                    {
                        dec /= 100;
                        ctx->display_ctx.cursor_y = size_end - snprintf(NULL, 0, "%lld.%lldK", inte, dec);
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld.%lldK", inte, dec);
                    }
                    else
                    {
                        ctx->display_ctx.cursor_y = size_end - snprintf(NULL, 0, "%lldK", inte);
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lldK", inte);
                    }
                }
                else if (list->node[loop].size / AZ_MB_OFFSET < 1024)//MB
                {
                    off_t inte = list->node[loop].size / AZ_MB_OFFSET;
                    off_t dec = list->node[loop].size % AZ_MB_OFFSET;

                    if (dec > 0)
                    {
                        dec /= 100000;
                        ctx->display_ctx.cursor_y = size_end - snprintf(NULL, 0, "%lld.%lldM", inte, dec);
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld.%lldM", inte, dec);
                    }
                    else
                    {
                        ctx->display_ctx.cursor_y = size_end - snprintf(NULL, 0, "%lldM", inte);
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lldM", inte);
                    }
                }
                else//GB
                {
                    off_t inte = list->node[loop].size / AZ_GB_OFFSET;
                    off_t dec = list->node[loop].size % AZ_GB_OFFSET;

                    if (dec > 0)
                    {
                        dec /= 100000000;
                        ctx->display_ctx.cursor_y = size_end - snprintf(NULL, 0, "%lld.%lldG", inte, dec);
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld.%lldG", inte, dec);
                    }
                    else
                    {
                        ctx->display_ctx.cursor_y = size_end - snprintf(NULL, 0, "%lldG", inte);
                        __az_win_printf(ctx->mp, &ctx->display_ctx, "%lldG", inte);
                    }
                }
            }
            else
            {
                ctx->display_ctx.cursor_y = size_end - snprintf(NULL, 0, "%lld", list->node[loop].size);
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%lld", list->node[loop].size);
            }
            ctx->display_ctx.cursor_y = mouth_start;
            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].mouth);
            ctx->display_ctx.cursor_y = day_end - snprintf(NULL, 0, "%s", list->node[loop].day);
            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].day);
            ctx->display_ctx.cursor_y = time_end - snprintf(NULL, 0, "%s", list->node[loop].time);
            __az_win_printf(ctx->mp, &ctx->display_ctx, "%s ", list->node[loop].time);
            if (list->node[loop].is_dir)
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[34m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].name);
                printf("\033[0m");
            }
            else if (*list->node[loop].auth == 'l')
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[36m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].name);
                printf("\033[0m");
            }
            else if (az_strschr(list->node[loop].auth, 'x', false) != NULL)
            {
                printf("\033[1m");
                if (ctx->display_ctx.enable_color)
                    printf("\033[32m");
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].name);
                printf("\033[0m");
            }
            else
                __az_win_printf(ctx->mp, &ctx->display_ctx, "%s", list->node[loop].name);
            __az_win_printf(ctx->mp, &ctx->display_ctx, "\n");
        }
    }
}

static const char* __az_get_last_dir(az_main_ctx ctx)
{
    int loop = 0;
    const char *pwd = NULL;

    pwd = az_ftp_client_pwd(ctx->ftp_client);
    if (pwd == NULL)
        return NULL;

    loop = az_strlen(pwd);
    if (loop == 1)
        return pwd;

    for (loop = loop - 1; loop > 0; loop--)
        if (pwd[loop - 1] == '/')
            break;

    return (const char*)&pwd[loop];
}

static int __get_str_width(az_memp mp, char *str)
{
    az_utf8 input = NULL;
    az_utf8_node node = NULL;
    size_t loop = 0;
    size_t len = 0;
    int width = 0;

    input = az_utf8_create(mp, 0, str);
    if (input == NULL)
        return -1;

    len = az_utf8_len(input, 0);
    for (loop = 0; loop < len; loop++)
    {
        node = az_utf8_get(input, loop);
        if (node->byte_count == 1)
            width++;
        else if (node->byte_count > 1)
            width += 2;
    }
    az_utf8_free(&input);

    return width;
}
