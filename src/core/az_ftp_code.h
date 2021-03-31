#ifndef __AZ_FTP_CODE_INCLUDE__
#define __AZ_FTP_CODE_INCLUDE__

#include<azftp/az_ftp_define.h>

/************
* FTP响应码解析
*
* FTP 响应由 3 位数字组成 (xyz) (以 3 个数字字符传递) 后面跟着一些文本。数字用来自动的判断当前的状态，
* 文本内容提供给人类用户。三位数字应该包含足够的信息，使用户 PI 不需要检查文本内容，而将其忽略、
* 或返回给用户。文本内容可能是与特定服务器相关的，所以每一个响应的文本内容很可能不同。
* 3 位数字的每一位都有特定的意义。允许用户进程将复杂的响应简化。第一位数字标识了响应是好，坏或者未完成，
* 简单的用户进程可以通过检查第一位数字，决定它的下一个动作（依计划处理，重试，放弃等等）。第二位数字标识
* 大概发生了什么错误（比如，文件系统错误，语法错误）。第三位数字指示信息顺序是否有误（例如，RNTO 前没有 RNFR 命令）。
    响应的第一位数字可能有以下五个值：
        1）1yz，预备状态
                请求的动作已经启动；在下一个新命令之前，期望一个回应。（用户进程在接收到完成
                响应前就发送另一条命令是违返协议的。但服务器 FTP 进程在处理前面命令的过程中应该
                将后续收到的命令存入队列。）这种类型的响应用来表明命令已被接受，对于不能同时监视
                数据和控制连接的用户进程来说，它可能要开始关注数据的连接了。服务器 FTP 进程最多
                每个命令发送一个 1yz 代码。
        2）2yz，完成状态
                请求动作被成功的完成，一个新的请求可以开始。
        3）3yz，中间状态
                命令被接受，但是请求动作暂时没有被执行，等侍收到进一步的信息。用户应该发送另
                一个命令来指定这个信息。这个回应用在命令组合中。
        4）4yz，暂时拒绝状态
                命令没有被接受，请求动作没有发生，但是这个错误状态是暂时的，动作可以被再次请
                求。用户应该重新回到命令队列的开始。判断一个响应应该属于 4yz 号还是 5yz 号的一
                个规则是看这个命令是否可以不加修改并在相同的用户、服务器状态下（比如，命令使
                用同样的拼写使用同样的参数；用户不改变文件访问权限；服务器不产生新的实现。）
                再次重复。
        5）5yz，永久拒绝状态
                命令不被接受，请求动作不会发生。用户进程不能重复同样的请求（包括同样的命令顺
                序）。一些“永久的”错误状态可以被修正，因此人类用户也许希望控制用户进程在将来的
                某点上重新开始命令队列。（比如在拼写改变之后，或目录状态改变之后。）
    第二位数字的功能：
        x0z 语法 - 这种响应指出了语法错误。给出的命令不存在、没有被实现、或多余。
        x1z 信息 - 对于请求信息的响应，比如对状态或帮助的请求。
        x2z 连接 - 关于控制连接和数据连接的响应。
        x3z 身份验证和帐户 - 对登陆过程和帐户处理的响应。
        x4z 目前还未使用。
        x5z 文件系统 - 请求传输时服务器文件系统的状态或其他文件系统动作状态。
    第三位数字为第二位数字指定的状态提供了更详细的意义。
* 注意，每一个响应的对应文本只是推荐的，而非强制性的，可依照相应的命令而更改。另一方面，响应代码，必须严格
* 的遵守最后部分的规范，也就是说，服务器实现不应该为与上面所描述的只有微小区别的状态发明新的代码，而应该使
* 用已经定义的代码。
************/

typedef enum az_ftp_tmp_reply_e
{
    AZ_FTP_RESTART_MARK = 110,     //重新开始标记响应
    AZ_FTP_SERVER_READY = 120,     //服务将在稍后准备完成
    AZ_FTP_DATACONN_OK = 125,    //数据连接已打开，传输开始
    AZ_FTP_FILE_OK = 150,                //文件状态 OK，将打开数据连接
    AZ_FTP_TMPRESP_COUNT
}az_ftp_tmp_reply;

typedef enum az_ftp_complete_reply_e
{
    AZ_FTP_CMD_OK = 200,             //命令 OK
    AZ_FTP_CMD_SPFUS = 202,        //命令没有实现，对本站点冗余
    AZ_FTP_SYS_STAT_HELP = 211,   //系统状态，或者系统帮助响应
    AZ_FTP_DIR_STAT = 212,            //目录状态
    AZ_FTP_FILE_STAT = 213,           //文件状态
    AZ_FTP_HELP_MSG = 214,         //帮助信息
    AZ_FTP_SYS_TYPE = 215,           //系统类型名称
    AZ_FTP_SER_READY = 220,        //接受新用户服务准备完成
    AZ_FTP_LOGOUT_OK = 221,      //服务关闭控制连接(已注销)
    AZ_FTP_ABOR_OK = 225,           //数据连接打开，没有传输(abort命令执行成功)
    AZ_FTP_TRANSFER_OK = 226,    //请求文件动作成功
    AZ_FTP_PASV_OK = 227,           //进入被动模式
    AZ_FTP_LOGIN_OK = 230,         //用户成功登录
    AZ_FTP_REQ_FILE_OK = 250,     //请求文件动作 OK，完成
    AZ_FTP_CREATE_OK = 257,       //创建OK
    AZ_FTP_COMPRESP_COUNT
}az_ftp_complete_reply;

typedef enum az_ftp_middle_reply_e
{
    AZ_FTP_NEED_PASS = 331,               //用户名 OK，需要密码
    AZ_FTP_NEED_ACCT_LOGIN = 332,   //需要帐户才能登录
    AZ_FTP_NEED_FURTHER = 350,        //请求文件动作需要进一步的信息
    AZ_FTP_MIDRESP_COUNT
}az_ftp_middle_reply;

typedef enum az_ftp_tmperr_reply_e
{
    AZ_FTP_SER_CLOSE = 421,            //服务不可用，关闭控制连接
    AZ_FTP_DATACONN_ERR = 425,   //不能打开数据连接
    AZ_FTP_TRANSFER_ABOR = 426,   //连接关闭，放弃传输
    AZ_FTP_FILE_BUSY = 450,             //文件不可使用（如，文件忙）
    AZ_FTP_LOCAL_ERR = 451,           //请求动作放弃，处理中发生本地错误
    AZ_FTP_NO_SPACE = 452,            //系统存储空间不足
    AZ_FTP_TMPERR_COUNT
}az_ftp_tmperr_reply;

typedef enum az_ftp_err_reply_e
{
    AZ_FTP_CMD_PARAM_ERR = 501,        //参数语法错误
    AZ_FTP_CMD_NOT_IMPT = 502,          //命令没有实现
    AZ_FTP_CMD_BAD_SEQ = 503,            //命令顺序错误
    AZ_FTP_CMD_NOT_IMPT_PAR = 504,  //没有实现这个命令参数
    AZ_FTP_NO_LOGIN = 530,                  //没有登录成功
    AZ_FTP_NEED_ACCT_FILE = 532,         //需要帐户来存储文件
    AZ_FTP_FILE_ERR = 550,                     //文件不可用（如，没有找到文件，没有访问权限）
    AZ_FTP_PAGE_TYPE_ERR = 551,          //请求动作放弃，未知的页面类型
    AZ_FTP_OUT_ALLO = 552,                  //超出存储分配空间
    AZ_FTP_ILLEGAL_FILENAME = 553,     //文件名不允许
    AZ_FTP_ERRRESP_COUNT
}az_ftp_err_reply;

const char *_az_ftp_get_reason(int reply_code);

#endif