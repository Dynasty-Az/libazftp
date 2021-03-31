#ifndef __AZ_FTP_MESSAGE_H_INCLUDE__
#define __AZ_FTP_MESSAGE_H_INCLUDE__

#include<azftp/az_ftp_define.h>
#include"az_ftp_code.h"

/***********
* FTP命令解析
*  通过控制连接传输的命令是 Telnet 字符串，命令由一个命令代码开头，紧跟一个参数域。命令代码由四个或少于四个的字母组成，
*  大写或小写字符被认为等同。因此，下面这些都可以描述 RETRIEVE 命令。
*  RETR Retr retr ReTr rETr
*  这个规定也适用于参数符号，比如 A 或者 a 都表示 ASCII 类型。命令代码和参数域用一个或多个空格进行分隔。
*  对于 NVT-ASCII 表示，参数域由不定长度的字符串组成，并以字符序列<CRLF>结束(\r\n)；对于其它协商的语言，
*  可能会使用不同的行结束符。必须注意的是服务器在接收到行结束符之前不会做任何动作。
*  参数域的所有字符都是 ASCII 字符，包括十进制整数也是 ASCII 字符。用方括号括起来的表示可选参数。如果这些
*  参数没有被指定，则隐含使用默认值。
*     下面是 FTP 的命令：
*           USER<SP><username><CRLF>
*           PASS<SP><password><CRLF>
*           ACCT<SP><account-information><CRLF>
*           CWD<SP><pathname><CRLF>
*           CDUP<CRLF>
*           SMNT<SP><pathname><CRLF>
*           QUIT<CRLF>
*           REIN<CRLF>
*           PORT<SP><host-port><CRLF>
*           PASV<CRLF>
*           TYPE<SP><type-code><CRLF>
*           STRU<SP><structure-code><CRLF>
*           MODE<SP><mode-code><CRLF>
*           RETR<SP><pathname><CRLF>
*           STOR<SP><pathname><CRLF>
*           STOU<CRLF>
*           APPE<SP><pathname><CRLF>
*           ALLO<SP><decimal-integer>[<SP>R<SP><decimal-integer>]<CRLF>
*           REST<SP><marker><CRLF>
*           RNFR<SP><pathname><CRLF>
*           RNTO<SP><pathname><CRLF>
*           ABOR<CRLF>
*           DELE<SP><pathname><CRLF>
*           RMD<SP><pathname><CRLF>
*           MKD<SP><pathname><CRLF>
*           PWD<CRLF>
*           LIST[<SP><pathname>]<CRLF>
*           NLST[<SP><pathname>]<CRLF>
*           SITE<SP><string><CRLF>
*           SYST<CRLF>
*           STAT[<SP><pathname>]<CRLF>
*           HELP[<SP><string>]<CRLF>
*           NOOP<CRLF>
*     下面是 FTP 命令参数(BNF表示法)：
*           <username> ::= <string>
*           <password> ::= <string>
*           <account-information> ::= <string>
*           <string> ::= <char> | <char><string>
*           <char> ::= any of the 128 ASCII characters except <CR> and <LF>
*           <marker> ::= <pr-string>
*           <pr-string> ::= <pr-char> | <pr-char><pr-string>
*           <pr-char> ::= printable characters, any ASCII code 33 through 126
*           <byte-size> ::= <number>
*           <host-port> ::= <host-number>,<port-number>
*           <host-number> ::= <number>,<number>,<number>,<number>
*           <port-number> ::= <number>,<number>
*           <number> ::= any decimal integer 1 through 255
*           <form-code> ::= N | T | C
*           <type-code> ::= A [<sp><form-code>]
*                                     | E [<sp> <form-code>]
*                                     | I
*                                     | L <sp> <byte-size>
*           <structure-code> ::= F | R | P
*           <mode-code> ::= S | B | C
*           <pathname> ::= <string>
*           <decimal-integer> ::= any decimal integer
*    FTP 的命令按照功能分类：
*       1）访问控制命令
*            用户名（USER）
*               这个命令的参数域是一个用来标识用户的 Telnet 字符串。用户识别对于服务器控制文件系统存取权限是必需的。这个命令通常是控制
*               连接建立后从用户端发送的第一条命令(一些服务器可能需要保证这一点)。一些服务器可能还需要附加的识别信息如密码或帐号命令。
*               为了改变控制权限和/或帐户信息，服务器可能在任何时候都允许接受一个新的 USER 命令，来更换存取权限或帐户信息。产生的效果
*               是刷新早先登录的用户名、密码和帐户信息，并重新开始一个登录过程。所有的传输参数不发生变化，并且所有正在传输中的文件传输
*               过程均在原来的访问控制权限下完成。
*            密码（PASS）
*               这个命令的参数域是一个用来指定用户密码的 Telnet 字符串。这个命令必须紧跟在用户名命令之后，在某些站点上，它用来完成用户
*               访问权限识别。因为密码信息非常敏感，一般应该使用掩码代替或者禁止回显。显然服务器没有安全的办法做到这一点，所以隐藏敏感
*               的密码信息就成了用户 FTP 进程的责任。
*            帐户（ACCT）
*               这个命令的参数域是一个用来识别用户帐户的 Telnet 字符串。这个命令不需要和 USER命令相关，某些站点可能需要一个帐户用来登录，
*               另一些站点仅用于特殊访问权限，比如存储文件。后一种情况下这个命令可能在任何时候收到。有一些响应代码用来自动地区分这些情
*               况：当登录过程必须要求帐户信息的时候，PASS命令成功的响应代码是 332。相应，如果登录过程不要求帐户信息时，PASS 命令成功的
*               响应代码是 230；如果帐户信息需要在随后的对话命令中给出，服务器应该根据是保留（等侍收到 ACCT 命令）还是放弃命令来相应的返
*               回 332 或 532。
*            改变工作目录（CWD）
*               这个命令允许用户在不改变登录用户和帐户信息的情况下改变工作目录或数据集。传输参数保持不变。这个命令的参数是一个路径名，用
*               来指定相应的目录或者其他系统上的文件组名。
*            返回上层目录（CDUP）
*               这个命令是CWD命令的特例，因为在不同的操作系统下表达父目录可能有不同的语法，所以可以用这个命令简化目录树的传输实现。它的
*               响应代码应该和 CWD 的响应代码相同。
*            结构装备（SMNT）
*               这个命令允许用户在不改变用户和帐户信息的情况下装备一个不同的文件系统数据结构。传置传输参数不会改变。它的参数是一个用来标识
*               目录或者其他系统中依赖文件组的路径名。
*            重新初始化（REIN）
*               此命令除允许当前正在传输过程完成外，终止一个用户，刷新所有的 I/O 和帐户信息。所有参数重设为默认值，并保持控制连接。此时等同
*               于控制连接刚刚建立的状态。这条命令之后可能需要 USER 命令。
*            注销 (QUIT)
*               此命令终止一个用户，并且当没有文件正在传输的话，服务器将关闭控制连接。如果当前有文件正在传输，连接会保持并等待回应，之后服务
*               器将关闭连接。如果用户进程想以不同的用户名传输文件，而不想关闭然后再重建立连接的情况下，应该使用 REIN 命令而不是QUIT。
*               控制连接的意外关闭将会导致服务器产生等同于放弃（ABOR）和注销（QUIT）动作。
*       2）传输参数命令
*          所有的数据传输参数都有默认值，只有在默认值需要改变的时候才需要用命令去指定传送数据传输参数。默认值是最后一次指定的值，或者
*          如果未被指定，则是标准默认值。这意味着服务器必须“记住”可用的默认值。这些命令可以在 FTP 服务请求前以任何顺序执行。
*            数据端口（PORT）
*               这个参数是用来指定数据连接时的主机数据端口。对于用户和服务器都有默认的数据端口值，并且一般情况下这条命令以及它的响应都不需要。
*               如果使用了这条命令，那它的参数是一个 32 位的因特网主机地址和一个 16 位 TCP 端口号。地址信息被分解为每 8 位一个段，每个段都作为
*               十进制数(用字符串表示)传送。段之间用逗号分隔，一个 PORT 命令像下面这样：
*                                    PORT h1,h2,h3,h4,p1,p2
*                                    h1 是因特网主机地址的高 8 位。
*            被动 (PASV)
*               此命令请求服务器 DTP 在一个数据端口(不是它的默认端口)上“监听”并等待连接而不是在收到传输命令后主动发起连接。这个命令的响应包括
*               服务器监听的地址和端口号。
*            表示类型（TYPE）
*               这个命令的参数指定在数据表示和存储部分介绍的表示类型。某些类型需要第二个参数。第一个参数用单个 Telnet 字符表示，对于 ASCII 和
*               EBCDIC 的第二个格式化参数也是如此;本地字节的第二个参数是一个表示字节长度的十进制整数。参数之间用<SP>(空格，ASCII 码的32)分开。
*                    下面的编码用来表示类型：
*                                    \        /
*                     A - ASCII  |        | N - 非打印
*                                     |-><-| T - Telnet 格式
*                  E - EBCDIC  |        | C - Carriage Control (ASA)
*                                    /         \
*                       I - 图像
*                    L <字节长度>- 本地字节长度
*               默认的表示类型是 ASCII 非打印。如果格式化参数首先被更改，然后单独更改第一个参数，格式化参数会变回默认的非打印。
*            文件结构（STRU）
*               这个命令的参数是单个 Telnet 字符，用来指定在数据表示和存储部分描述的文件结构。
*                   下面编码用来表示文件结构：
*                       F - 文件 (没有记录的结构)
*                       R - 记录结构
*                       P - 页结构
*                   默认的结构是文件。
*            传输模式（MODE）
*               这个命令的参数是单个 Telnet 字符，用来指定在传输模式部分描述的数据传送传输模式。
*                   下面的编码用来表示传送模式：
*                       S - 流
*                       B - 块
*                       C - 压缩
*                   默认的传送模式是流。
*       3）服务命令
*          服务命令定义了用户请求传送文件或者文件系统的功能。FTP 服务命令的参数一般是一个路径。路径的语法必须符合服务器站点的惯例（尽量用
*          默认标准）和控制连接的语言习惯。建议的默认参数是使用最后一个设备，目录或文件名，或者本地用户的默认标准。除"rename from"命令后
*          面必须紧跟"rename to"命令以及restart命令必须紧跟随中断服务命令(例如 STOR 或 RETR)之外，其他命令可以使用任意的顺序。服务器应当总
*          是使用数据连接来发送服务命令响应数据，只有少数特定的信息响应除外。
*            获得 (RETR)
*               这个命令引起服务器 DTP 传送一个由路径指定的文件拷贝到数据连接另一端的服务器或用户 DTP。服务器文件的状态和内容应该不受影响。
*            保存 (STOR)
*               这个命令引起服务器 DTP 接受经过数据连接传送的数据并将这些数据存储为服务器端的一个文件。如果在路径参数里指定的文件在服务器端
*               已经存在，那么这个文件会被传送过来的数据覆盖。如果指定的文件不存在则会在服务器端新建一个文件。
*            唯一保存 (STOU)
*               这个命令类似于 STOR 命令，但是它会在在当前目录下创建一个名字唯一的文件。在250 号标准响应里必须包含创建出的文件名。
*            追加 (包括创建) (APPE)
*               这个命令引起服务 DTP 接受从数据连接传送过来的数据并存储在服务器端的一个文件里。如果指定的文件在服务器端已经存在，则这个数据
*               会附加到文件的后面；否则服务器端会创建这个文件。
*            分配 (ALLO)
*               一些服务器可能要求用这个命令来保留足够的空间来容纳新文件。其参数是一个十进制整数，用来指定保留给文件存储用的字节数（用逻辑字
*               节长度)。对于用记录或者而结构传送的文件而言，还需要有最大结构或页的大小（使用逻辑字节），这个值在这个命令的第二个参数域用十进
*               制整数指定。第二个参数是可选的，但当它存在的时候应该用三个 Telnet字符<SP>R<SP>和第一个参数分开。这个命令之后应该是 STOR 或
*               者 APPE 命令。在那些不需要预先知道文件最大值的服务器上，这个命令应该被作为 NOOP(无操作)对待，在那些只对记录或页最大值感兴趣
*               的服务器上应该忽略第一个参数。
*            重新开始 (REST)
*               这个命令的参数域指定了需要重新开始传输的文件的位置标记。这个命令不会引起文件的传输，只是忽略文件中指定标记点前的数据。
*            重命名开始 （RNFR）
*               这个命令指定了需要重新命名的文件的原始路径名。后面必须马上接着“重命名为”命令，来指定新的文件路径。
*            重命名为 （RNTO）
*               这个命令为在“重命名开始”命令中指定的文件指定新的路径。这两个命令一起为文件重新命名。
*            放弃（ABOR）
*               该命令告诉服务器放弃先前的 FTP 服务命令和相关的传输的数据。放弃命令也许需要引起服务器的“特别注意”（参见 FTP 命令部分），使服
*               务器强制识别。当前一个命令（包括数据传输）完成时，将不会产生动作。服务器不会关闭控制连接，但是数据连接必须关闭。服务器接收这个
*               命令时可能处在两种状态：(1)FTP 服务命令已经完成，或者(2)FTP 服务命令还在执行中。第一种情况，服务器关闭数据连接（如果数据连接是
*               打开的）回应 226 代码，表示放弃命令已经成功处理。第二种情况，服务器放弃正在进行的 FTP 服务，关闭数据连接，返回 426 响应代码，表
*               示请求服务请求异常终止。然后服务器发送 226 响应代码，表示放弃命令成功处理。
*            删除 (DELE)
*               这个命令在服务器端删除指定的文件。如果需要额外的保护（比如讯问“你丫的真的想删除么？”），应该由用户 FTP 进程提供。
*            删除目录（RMD）
*               这个命令移除指定路径下的目录（如果是绝对路径），或者是当前工作目录的子目录（如果是相对路径）。
*            新建目录（MKD）
*               该命令在指定的路径下新建一个目录（如果是绝对路径），或者在当前工作目录下建子目录（如果路径是相对的）。
*            打印工作目录（PWD）
*               该命令返回一个当前的工作目录名。
*            列表（LIST）
*               该命令从服务器端发送一个列表到被动的 DTP。如果路径名指定了目录或者别的文件组，服务器应该传送指定目录下的文件列表。如果路径名
*               指定了文件，服务器应当传送这个文件的信息。没有参数，意味着用户的当前工作目录或者缺省目录。数据通过数据连接以ASCII 或 EBCDIC
*               类型传输。（用户必须确定类型是 ASCII 或者 EBCDIC）。因为不同系统间的文件信息差别很大，这个信息可能不易被程序自动使用，但可能
*               对于用户来说是有用处的。
*            名字列表 （NLST）
*               该命令从服务器端传送目录列表到用户端。路径名应该指定一个目录名或者其他系统文件组描述符；无参数意味着当前目录。服务器只返回文件
*               的名字组成的字节流，不包括其他的信息。数据将通过数据连接以ASCII或者 EBCDIC 类型传输，每个路径名字符串由<CRLF>或<NL>分割（用
*               户仍必须保证类型使用正确）。这个命令的响应信息将可能被用于程序对文件的自动处理。例如，多线程下载的实现。
*            站点参数（SITE）
*               服务器使用这个命令，提供本系统可能对文件传输有帮助的特殊服务。在协议中它的用处不是很普遍。服务的种类和语法规约可以在 HELP SITE 命令
*               的响应中确定。
*            系统（SYST）
*               该命令来得到服务器端操作系统的类型。响应的第一个词应该是 Assigned Numbers 文档[4]中表示操作系统名字的一个词。
*            状态 （STAT）
*               该命令应该通过控制连接以响应码的形式返回状态信息。此命令可能在文件传输过程中发出（与 Telnet IP 和同步信号一起，参见 FTP 命令道听部分），
*               此时服务器将返回正在传输的状态。或者这个命令也可能在两个文件传输过程之间发出，这种情况下，命令可能将有一个参数域。如果参数指定了一个
*               路径名，则命令将与列表命令类似，只是数据由控制连接传输。如果给出了部分路径，服务器可能响应指定的路径下的文件名列表或者相关属性。如果
*               没有提供参数，将返回服务器 FTP 进程一般的状态信息，其中应该包括所有传输参数的当前值和连接的状态。
*            帮助（HELP）
*               该命令使服务器通过控制连接传送关于具体实现状态的帮助信息给用户。该命令可以有参数（例如，命令的名字）返回更加具体的信息。回应代码是
*               211 或者 214。建议在输入 USER命令前允许 HELP。服务器可以用这个响应指定站点特定的参数，例如，在 HELP SITE 响应中指定。
*            空操作（NOOP）
*               该命令不应影响任何参数或者之前发送的命令。该命令不指定任何动作，只是要求服务器返回 OK 响应。
***********/

#ifndef AZ_FTP_COMMAND_LEN
#define AZ_FTP_COMMAND_LEN 8
#endif // !AZ_FTP_COMMAND_LEN
#ifndef AZ_FTP_ARGV_MAX_NUM
#define AZ_FTP_ARGV_MAX_NUM 5
#endif // !AZ_FTP_ARGV_MAX_NUM
#ifndef AZ_FTP_ARGV_MAX_LEN
#define AZ_FTP_ARGV_MAX_LEN 1024
#endif // !AZ_FTP_ARGV_MAX_LEN

typedef struct az_ftp_msg_s
{
    az_memp mp;
    az_ftp_cmd cmd_index;
    int code;
    int argc;
    char **argv;
    char *reason;
    char *str;
}az_ftp_msg_t, *az_ftp_msg;

#define msg_is_reply(msg) (msg->code >= 100 && msg->code < 600)
#define msg_is_cmd(msg) (!msg_is_reply(msg))
/*
#define az_ftp_response(mp, list, code, res) \
{ \
    az_ftp_msg reply_d = NULL; \
    reply_d = az_ftp_make_reply(mp, code, res); \
    if (reply_d != NULL) \
        az_list_insert(list, AZ_LIST_TAIL, 0, &reply_d, sizeof(az_ftp_msg)); \
    while (az_list_size(list) > 0) \
        az_msleep(10); \
}
*/

az_ftp_msg az_ftp_msg_create(az_memp pool);
const char* az_ftp_msg_to_str(az_ftp_msg msg);
void az_ftp_msg_free(az_ftp_msg *msg);

int az_ftp_command_parser(az_memp pool, char *recv_buf, int buf_len, int *data_len, az_ftp_msg *cmd);
int az_ftp_reply_parser(az_memp pool, char *recv_buf, int buf_len, int *data_len, az_ftp_msg *cmd);

az_ftp_cmd az_ftp_msg_get_cmd(az_ftp_msg cmd);
int az_ftp_msg_get_argc(az_ftp_msg cmd);
const char* az_ftp_msg_get_argv(az_ftp_msg cmd, int index);
int az_ftp_msg_add_argv(az_ftp_msg cmd, const char *argv);

int az_ftp_msg_get_code(az_ftp_msg reply);
const char* az_ftp_msg_get_res(az_ftp_msg reply);

az_ftp_msg az_ftp_make_cmd(az_memp pool, az_ftp_cmd cmd, const char *argv);
az_ftp_msg az_ftp_make_reply(az_memp pool, int code, const char *res);

#endif