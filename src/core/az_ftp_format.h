#ifndef __AZ_FTP_FORMAT_H_INCLUDE__
#define __AZ_FTP_FORMAT_H_INCLUDE__

//#include<iconv.h>
#include<azftp/az_ftp_define.h>

typedef enum az_text_format_e
{
    AZ_FORMAT_UNKNOWN,
    AZ_FORMAT_ANSI,
    AZ_FORMAT_ASCII,
    AZ_FORMAT_UTF8,// UTF8 without BOM
    AZ_FORMAT_UTF8_BOM,// UTF8 with BOM
    AZ_FORMAT_UNICODE,// UTF16 LE without BOM
    AZ_FORMAT_UNICODE_BOM,// UTF16 LE with BOM
    AZ_FORMAT_UNICODE_BE,// UTF16-BE without BOM
    AZ_FORMAT_UNICODE_BOM_BE,// UTF16-BE with BOM
    AZ_FORMAT_UTF32,//UTF-32-LE without BOM
    AZ_FORMAT_UTF32_BOM,//UTF-32-LE with BOM
    AZ_FORMAT_UTF32_BE,//UTF-32-BE without BOM
    AZ_FORMAT_UTF32_BOM_BE,//UTF-32-BE with BOM
    AZ_FORMAT_GB2312,
    AZ_FORMAT_GBK,
    AZ_FORMAT_BIG5,
    AZ_FORMAT_COUNT
}az_format;

az_format az_check_ascii_utf8(const char *str, size_t in_len, int *format_byte);

#endif