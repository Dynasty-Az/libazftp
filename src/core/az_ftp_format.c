#include"az_ftp_format.h"

az_format az_check_ascii_utf8(const char *str, size_t in_len, int *format_byte)
{
    int data_count = 0;
    size_t loop = 0;
    int ascii_flag = 1;

    for (loop = 0; loop < in_len; loop++)
    {
        if (data_count == 0)
        {
            if ((str[loop] & 0x80) == 0x00)
                data_count = 0;
            else if ((str[loop] & 0xF8) == 0xF0)
                data_count = 3;
            else if ((str[loop] & 0xF0) == 0xE0)
                data_count = 2;
            else if ((str[loop] & 0xE0) == 0xC0)
                data_count = 1;
            else
            {
                if (format_byte != NULL)
                    *format_byte = 0;
                return AZ_FORMAT_UNKNOWN;
            }
            if (format_byte != NULL)
                *format_byte = (data_count + 1) > *format_byte ? (data_count + 1) : *format_byte;
        }
        else
        {
            ascii_flag = 0;//多字节编码，不是ascii

            if ((str[loop] & 0xC0) != 0x80)
            {
                if (format_byte != NULL)
                    *format_byte = 0;
                return AZ_FORMAT_UNKNOWN;//不是utf8
            }
            data_count--;
        }
    }

    if (ascii_flag == 1)
        return AZ_FORMAT_ASCII;

    return AZ_FORMAT_UTF8;
}
