#ifndef __CMD_HISTROY_H_INCLUDE__
#define __CMD_HISTROY_H_INCLUDE__

#include<azctools/az_utf8_str.h>

typedef struct cmd_histroy_ctx_s cmd_histroy_t, *cmd_histroy;

cmd_histroy _create_histroy_ctx(const char *path, const char *file_name);
void _free_histroy_ctx(cmd_histroy *ctx);
az_ret _load_histroy(cmd_histroy ctx);
az_ret _save_histroy(cmd_histroy ctx);
az_ret _insert_histroy(cmd_histroy ctx, az_utf8 cmd);
const az_utf8_t* _get_histroy(cmd_histroy ctx, int index);
int _histroy_size(cmd_histroy ctx);

#endif