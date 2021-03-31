#include"cmd_histroy.h"
#include<azctools/az_memp.h>
#include<azctools/az_tools.h>

#define DEF_CACHE_NAME "cmd_histroy"
#define DEF_CACHE_SIZE 100

struct cmd_histroy_ctx_s
{
    az_memp mp;
    char *cache_path;
    int count;
    int size;
    az_utf8 *data;
};

cmd_histroy _create_histroy_ctx(const char *path, const char *file_name)
{
    az_memp pool = NULL;
    cmd_histroy tmp = NULL;

    pool = az_memp_create(AZ_MEM_POOL_DEFAULT_SIZE, false);
    if (pool == NULL)
        return NULL;

    tmp = (cmd_histroy)az_mpcalloc(pool, sizeof(cmd_histroy_t));
    if (tmp == NULL)
        goto ERR;
    tmp->mp = pool;
    tmp->size = DEF_CACHE_SIZE;
    tmp->data = (az_utf8 *)az_mpcalloc(tmp->mp, sizeof(az_utf8)*tmp->size);
    if (tmp->data == NULL)
        goto ERR;
    if (path != NULL && *path != '\0')
    {
        if (file_name == NULL || *file_name == '\0')
            file_name = DEF_CACHE_NAME;

        if (az_mkloop_dir(path) != 0)
            goto ERR;
        tmp->cache_path = (char *)az_mpcalloc(tmp->mp, sizeof(char)*(az_strlen(path) + az_strlen(file_name) + 2));
        if (tmp->cache_path == NULL)
            goto ERR;
        az_strncpy(tmp->cache_path, az_strlen(path) + 1, path, az_strlen(path));
        if (tmp->cache_path[az_strlen(path) - 1] != '/')
            az_strcatchr(tmp->cache_path, az_strlen(path) + az_strlen(file_name) + 2, '/');
        az_strcatstr(tmp->cache_path, az_strlen(path) + az_strlen(file_name) + 2, file_name);

        _load_histroy(tmp);
    }

    return tmp;
ERR:
    if (pool != NULL)
        az_memp_destory(pool);
    return NULL;
}

void _free_histroy_ctx(cmd_histroy *ctx)
{
    if (ctx == NULL || *ctx == NULL)
        return;
    _save_histroy(*ctx);
    az_memp_destory((*ctx)->mp);
    *ctx = NULL;
}

az_ret _load_histroy(cmd_histroy ctx)
{
    FILE *fp = NULL;
    char *data = NULL;
    int data_size = 0;
    int offset = 0;
    int num = 0;
    int jump_num = 0;

    if (ctx == NULL || ctx->cache_path == NULL || *ctx->cache_path == '\0')
        return AZ_ERROR;

    fp = fopen(ctx->cache_path, "r");
    if (fp == NULL)
        return AZ_ERROR;
    
    data = (char *)az_mpcalloc(ctx->mp, sizeof(char) * 1024);
    if (data == NULL)
        goto ERR;
    data_size += 1024;

    fgets(data, data_size, fp);
    if (az_strncmp(data, "histroy cmd::", az_strlen("histroy cmd::")) != 0)
        goto ERR;
    data[az_strlen(data) - 1] = '\0';
    num = atoi(data + 13);
    if (num <= 0)
        goto END;
    if (num > ctx->size)
        jump_num = num - ctx->size;
    fgets(data, data_size, fp);
    if (*data != '\n')
        goto ERR;

    if (ctx->count > 0)
    {
        int loop = 0;
        for (loop = 0; loop < ctx->count; loop++)
            az_utf8_free(&ctx->data[loop]);
    }
    ctx->count = 0;
    while (!feof(fp))
    {
        Az_Memzero(data, data_size);
        fgets(data + offset, data_size - offset, fp);
        if (data[az_strlen(data) - 1] != '\n' && az_strlen(data) == data_size - 1)
        {
            char *tmp = NULL;
            tmp = (char *)az_mprealloc(ctx->mp, (void **)&data, data_size + 1024);
            if (tmp == NULL)
                goto ERR;
            data = tmp;
            data_size += 1024;
            offset = az_strlen(data);
            continue;
        }
        if (jump_num > 0)
        {
            jump_num--;
            continue;
        }

        if (data[az_strlen(data) - 1] == '\n')
            data[az_strlen(data) - 1] = '\0';
        if (*data == '\0')
        {
            offset = 0;
            continue;
        }
        ctx->data[ctx->count] = az_utf8_create(ctx->mp, 0, data);
        if (ctx->data[ctx->count] == NULL)
            goto ERR;
        ctx->count++;
        offset = 0;
    }
END:
    fclose(fp);
    az_mpfree(ctx->mp, (void **)&data);
    return AZ_OK;
ERR:
    if (fp != NULL)
        fclose(fp);
    if (data != NULL)
        az_mpfree(ctx->mp, (void **)&data);
    if (ctx->count > 0)
        return AZ_OK;
    return AZ_ERROR;
}

az_ret _save_histroy(cmd_histroy ctx)
{
    FILE *fp = NULL;
    int loop = 0;

    if (ctx == NULL)
        return AZ_ERROR;
    if (ctx->cache_path == NULL || ctx->count == 0)
        return AZ_OK;

    fp = fopen(ctx->cache_path, "w");
    if (fp == NULL)
        return AZ_ERROR;

    fprintf(fp, "histroy cmd::%d\n\n", ctx->count);
    for (loop = 0; loop < ctx->count; loop++)
        fprintf(fp, "%s\n", az_utf8_tostr(ctx->data[loop], 0));
    fflush(fp);
    fclose(fp);

    return AZ_OK;
}

az_ret _insert_histroy(cmd_histroy ctx, az_utf8 cmd)
{
    int index = 0;

    if (ctx == NULL || cmd == NULL)
        return AZ_ERROR;
    if (az_utf8_len(cmd, 0) == 0)
        return AZ_OK;

    if (ctx->count == ctx->size)
    {
        az_utf8_free(&ctx->data[0]);
        Az_Memmove(&ctx->data[0], &ctx->data[1], sizeof(az_utf8)*(ctx->size - 1));
        ctx->count--;
    }
    index = ctx->count;

    ctx->data[index] = az_utf8_create(ctx->mp, az_utf8_len(cmd, 0), NULL);
    if (ctx->data[index] == NULL)
        return AZ_ERROR;
    az_utf8_copy(ctx->data[index], 0, cmd, 0);
    ctx->count++;

    return AZ_OK;
}

const az_utf8_t* _get_histroy(cmd_histroy ctx, int index)
{
    if (ctx == NULL || index >= ctx->count || index < 0)
        return NULL;
    return (const az_utf8_t *)ctx->data[index];
}

int _histroy_size(cmd_histroy ctx)
{
    if (ctx == NULL)
        return 0;
    return ctx->count;
}
