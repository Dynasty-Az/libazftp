#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>
#include <stdlib.h>
#include <string.h>

/* Information about filling a column.  */
struct column_info
{
    int valid_len;
    int line_len;
    int *col_arr;
};
struct column_info *column_info;

static int line_length;

/* Maximum number of columns ever possible for this display.  */
static int max_idx;

/* The minimum width of a colum is 3: 1 character for the name and 2
for the separating white space.  */
#define MIN_COLUMN_WIDTH    3

static inline int
cmp_str(char const *lhs, char const *rhs,
    int(*cmp)(char const *, char const *))
{
    return cmp(lhs, rhs);
}

static int
compare_str(const void *lhs, const void *rhs)
{
    return cmp_str(*(char **)lhs, *(char **)rhs, strcoll);
}

unsigned short int get_ws_col()
{
    struct winsize size;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
    return size.ws_col;
}

static void
init_column_info(void)
{
    int i;
    int allocate = 0;

    line_length = get_ws_col();
    max_idx = line_length / MIN_COLUMN_WIDTH;
    if (max_idx == 0)
        max_idx = 1;

    if (column_info == NULL)
    {
        column_info = malloc(sizeof(struct column_info) * max_idx);
        allocate = 1;
    }

    for (i = 0; i < max_idx; ++i)
    {
        int j;

        column_info[i].valid_len = 1;
        column_info[i].line_len = (i + 1) * MIN_COLUMN_WIDTH;

        if (allocate)
            column_info[i].col_arr = (int *)malloc(sizeof(int) * (i + 1));

        for (j = 0; j <= i; ++j)
            column_info[i].col_arr[j] = MIN_COLUMN_WIDTH;
    }
}

static void
indent(int from, int to)
{
    while (from < to)
    {
        putchar(' ');
        from++;
    }
}

static void
print_many_per_line(char *arr[], size_t files_index)
{
    struct column_info *line_fmt;
    int filesno;            /* Index into files. */
    int row;                /* Current row. 当前行*/
    int max_name_length;    /* Length of longest file name + frills.最长文件名的长度+褶边。 */
    int name_length;        /* Length of each file name + frills. 每个文件名的长度+褶边。*/
    int pos;            /* Current character column. 当前字符列。*/
    int cols;            /* Number of files across. 文件数。*/
    int rows;            /* Maximum number of files down. 已关闭的最大文件数。*/

    int max_cols;

    init_column_info();
    /* Normally the maximum number of columns is determined by the
    screen width.  But if few files are available this might limit it
    as well.  通常，最大列数由屏幕宽度决定。但如果可用的文件很少，这也可能会限制它。*/
    max_cols = max_idx > files_index ? files_index : max_idx;

    /* Compute the maximum number of possible columns.  计算可能的最大列数。*/
    for (filesno = 0; filesno < files_index; ++filesno)
    {
        int i;

        name_length = strlen(arr[filesno]);

        for (i = 0; i < max_cols; ++i)
        {
            if (column_info[i].valid_len)
            {
                int idx = filesno / ((files_index + i) / (i + 1));
                int real_length = name_length + (idx == i ? 0 : 2);
                if (real_length > column_info[i].col_arr[idx])
                {
                    column_info[i].line_len += (real_length
                        - column_info[i].col_arr[idx]);
                    column_info[i].col_arr[idx] = real_length;
                    column_info[i].valid_len = column_info[i].line_len < line_length;
                }
            }
        }

    }

    /* Find maximum allowed columns.  查找允许的最大列数。*/
    for (cols = max_cols; cols > 1; --cols)
    {
        if (column_info[cols - 1].valid_len)
            break;
    }

    line_fmt = &column_info[cols - 1];

    /* Calculate the number of rows that will be in each column except possibly
    for a short column on the right.  计算每列中的行数，可能除了右侧的短列。*/
    rows = files_index / cols + (files_index % cols != 0);

    for (row = 0; row < rows; row++)
    {
        int col = 0;
        filesno = row;
        pos = 0;
        /* Print the next row.  */
        while (1)
        {
            printf("%s", arr[filesno]);
            name_length = strlen(arr[filesno]);
            max_name_length = line_fmt->col_arr[col++];

            filesno += rows;
            if (filesno >= files_index)
                break;

            indent(pos + name_length, pos + max_name_length);
            pos += max_name_length;
        }
        putchar('\n');
    }
}

void main()
{

    char *arr[] =
    {
        "asdfasdf",
        "adfasdf",
        "sdfdaasd",
        "sdfasdfasdg",
        "ghjsdfa",
        "asdfadsf",
        "dgfsdg",
        "文件",
        "gsdgsrg",
        "sdfgs",
        "dfgsdhsdfgj",
        "sdfg",
        "qwersdfgsdfhs",
        "sdfhfhdfgh",
        "sdfg",
        "dfgsdfg",
        "sdfg",
        "dsfgsdfg",
        "电影",
        "gsdfgsdfg",
        "sdfgsdf",
        "游戏",
        "sdfgsdfg",
        "dfghdfgjd",
        "dfgh",
        "sdfg",
        "rsdfhfdgh",
        "sdfhdf",
        "dfgh",
        "syutdfhsgd",
        "ksdfgdsf",
        "fgsdh",
        "sdfh",
        "yuosdfhsf",
        "vbdfh",
        "sdjklfhs",
        "erfhsdfh",
        "sdfh",
        "sdfhsdfh",
        "sdfh",
        "wery",
        "weywery",
        "dfgh",
        "sdfg",
        "sdfhfdgh",
        "sdfhdf",
        "dfgh",
        "sdfhsgd",
        "sdfgdsf",
        "sdfgsdh",
        "sdfh",
        "sdfhsf",
        "sdfh",
        "retfhs",
        "fhsdfh",
        "yudfh",
        "sdfhsdfh"
    };

    qsort(arr, sizeof(arr) / sizeof(arr[0]), sizeof(arr[0]), (__compar_fn_t)compare_str);
    print_many_per_line(arr, sizeof(arr) / sizeof(arr[0]));

    return;
}