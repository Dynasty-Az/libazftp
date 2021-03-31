#include"az_ftp_code.h"

#define set_argv(n) \
{ \
    reasons = reasons##n##xx; \
    len = sizeof(reasons##n##xx) / sizeof(*reasons); \
}

const char *_az_ftp_get_reason(int reply_code)
{
    struct code_to_reason
    {
        int code;
        const char *reason;
    };

    static const struct code_to_reason reasons1xx[] = {
        { 110, "Restart marker reply" },
        { 120, "Service ready in some minutes" },
        { 125, "Data connection already open; transfer starting" },
        { 150, "File status okay; about to open data connection" },
    };
    static const struct code_to_reason reasons2xx[] = {
        { 200, "Command okay" },
        { 202, "Command not implemented, superfluous at this site" },
        { 211, "System status, or system help reply" },
        { 212, "Directory status" },
        { 213, "File status" },
        { 214, "Help message" },
        { 215, "NAME system type" },
        { 220, "Service ready for new user" },
        { 221, "Service closing control connection" },
        { 225, "Data connection open; no transfer in progress" },
        { 226, "Closing data connection" },
        { 227, "Entering Passive Mode" },
        { 230, "User logged in, proceed" },
        { 250, "Requested file action okay, completed" },
        { 257, "created" },
    };
    static const struct code_to_reason reasons3xx[] = {
        { 331, "User name okay, need password" },
        { 332, "Need account for login" },
        { 350, "Requested file action pending further information" },
    };
    static const struct code_to_reason reasons4xx[] = {
        { 421, "Service not available, closing control connection" },
        { 425, "Can't open data connection" },
        { 426, "Connection closed; transfer aborted" },
        { 450, "Requested file action not taken" },
        { 451, "Requested action aborted. Local error in processing" },
        { 452, "Requested action not taken" },
    };
    static const struct code_to_reason reasons5xx[] = {
        { 501, "Syntax error in parameters or arguments" },
        { 502, "Command not implemented" },
        { 503, "Bad sequence of commands" },
        { 504, "Command not implemented for that parameter" },
        { 530, "Not logged in" },
        { 532, "Need account for storing files" },
        { 550, "Requested action not taken" },
        { 551, "Requested action aborted. Page type unknown" },
        { 552, "Requested file action aborted" },
        { 553, "Requested action not taken" },
    };

    const struct code_to_reason *reasons;
    int len, i;

    switch (reply_code / 100)
    {
    case 1:
        set_argv(1)
        break;
    case 2:
        set_argv(2)
        break;
    case 3:
        set_argv(3)
        break;
    case 4:
        set_argv(4)
        break;
    case 5:
        set_argv(5)
        break;
    default:
        return NULL;
    }

    for (i = 0; i < len; i++)
        if (reasons[i].code == reply_code)
            return reasons[i].reason;

    /* Not found. */
    return NULL;
}
