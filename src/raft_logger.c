#include "_raft_logger.h"

static RAFT_LOGGER_IMPL g_logger_cb = NULL;

int raft_logger_printf(int level, const char *func, const char *file, int line, const char *format, ...)
{
    int ret = 0;

    if (g_logger_cb) {
        va_list ap;

        va_start(ap, format);
        ret = g_logger_cb(level, func, file, line, format, &ap);
        va_end(ap);
    }

    return ret;
}

int raft_logger_setup(RAFT_LOGGER_IMPL lcb)
{
    g_logger_cb = lcb;
}

