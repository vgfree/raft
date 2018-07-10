#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#if defined(__LINUX__) || defined(__linux__)
  #include <syslog.h>
#else
  #define LOG_EMERG     0       /* system is unusable */
  #define LOG_ALERT     1       /* action must be taken immediately */
  #define LOG_CRIT      2       /* critical conditions */
  #define LOG_ERR       3       /* error conditions */
  #define LOG_WARNING   4       /* warning conditions */
  #define LOG_NOTICE    5       /* normal but significant condition */
  #define LOG_INFO      6       /* informational */
  #define LOG_DEBUG     7       /* debug-level messages */
#endif

#if !defined(LOCAL)
  #define __LOCAL(var, line)    __ ## var ## line
  #define _LOCAL(var, line)     __LOCAL(var, line)
  #define LOCAL(var)            _LOCAL(var, __LINE__)
#endif

#ifndef __FILENAME__
  #define __FILENAME__ ({ const char *LOCAL(p) = strrchr(__FILE__, '/'); LOCAL(p) ? LOCAL(p) + 1 : __FILE__; })
#endif

typedef int (*RAFT_LOGGER_IMPL)(short syslv, const char *func, const char *file, int line, const char *format, va_list *ap);

int raft_logger_setup(RAFT_LOGGER_IMPL lcb);

int raft_logger_printf(short syslv, const char *func, const char *file, int line, const char *format, ...);

#define raft_printf(syslv, fmt, ...) \
    raft_logger_printf(syslv, __FUNCTION__, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__)

