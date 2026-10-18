/* GCC 16.2-open2 runtime shims that are intentionally absent from libnix. */

#include <dos/dos.h>
#include <proto/dos.h>
#include <stdio.h>
#include <string.h>
#include <workbench/startup.h>
#ifdef OPENAMIGAPYTHON_STARTUP_TRACE
#include <stabs.h>
#endif

#ifndef OPENAMIGA_GCC_OPEN2
#error "open2_runtime.c is only for the ac4 GCC 16.2-open2 build"
#endif

/* libnix leaves Workbench startup retrieval to the application. */
struct WBStartup *WBenchMsg = NULL;

/*
 * libnix getenv() walks its Unix-style environment representation and can
 * block under the AmigaChrome launch environment.  CPython only needs a
 * borrowed value long enough to consume it, so use a small rotating set of
 * dos.library-backed buffers.  Local variables shadow the global ENV: value,
 * matching AmigaDOS command semantics.
 */
char *
openamiga_ac4_getenv(const char *name)
{
    enum { ENV_SLOTS = 8, ENV_SIZE = 2048 };
    static char values[ENV_SLOTS][ENV_SIZE];
    static unsigned int next_slot;
    char *value;
    LONG length;

    if (name == NULL || *name == '\0')
        return NULL;

    value = values[next_slot++ % ENV_SLOTS];
    length = GetVar((STRPTR)name, (STRPTR)value, ENV_SIZE - 1,
                    GVF_LOCAL_ONLY);
    if (length < 0)
        length = GetVar((STRPTR)name, (STRPTR)value, ENV_SIZE - 1,
                        GVF_GLOBAL_ONLY);
    if (length < 0)
        return NULL;
    if (length >= ENV_SIZE)
        length = ENV_SIZE - 1;
    value[length] = '\0';
    return value;
}

/*
 * Opt-in startup tracing for target-side bring-up.  This deliberately uses
 * dos.library directly so it remains useful before CPython has initialized
 * its own file objects.  Set ENV:OPENAMIGAPYTHON_TRACE to enable it.
 */
void
openamiga_ac4_trace(const char *message)
{
#ifndef OPENAMIGAPYTHON_STARTUP_TRACE
    char enabled[8];
#endif
    char path[256];
    BPTR file;
    LONG length;
    LONG path_length;

    if (message == NULL)
        return;
#ifndef OPENAMIGAPYTHON_STARTUP_TRACE
    if (GetVar((STRPTR)"OPENAMIGAPYTHON_TRACE", (STRPTR)enabled,
               (LONG)sizeof(enabled), GVF_GLOBAL_ONLY) < 0 &&
        GetVar((STRPTR)"OPENAMIGAPYTHON_TRACE", (STRPTR)enabled,
               (LONG)sizeof(enabled), GVF_LOCAL_ONLY) < 0)
        return;
#endif

#ifdef OPENAMIGAPYTHON_STARTUP_TRACE
    strcpy(path, "DH0:ACAgent/OpenAmigaPython.trace");
#else
    strcpy(path, "T:OpenAmigaPython.trace");
#endif
    path_length = GetVar((STRPTR)"OPENAMIGAPYTHON_TRACE_FILE",
                         (STRPTR)path, (LONG)sizeof(path) - 1,
                         GVF_GLOBAL_ONLY);
    if (path_length < 0)
        path_length = GetVar((STRPTR)"OPENAMIGAPYTHON_TRACE_FILE",
                             (STRPTR)path, (LONG)sizeof(path) - 1,
                             GVF_LOCAL_ONLY);
    if (path_length >= 0)
        path[path_length < (LONG)sizeof(path) ? path_length :
             (LONG)sizeof(path) - 1] = '\0';

    file = Open((STRPTR)path, MODE_READWRITE);
    if (file != (BPTR)0)
        Seek(file, 0, OFFSET_END);
    else
        file = Open((STRPTR)path, MODE_NEWFILE);
    if (file == (BPTR)0)
        return;

    length = (LONG)strlen(message);
    Write(file, (APTR)message, length);
    Write(file, (APTR)"\n", 1);
    Close(file);
}

#ifdef OPENAMIGAPYTHON_STARTUP_TRACE
/*
 * Bracket libnix's ordered startup list.  The stored priorities are the
 * signed ADD2INIT priority plus 128; these probes sit between the library
 * initializers used by the ac4 executable and disappear from release builds.
 */
#define AC4_INIT_PROBE(name, priority, message) \
    void name(void) { openamiga_ac4_trace(message); } \
    ADD2INIT(name, priority)

AC4_INIT_PROBE(openamiga_init_after_libraries, -78,
               "init:after-libraries")
AC4_INIT_PROBE(openamiga_init_after_stack, -69,
               "init:after-stack")
AC4_INIT_PROBE(openamiga_init_after_malloc, -49,
               "init:after-malloc")
AC4_INIT_PROBE(openamiga_init_after_commandline, -39,
               "init:after-commandline")
AC4_INIT_PROBE(openamiga_init_before_socket, -36,
               "init:before-socket")
AC4_INIT_PROBE(openamiga_init_after_socket, -34,
               "init:after-socket")
AC4_INIT_PROBE(openamiga_init_after_stdio, -29,
               "init:after-stdio")
AC4_INIT_PROBE(openamiga_init_before_timezone, -12,
               "init:before-timezone")
AC4_INIT_PROBE(openamiga_init_at_timezone, -11,
               "init:at-timezone-priority")
AC4_INIT_PROBE(openamiga_init_at_runtime_services, -10,
               "init:at-runtime-services-priority")
AC4_INIT_PROBE(openamiga_init_before_user, -9,
               "init:before-user")
AC4_INIT_PROBE(openamiga_init_after_user, -8,
               "init:after-user")
AC4_INIT_PROBE(openamiga_init_after_cpp, -4,
               "init:after-cpp")
AC4_INIT_PROBE(openamiga_init_after_environment, -1,
               "init:after-environment")
AC4_INIT_PROBE(openamiga_init_complete, 2,
               "init:complete")

#undef AC4_INIT_PROBE
#endif

/* libnix popen() returns a normal FILE and does not provide pclose(). */
int
pclose(FILE *stream)
{
    if (stream == NULL)
        return -1;
    return fclose(stream);
}
