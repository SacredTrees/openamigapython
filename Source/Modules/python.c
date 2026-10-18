/* Minimal main program -- everything is loaded from the library */

#include "Python.h"

#ifdef __FreeBSD__
#include <fenv.h>
#endif

#ifdef _AMIGA
#include "../Amiga/wbconsole.h"
/* Amiga constructor function declarations */
extern int WBArgParse_constructor(void);
extern int dosio_init_constructor(void);
extern int locale_lib_init_constructor(void);
#if defined(OPENAMIGA_GCC_OPEN2) && \
    defined(OPENAMIGAPYTHON_STARTUP_TRACE)
extern void openamiga_ac4_trace(const char *message);
#define AC4_TRACE(message) openamiga_ac4_trace(message)
#else
#define AC4_TRACE(message) ((void)0)
#endif
#endif

int
main(int argc, char **argv)
{
	/* 754 requires that FP exceptions run in "no stop" mode by default,
	 * and until C vendors implement C99's ways to control FP exceptions,
	 * Python requires non-stop mode.  Alas, some platforms enable FP
	 * exceptions by default.  Here we disable them.
	 */
#ifdef __FreeBSD__
	fedisableexcept(FE_OVERFLOW);
#endif

#ifdef _AMIGA
	/* Workbench: claim WBStartup (GetMsg) + open CON: before stdio use.
	 * Shell: amiga_wb_prepare is a no-op and keeps argc/argv.
	 */
	AC4_TRACE("main:entry");
	AC4_TRACE("main:before-locale-init");
	locale_lib_init_constructor();
	AC4_TRACE("main:after-locale-init");
	AC4_TRACE("main:before-dosio-init");
	dosio_init_constructor();
	AC4_TRACE("main:after-dosio-init");
#ifndef OPENAMIGA_GCC_OPEN2
	/* PosixLib initializes parts of its FILE/fd bridge lazily.  Prime it
	 * before CPython wraps the inherited AmigaDOS standard streams; on a
	 * cold boot PyFile_FromFile(stdin, ...) can otherwise block forever.
	 * ac4 uses libnix rather than PosixLib and must not enter this path.
	 */
	{
		FILE *warmup = fopen("NIL:", "w");
		if (warmup != NULL)
			fclose(warmup);
	}
#endif
	AC4_TRACE("main:before-wb-prepare");
	if (amiga_wb_prepare(&argc, &argv) != 0) {
		AC4_TRACE("main:wb-prepare-failed");
		amiga_wb_cleanup();
		return 20;
	}
	AC4_TRACE("main:after-wb-prepare");
#endif

	{
		int st;

#ifdef _AMIGA
		AC4_TRACE("main:before-py-main");
#endif
		st = Py_Main(argc, argv);
#ifdef _AMIGA
		AC4_TRACE("main:after-py-main");
		amiga_wb_cleanup();
		AC4_TRACE("main:after-wb-cleanup");
#endif
		return st;
	}
}
