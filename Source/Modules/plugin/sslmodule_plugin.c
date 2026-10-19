/*
 * Compile sslmodule.c as a LoadSeg plugin TU with host redirects.
 * The backend is OpenTLS, through opentlsinclude: (see vmakefile).
 * PYAMIGA_PLUGIN_BUILD comes from the plugin vmakefile CFLAGS.
 */
#include "Python.h"
#include "pyamiga_plugin.h"
#include "pyamiga_redir.h"
#include "../sslmodule.c"
