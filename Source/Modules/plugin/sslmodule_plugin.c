/*
 * Compile sslmodule.c as a LoadSeg plugin TU with host redirects.
 * Default: OpenTLS via opentlsinclude: and -DPYAMIGA_USE_OPENTLS.
 * AmiTLS: amitlsinclude: and -DPYAMIGA_USE_AMITLS (SSL_CFLAGS_AMITLS).
 * AmiSSL: sslinclude: assign and SSL_CFLAGS_AMISSL (see vmakefile).
 * PYAMIGA_PLUGIN_BUILD comes from the plugin vmakefile CFLAGS.
 */
#include "Python.h"
#include "pyamiga_plugin.h"
#include "pyamiga_redir.h"
#include "../sslmodule.c"
