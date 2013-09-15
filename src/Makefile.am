EXTRA_DIST = \
	adapter_slurm.cc

lib_LTLIBRARIES = \
	ecap_adapter_slurm.la

noinst_HEADERS = \
	slurm.h \
	\
	autoconf.h

# Slurm
ecap_adapter_slurm_la_SOURCES = adapter_slurm.cc
ecap_adapter_slurm_la_LDFLAGS = -module -avoid-version
ecap_adapter_slurm_la_LIBADD = -lecap

# -shared -export-dynamic -Wl,-soname,ecap_noop_adapter.so

DISTCLEANFILES = \
        autoconf.h

AM_CPPFLAGS = -I$(top_srcdir)/src

