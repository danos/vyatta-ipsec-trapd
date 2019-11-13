# Trivial makefile for scripts

prefix = /opt/vyatta
BINDIR = $(DESTDIR)$(prefix)/sbin
mibdir = $(DESTDIR)/usr/share/snmp/mibs
INSTALL = install

mibs = BROCADE-IPSEC-MIB.mib

sbin_SCRIPTS = scripts/ipsec-trapd.pl

all:
	true

install: install-progs install-mibs

install-progs: $(BINDIR)
	for i in $(sbin_SCRIPTS); do \
		$(INSTALL) -m 755 $$i $(BINDIR); \
	done

install-mibs: $(mibdir)
	for i in $(mibs); do \
		$(INSTALL) -m 644 $$i $(mibdir)/$$(basename $$i .mib).txt; \
	done

$(BINDIR) $(mibdir):
	$(INSTALL) -d -m 755 $@
	
