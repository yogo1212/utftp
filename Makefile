NAME = utftp
VERSION = 0.1

LIBSRCDIR = lib
LIBOBJDIR = libobj

APPSRCDIR = app
APPOBJDIR = appobj

INCDIR = include

BINDIR = bin


DIRS = $(BINDIR) $(LIBOBJDIR) $(APPOBJDIR)


CFLAGS += -std=gnu99 -pedantic -Wall -Wextra -I$(INCDIR)
DEBUG = 1

ifeq (1,$(DEBUG))
CFLAGS += -g
else
CFLAGS += -O2
endif

LDFLAGS += -levent

LIBCFLAGS := $(CFLAGS) -fPIC
LIBLDFLAGS := $(LDFLAGS)

APPCFLAGS := $(CFLAGS)
APPLDFLAGS := $(LDFLAGS) -Lbin

LIBSOURCES = $(wildcard $(LIBSRCDIR)/*.c)
LIBOBJECTS = $(patsubst $(LIBSRCDIR)/%.c,$(LIBOBJDIR)/%.o,$(LIBSOURCES))
LIBHEADERS = $(wildcard $(INCDIR)/*.h)
LIBBIN = $(BINDIR)/lib$(NAME).so

APPSOURCES = $(wildcard $(APPSRCDIR)/*.c)
APPOBJECTS = $(patsubst $(APPSRCDIR)/%.c,$(APPOBJDIR)/%.o,$(APPSOURCES))
APPBIN = $(BINDIR)/$(NAME)

.PHONY: clean default debug install uninstall

default: $(LIBBIN) $(APPBIN)

debug:
	$(MAKE) DEBUG=1

$(LIBBIN): % : %.$(VERSION)
	cd $(BINDIR) ; ln -sf $(patsubst $(BINDIR)/%,%,$^) $(patsubst $(BINDIR)/%,%,$@)


$(LIBBIN).$(VERSION): $(LIBOBJECTS) | $(BINDIR)
	$(CC) $^ -o $@ $(LIBLDFLAGS) -shared
	chmod 755 $@

$(APPBIN): $(APPOBJECTS) | $(BINDIR) $(LIBBIN)
	$(CC) $^ -o $@ $(APPLDFLAGS) -l$(NAME) $(APPCFLAGS)


$(LIBOBJECTS): $(LIBOBJDIR)/%.o : $(LIBSRCDIR)/%.c | $(LIBOBJDIR)
	$(CC) -c $< -o $@ $(LIBCFLAGS)

$(APPOBJECTS): $(APPOBJDIR)/%.o : $(APPSRCDIR)/%.c | $(APPOBJDIR)
	$(CC) -c $< -o $@ $(CFLAGS)


$(DIRS):
	mkdir -p $@

clean::
	rm -rf $(DIRS)

#from here on it's cheap install-stuff. probably rubbish

ROOT ?= /
usr ?= usr/local/

usrdir = $(ROOT)$(usr)
libdir = $(usrdir)lib/
includedir = $(usrdir)include/
bindir = $(usrdir)bin/

INSTALL_BIN_CMD=install -m 0755

install_lib: $(LIBBIN).$(VERSION)
	mkdir -p $(libdir)
	$(INSTALL_BIN_CMD) $^ $(libdir)
	cd $(libdir) ; ln -fs $(patsubst $(BINDIR)/%,%,$(LIBBIN).$(VERSION)) $(patsubst $(BINDIR)/%,%,$(LIBBIN))

install_headers: $(LIBHEADERS)
	mkdir -p $(includedir)
	install $(LIBHEADERS) $(includedir)

install_app: $(APPBIN)
	mkdir -p $(bindir)
	$(INSTALL_BIN_CMD) $^ $(bindir)

install: install_lib install_headers install_app

uninstall_lib:
	rm -f $(patsubst $(BINDIR)/%,$(libdir)/%*,$(LIBBIN))

uninstall_headers:
	rm -f $(patsubst $(INCDIR)/%,$(includedir)/%,$(LIBHEADERS))

uninstall_app:
	rm -f $(patsubst $(BINDIR)/%,$(bindir)/%,$(APPBIN))

uninstall: uninstall_lib uninstall_headers uninstall_app
