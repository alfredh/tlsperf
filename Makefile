#
# Makefile
#
# Copyright (C) 2010 Creytiv.com
#

PROJECT	  := tlsperf
VERSION   := 0.0.1


ifeq ($(LIBRE_MK),)
LIBRE_MK  := $(shell [ -f /usr/share/re/re.mk ] && \
	echo "/usr/share/re/re.mk")
endif
ifeq ($(LIBRE_MK),)
LIBRE_MK  := $(shell [ -f /usr/local/share/re/re.mk ] && \
	echo "/usr/local/share/re/re.mk")
endif

include $(LIBRE_MK)

INSTALL := install
ifeq ($(DESTDIR),)
PREFIX  := /usr/local
else
PREFIX  := /usr
endif
BINDIR	:= $(PREFIX)/bin
CFLAGS	+= -g -Wall -I$(LIBRE_INC)
LIBS	+= -L/usr/local/lib -lm
BIN	:= $(PROJECT)$(BIN_SUFFIX)
APP_MK	:= src/srcs.mk

include $(APP_MK)

OBJS	?= $(patsubst %.c,$(BUILD)/src/%.o,$(SRCS))

all: $(BIN)

-include $(OBJS:.o=.d)

$(BIN): $(OBJS)
	@echo "  LD      $@"
ifneq ($(GPROF),)
	@$(LD) $(LFLAGS) $^ ../re/libre.a $(LIBS) -o $@
else
	@$(LD) $(LFLAGS) $^ -L$(LIBRE_SO) -lre $(LIBS) -o $@
endif


$(BUILD)/%.o: %.c $(BUILD) Makefile $(APP_MK)
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -o $@ -c $< $(DFLAGS)

$(BUILD): Makefile
	@mkdir -p $(BUILD)/src
	@touch $@

clean:
	@rm -rf $(BIN) $(BUILD)

install: $(BIN)
	@mkdir -p $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)
