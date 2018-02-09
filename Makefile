SHELL = /bin/bash

VERSION = 0.0.1

CLIENT = cshell-client
SERVER = cshell-server
ROUTER = cshell-router
TCPTST = raw-tcp-tester


all: $(CLIENT) $(SERVER) $(ROUTER) 
# $(TCPTST)

cross=
DESTDIR=
prefix=/usr/local
incdir=$(prefix)/include
libdir=$(prefix)/lib
bindir=$(prefix)/bin
mkinstalldirs = $(addprefix $(DESTDIR)/,$(incdir) $(libdir) $(bindir))



# AR flags
ARFLAGS = rvU

# C preprocessor flags
CPPFLAGS= -DCSHELL_VERSION=\"$(VERSION)\"

# C Compiler and flags
CC=$(cross)gcc -std=gnu11
CFLAGS=-Wall -Wextra -fPIC -O3 -g0 $(DEFINES) $(INCLUDES) 

# C++ Compiler and flags
CXX=$(cross)gcc -std=c++11
CXXFLAGS=$(CFLAGS)

# Loader Flags And Libraries
LD=$(CC)
LDFLAGS = $(CFLAGS)
LDLIBS = -L/usr/local/lib -lcuttle -lssl -lcrypto -pthread

# 



COMMON_SOURCES = src/so-msg.c src/corpc-msg.c

CLIENT_SOURCES = $(COMMON_SOURCES) src/cshell-client.c src/tunnel.c src/checksum.c src/ip-pkt.c
SERVER_SOURCES = $(COMMON_SOURCES) src/cshell-server.c
ROUTER_SOURCES = $(COMMON_SOURCES) src/cshell-router.c
TCPTST_SOURCES = $(COMMON_SOURCES) src/raw-tcp-tester.c

CLIENT_MODULES = $(addsuffix .o, $(basename $(CLIENT_SOURCES)))
SERVER_MODULES = $(addsuffix .o, $(basename $(SERVER_SOURCES))) 
ROUTER_MODULES = $(addsuffix .o, $(basename $(ROUTER_SOURCES)))
TCPTST_MODULES = $(addsuffix .o, $(basename $(TCPTST_SOURCES)))

INCLUDES += -Isrc




$(CLIENT): $(CLIENT_MODULES)
	$(LD) $(LDFLAGS) $(CLIENT_MODULES) $(LDLIBS) -o $@

$(SERVER): $(SERVER_MODULES)
	$(LD) $(LDFLAGS) $(SERVER_MODULES) $(LDLIBS) -o $@

$(ROUTER): $(ROUTER_MODULES)
	$(LD) $(LDFLAGS) $(ROUTER_MODULES) $(LDLIBS) -o $@

$(TCPTST): $(TCPTST_MODULES)
	$(LD) $(LDFLAGS) $(TCPTST_MODULES) $(LDLIBS) -o $@

clean:
	$(RM) src/*.o
	
distclean: clean
	$(RM) $(CLIENT) $(SERVER) $(ROUTER) $(TCPTST) 


$(mkinstalldirs) : 
	mkdir -p $@

test:
	@echo "CLIENT_MODULES=$(CLIENT_MODULES)"
	@echo "SERVER_MODULES=$(SERVER_MODULES)"
	@echo "ROUTER_MODULES=$(ROUTER_MODULES)"
