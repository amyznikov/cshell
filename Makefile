SHELL = /bin/bash

VERSION = 0.0.1

CLIENT = cshell-client
SERVER = cshell-server
ROUTER = cshell-router


all: $(CLIENT) $(SERVER) $(ROUTER)

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




COMMON_SOURCES = src/debug.c  src/sockopt.c

CLIENT_SOURCES = $(COMMON_SOURCES) src/cshell-client.c
SERVER_SOURCES = $(COMMON_SOURCES) src/cshell-server.c
ROUTER_SOURCES = $(COMMON_SOURCES) src/cshell-router.c


CLIENT_MODULES = $(addsuffix .o, $(basename $(CLIENT_SOURCES)))
SERVER_MODULES = $(addsuffix .o, $(basename $(SERVER_SOURCES))) 
ROUTER_MODULES = $(addsuffix .o, $(basename $(ROUTER_SOURCES)))

INCLUDES += -Isrc




$(CLIENT): $(CLIENT_MODULES)
	$(LD) $(LDFLAGS) $(CLIENT_MODULES) -o $@

$(SERVER): $(SERVER_MODULES)
	$(LD) $(LDFLAGS) $(SERVER_MODULES) -o $@

$(ROUTER): $(ROUTER_MODULES)
	$(LD) $(LDFLAGS) $(ROUTER_MODULES) -o $@

clean:
	$(RM) src/*.o
	
distclean: clean
	$(RM) $(CLIENT) $(SERVER) $(ROUTER) 


$(mkinstalldirs) : 
	mkdir -p $@

test:
	@echo "CLIENT_MODULES=$(CLIENT_MODULES)"
	@echo "SERVER_MODULES=$(SERVER_MODULES)"
	@echo "ROUTER_MODULES=$(ROUTER_MODULES)"
