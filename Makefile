CC = clang
LLC = llc
MCPU = $(shell gcc -march=native -Q --help=target | grep "mtune=    " | awk '{print $$NF}')
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

LIBBPF_LIBXDP_STATIC ?= 0

# Top-level directories.
BUILD_DIR = build
SRC_DIR = src
MODULES_DIR = modules

# Common directories.
COMMON_DIR = $(SRC_DIR)/common
LOADER_DIR = $(SRC_DIR)/loader
XDP_DIR = $(SRC_DIR)/xdp

# Additional build directories.
BUILD_LOADER_DIR = $(BUILD_DIR)/loader
BUILD_XDP_DIR = $(BUILD_DIR)/xdp

# XDP Tools directories.
XDP_TOOLS_DIR = $(MODULES_DIR)/xdp-tools
XDP_TOOLS_HEADERS = $(XDP_TOOLS_DIR)/headers

# LibXDP and LibBPF directories.
LIBXDP_DIR = $(XDP_TOOLS_DIR)/lib/libxdp
LIBBPF_DIR = $(XDP_TOOLS_DIR)/lib/libbpf

LIBBPF_SRC = $(LIBBPF_DIR)/src

# LibBPF objects.
LIBBPF_OBJS = $(addprefix $(LIBBPF_SRC)/staticobjs/, $(notdir $(wildcard $(LIBBPF_SRC)/staticobjs/*.o)))

# LibXDP objects.
# To Do: Figure out why static objects produces errors relating to unreferenced functions with dispatcher.
# Note: Not sure why shared objects are acting like static objects here where we can link while building and then don't require them at runtime, etc.
LIBXDP_OBJS = $(addprefix $(LIBXDP_DIR)/sharedobjs/, $(notdir $(wildcard $(LIBXDP_DIR)/sharedobjs/*.o)))

# Loader directories.
LOADER_SRC = prog.c
LOADER_OUT = xdpfw

LOADER_UTILS_DIR = $(LOADER_DIR)/utils

# Loader utils.
LOADER_UTILS_CONFIG_SRC = config.c
LOADER_UTILS_CONFIG_OBJ = config.o

LOADER_UTILS_CMDLINE_SRC = cmdline.c
LOADER_UTILS_CMDLINE_OBJ = cmdline.o

LOADER_UTILS_HELPERS_SRC = helpers.c
LOADER_UTILS_HELPERS_OBJ = helpers.o

# Loader objects.
LOADER_OBJS = $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CMDLINE_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ)

# User space application chain.
xdpfw: utils libxdp $(OBJS)
	mkdir -p $(BUILDDIR)/
	$(CC) -g0 -O3 -ffast-math -march=$(MCPU) -mtune=$(MCPU) -flto $(LDFLAGS) $(INCS) -o $(BUILDDIR)/$(XDPFWOUT) $(LIBBPFOBJS) $(LIBXDPOBJS) $(OBJS) $(SRCDIR)/$(XDPFWSRC)

# XDP program chain.
xdpfw_filter:
	mkdir -p $(BUILDDIR)/
	$(CC) $(INCS) -D__BPF__ -D __BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -g0 -O3 -ffast-math -march=$(MCPU) -mtune=$(MCPU) -flto -emit-llvm -c -g -o $(BUILDDIR)/$(XDPPROGLL) $(SRCDIR)/$(XDPPROGSRC)
	$(LLC) -march=bpf -filetype=obj -o $(BUILDDIR)/$(XDPPROGOBJ) $(BUILDDIR)/$(XDPPROGLL)
	
# Utils chain.
utils:
	mkdir -p $(BUILDDIR)/
	$(CC) $(INCS) -g0 -O3 -ffast-math -march=$(MCPU) -mtune=$(MCPU) -flto -c -o $(BUILDDIR)/$(CONFIGOBJ) $(SRCDIR)/$(CONFIGSRC)
	$(CC) $(INCS) -g0 -O3 -ffast-math -march=$(MCPU) -mtune=$(MCPU) -flto -c -o $(BUILDDIR)/$(CMDLINEOBJ) $(SRCDIR)/$(CMDLINESRC)

ifeq ($(LIBBPF_LIBXDP_STATIC), 1)
	LOADER_OBJS := $(LIBBPF_OBJS) $(LIBXDP_OBJS) $(LOADER_OBJS)
endif

# XDP directories.
XDP_SRC = prog.c
XDP_OBJ = xdp_prog.o

# Includes.
INCS = -I $(SRC_DIR) -I $(LIBBPF_SRC) -I /usr/include -I /usr/local/include

# Flags.
FLAGS = -O2 -g
FLAGS_LOADER = -lconfig -lelf -lz

ifeq ($(LIBBPF_LIBXDP_STATIC), 0)
	FLAGS_LOADER += -lbpf -lxdp
endif

# All chains.
all: loader xdp

# Loader program.
loader: loader_utils
	$(CC) $(INCS) $(FLAGS) $(FLAGS_LOADER) -o $(BUILD_LOADER_DIR)/$(LOADER_OUT) $(LOADER_OBJS) $(LOADER_DIR)/$(LOADER_SRC)

loader_utils: loader_utils_config loader_utils_cmdline loader_utils_helpers

loader_utils_config:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_CONFIG_SRC)

loader_utils_cmdline:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CMDLINE_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_CMDLINE_SRC)

loader_utils_helpers:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_HELPERS_SRC)

# XDP program.
xdp:
	$(CC) $(INCS) $(FLAGS) -target bpf -c -o $(BUILD_XDP_DIR)/$(XDP_OBJ) $(XDP_DIR)/$(XDP_SRC)

# LibXDP chain. We need to install objects here since our program relies on installed object files and such.
libxdp:
	$(MAKE) -C $(XDP_TOOLS_DIR) libxdp
	sudo $(MAKE) -C $(LIBBPF_SRC) install
	sudo $(MAKE) -C $(LIBXDP_DIR) install

clean:
	$(MAKE) -C $(XDP_TOOLS_DIR) clean
	$(MAKE) -C $(LIBBPF_SRC) clean

	find $(BUILD_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_LOADER_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_XDP_DIR) -type f ! -name ".*" -exec rm -f {} +

install:
	mkdir -p /etc/xdpfw/
	cp -n xdpfw.conf.example /etc/xdpfw/xdpfw.conf

	cp -f $(BUILD_LOADER_DIR)/$(LOADER_OUT) /usr/bin
	cp -f $(BUILD_XDP_DIR)/$(XDP_OBJ) /etc/xdpfw

	cp -n other/xdpfw.service /etc/systemd/system/
.PHONY: libxdp all
.DEFAULT: all
