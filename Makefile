# Package config.
PKG_CONF = pkg-config

ifeq ($(shell which $(PKG_CONF)),)
$(error "Package config not found. Please install it on server.")
endif

# Add path to package config.
PKG_CONFIG_PATH += /usr/lib64/pkgconfig

# Compilers we'll be using.
CC = clang
LLC = llc
CMAKE = cmake

# Top-level directories.
SRC_DIR = src
BUILD_DIR = build
MODULES_DIR = modules

# LibXDP.
XDP_TOOLS_DIR =$(MODULES_DIR)/xdp-tools
LIBBPF_DIR = $(XDP_TOOLS_DIR)/lib/libbpf
LIBBPF_SRC = $(LIBBPF_DIR)/src

LIBXDP_DIR = $(XDP_TOOLS_DIR)/lib/libxdp
LIBXDP_HEADERS = $(XDP_TOOLS_DIR)/headers

LIBBPF_OBJS = $(LIBBPF_SRC)/staticobjs/bpf_prog_linfo.o $(LIBBPF_SRC)/staticobjs/bpf.o $(LIBBPF_SRC)/staticobjs/btf_dump.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/btf.o $(LIBBPF_SRC)/staticobjs/gen_loader.o $(LIBBPF_SRC)/staticobjs/hashmap.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/libbpf_errno.o $(LIBBPF_SRC)/staticobjs/libbpf_probes.o $(LIBBPF_SRC)/staticobjs/libbpf.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/netlink.o $(LIBBPF_SRC)/staticobjs/nlattr.o $(LIBBPF_SRC)/staticobjs/ringbuf.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/str_error.o $(LIBBPF_SRC)/staticobjs/strset.o

LIBXDP_OBJS = $(LIBXDP_DIR)/staticobjs/libxdp.o $(LIBXDP_DIR)/staticobjs/xsk.o

# JSON-C.
JSONC_DIR = $(MODULES_DIR)/json-c

# Main loader source/out.
KILIMANJARO_SRC = $(SRC_DIR)/kilimanjaro.c
KILIMANJARO_OUT = $(BUILD_DIR)/kilimanjaro

# Command line source/object.
CMD_LINE_SRC = $(SRC_DIR)/cmd_line.c
CMD_LINE_OBJ = $(BUILD_DIR)/cmd_line.o

# Config source/object.
CONFIG_SRC = $(SRC_DIR)/config.c
CONFIG_OBJ = $(BUILD_DIR)/config.o

# Maps source/object.
MAPS_SRC = $(SRC_DIR)/maps.c
MAPS_OBJ = $(BUILD_DIR)/maps.o

# Utils source/object.
UTILS_SRC = $(SRC_DIR)/utils.c
UTILS_OBJ = $(BUILD_DIR)/utils.o

# Socket source/object.
SOCKET_SRC = $(SRC_DIR)/socket.c
SOCKET_OBJ = $(BUILD_DIR)/socket.o

# AF_XDP source/object.
AF_XDP_SRC = $(SRC_DIR)/af_xdp.c
AF_XDP_OBJ = $(BUILD_DIR)/af_xdp.o

# XDP Program source/emit LLVM/object files.
XDP_PROG_SRC = $(SRC_DIR)/xdp_prog.c
XDP_PROG_LL = $(BUILD_DIR)/xdp_prog.ll
XDP_PROG_OBJ = $(BUILD_DIR)/xdp_prog.o

# Global and common flags.
GLOBAL_INCLUDES += -I/usr/include -I/usr/local/include
GLOBAL_FLAGS += -O2 -g
GLOBAL_FLAGS += $(GLOBAL_INCLUDES)
GLOBAL_FLAGS += $(shell $(PKG_CONF) --cflags json-c)

MAIN_FLAGS += $(GLOBAL_FLAGS)
MAIN_FLAGS += -pthread -lelf -lz
MAIN_COMMON_OBJS += $(CMD_LINE_OBJ) $(CONFIG_OBJ) $(MAPS_OBJ) $(UTILS_OBJ) $(SOCKET_OBJ) $(AF_XDP_OBJ)
MAIN_COMMON_OBJS += $(LIBBPF_OBJS) $(LIBXDP_OBJS)
MAIN_COMMON_OBJS += $(shell $(PKG_CONF) --libs json-c)

# Handles all chains.
all: kilimanjaro config maps utils socket af_xdp xdp_prog
full: json-c full

# LibXDP.
libxdp:
	sudo $(MAKE) -C $(XDP_TOOLS_DIR)
	sudo $(MAKE) -C $(XDP_TOOLS_DIR)/lib/libbpf/src install
	sudo $(MAKE) -C $(XDP_TOOLS_DIR) install

# Creates build directory.
mk_build:
	mkdir -p $(BUILD_DIR)

# The main loader.
kilimanjaro: libxdp mk_build cmd_line config maps utils socket af_xdp
	$(CC) $(MAIN_FLAGS) -o $(KILIMANJARO_OUT) $(MAIN_COMMON_OBJS) $(KILIMANJARO_SRC)

# Command line object.
cmd_line: mk_build
	$(CC) $(GLOBAL_FLAGS) -c -o $(CMD_LINE_OBJ) $(CMD_LINE_SRC)

# Config object.
config: mk_build
	$(CC) $(GLOBAL_FLAGS) -c -o $(CONFIG_OBJ) $(CONFIG_SRC)

# Maps object.
maps: mk_build
	$(CC) $(GLOBAL_FLAGS) -c -o $(MAPS_OBJ) $(MAPS_SRC)

# Utils object.
utils: mk_build
	$(CC) $(GLOBAL_FLAGS) -c -o $(UTILS_OBJ) $(UTILS_SRC)

# Socket object.
socket: mk_build
	$(CC) $(GLOBAL_FLAGS) -c -o $(SOCKET_OBJ) $(SOCKET_SRC)

# The AF_XDP program.
af_xdp: mk_build
	$(CC) $(GLOBAL_FLAGS) -c -o $(AF_XDP_OBJ) $(AF_XDP_SRC)

# The XDP/BPF object.
xdp_prog: mk_build
	$(CC) $(GLOBAL_INCLUDES) -D__BPF__  -D __BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -O2 -emit-llvm -c -g -o $(XDP_PROG_LL) $(XDP_PROG_SRC)
	$(LLC) -march=bpf -filetype=obj -o $(XDP_PROG_OBJ) $(XDP_PROG_LL)

# Building JSON C.
json-c:
	mkdir -p $(JSONC_DIR)/build
	cd $(JSONC_DIR)/build && cmake ../
	cd $(JSONC_DIR)/build && make && make install

# Install.
install:
	mkdir -p /etc/kilimanjaro
	cp -n data/kilimanjaro.json.example /etc/kilimanjaro/kilimanjaro.json
	cp data/update_edge.sh /root/
	cp data/kilimanjaro.service /etc/systemd/system/kilimanjaro.service
	cp $(XDP_PROG_OBJ) /etc/kilimanjaro/xdp_prog.o
	cp $(KILIMANJARO_OUT) /usr/bin/kilimanjaro

# Clean up chain for build directory.
clean:
	$(MAKE) -C $(XDP_TOOLS_DIR) clean
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.ll $(KILIMANJARO_OUT)

pkg-path:
	echo $(PKG_CONFIG_PATH)

# Default.
.DEFAULT: all
