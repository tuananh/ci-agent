all: ci-agentd

BPF_HEADERS = vmlinux.h

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

BPF_OBJS = ci-agent.bpf.o

$(BPF_OBJS): $(BPF_HEADERS)

%.bpf.o: %.bpf.c
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

ALL_HEADERS += $(BPF_HEADERS)
ALL_OBJS += $(BPF_OBJS)

AGENT_HEADERS = ci-agent.skel.h
AGENT_OBJS = ci-agentd.o
AGENT_OBJS += ci-agentd-broadcast.o
AGENT_OBJS += ci-agentd-dns.o
ALL_HEADERS += $(AGENT_HEADERS)
ALL_OBJS += $(AGENT_OBJS)

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

$(AGENT_OBJS): $(AGENT_HEADERS)

BPF_CFLAGS = $(shell pkg-config libbpf --cflags)
BPF_LIBS = $(shell pkg-config libbpf --libs)
CPPFLAGS += $(BPF_CFLAGS)

ELF_CFLAGS = $(shell pkg-config libelf --cflags)
ELF_LIBS = $(shell pkg-config libelf --libs)
CPPFLAGS += $(ELF_CFLAGS)

ZLIB_CFLAGS = $(shell pkg-config zlib --cflags)
ZLIB_LIBS = $(shell pkg-config zlib --libs)
CPPFLAGS += $(ZLIB_CFLAGS)

CFLAGS ?= -O2 -Wall -g -std=gnu2x

%.o: %.c
	gcc $(CPPFLAGS) $(CFLAGS) -c $< -o $@

AGENT_LIBS += $(BPF_LIBS)
AGENT_LIBS += $(ELF_LIBS)
AGENT_LIBS += $(ZLIB_LIBS)

ci-agentd: $(BPF_OBJS) $(AGENT_OBJS)
	gcc -o $@ $(AGENT_OBJS) $(AGENT_LIBS) $(LDFLAGS)

clean:
	rm -f $(ALL_HEADERS) $(ALL_OBJS) ci-agentd ci-agent-client
