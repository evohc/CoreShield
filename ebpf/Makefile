CLANG := clang
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

# Source and Object Paths
MONITOR_SRC := monitor/monitor.bpf.c
MONITOR_OBJ := monitor/monitor.bpf.o

SHIELD_SRC := shield/shield.bpf.c
SHIELD_OBJ := shield/shield.bpf.o
all: $(MONITOR_OBJ) $(SHIELD_OBJ)

$(MONITOR_OBJ): $(MONITOR_SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@ 

$(SHIELD_OBJ): $(SHIELD_SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@ 

clean:
	rm -f $(MONITOR_OBJ) $(SHIELD_OBJ)

.PHONY: all clean