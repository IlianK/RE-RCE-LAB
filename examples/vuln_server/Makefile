# Makefile

# ------------------------
# Configuration
# ------------------------
SRC       := vuln_server.c
BIN_DIR   := binaries
OUT_DIR   := analysis
CC        := gcc
CFLAGS32  := -m32
LDFLAGS32 := -m32

# ------------------------
# Targets
# ------------------------

.PHONY: all checksec clean

all: dirs no_protection canary pie relro nx_only full_stripped

dirs:
	mkdir -p $(BIN_DIR) $(OUT_DIR)

# No protection at all
no_protection:
	$(CC) $(CFLAGS32) -fno-stack-protector -z execstack -no-pie \
		-o $(BIN_DIR)/vuln_noprot $(SRC)

# Stack canary only
canary:
	$(CC) $(CFLAGS32) -fstack-protector-all -z noexecstack -no-pie \
		-o $(BIN_DIR)/vuln_canary $(SRC)

# PIE (Position Independent Executable)
pie:
	$(CC) $(CFLAGS32) -fPIE -pie -fstack-protector -z noexecstack \
		-o $(BIN_DIR)/vuln_pie $(SRC)

# RELRO + PIE + stack canary
relro:
	$(CC) $(CFLAGS32) -fstack-protector-all -z relro -z now -fPIE -pie \
		-o $(BIN_DIR)/vuln_relro $(SRC)

# NX (non-executable stack) only
nx_only:
	$(CC) $(CFLAGS32) -fno-stack-protector -z noexecstack -no-pie \
		-o $(BIN_DIR)/vuln_nx $(SRC)

# Fully stripped binary
full_stripped:
	$(CC) $(CFLAGS32) -fstack-protector-all -z relro -z now -fPIE -pie \
		-o $(BIN_DIR)/vuln_stripped $(SRC)
	strip $(BIN_DIR)/vuln_stripped

# Run checksec on all binaries
checksec:
	rm -f $(OUT_DIR)/checksec_report.txt
	for bin in $(BIN_DIR)/vuln_*; do \
		echo "=== $$bin ===" >> $(OUT_DIR)/checksec_report.txt; \
		checksec --file=$$bin >> $(OUT_DIR)/checksec_report.txt 2>&1; \
		echo "" >> $(OUT_DIR)/checksec_report.txt; \
	done
	@echo "Checksec report saved to $(OUT_DIR)/checksec_report.txt"

# Cleanup
clean:
	rm -rf $(BIN_DIR)/* $(OUT_DIR)/*
