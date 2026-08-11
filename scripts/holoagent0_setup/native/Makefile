CC ?= cc

CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c17 -O2 -Wall -Wextra -Werror -fPIE
LDFLAGS := -pie
BUILD_DIR := build

.PHONY: all clean

all: $(BUILD_DIR)/tracee_launcher $(BUILD_DIR)/finalizer_only \
	$(BUILD_DIR)/native_test_probe

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/tracee_launcher: tracee_launcher.c seccomp_policy.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(BUILD_DIR)/finalizer_only: finalizer_only.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@

$(BUILD_DIR)/native_test_probe: finalizer_only.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DHOLOAGENT_NATIVE_TEST_PROBE $< \
		$(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD_DIR)
