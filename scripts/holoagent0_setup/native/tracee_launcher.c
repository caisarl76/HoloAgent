#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/close_range.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int install_tracee_seccomp(void);

enum {
    EXIT_INHERITED_SOCKET = 30,
    EXIT_BOUNDARY_FAILURE = 31,
    EXIT_USAGE = 64,
    MAX_PASS_FDS = 64,
    MAX_REVIEWED_FD = 65535,
};

enum fd_class {
    FD_ALLOWED,
    FD_SOCKET,
    FD_UNKNOWN,
    FD_OBSERVATION_ERROR,
};

struct fd_mapping {
    int source;
    int target;
    int temporary;
    bool observed;
    bool safe_rebound;
};

static int report_fd = -1;

static enum fd_class classify_fd(int fd) {
    struct stat descriptor_stat;
    if (fstat(fd, &descriptor_stat) < 0) {
        return FD_OBSERVATION_ERROR;
    }
    if (S_ISSOCK(descriptor_stat.st_mode)) {
        int domain = 0;
        int type = 0;
        int protocol = 0;
        socklen_t size = sizeof(int);
        int domain_result = getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &size);
        size = sizeof(int);
        int type_result = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size);
        size = sizeof(int);
        int protocol_result =
            getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &size);
        (void)domain_result;
        (void)type_result;
        (void)protocol_result;
        (void)domain;
        (void)type;
        (void)protocol;
        return FD_SOCKET;
    }
    if (S_ISREG(descriptor_stat.st_mode) || S_ISCHR(descriptor_stat.st_mode) ||
        S_ISFIFO(descriptor_stat.st_mode)) {
        return FD_ALLOWED;
    }
    return FD_UNKNOWN;
}

static bool is_dev_null(int fd) {
    struct stat descriptor_stat;
    struct stat dev_null_stat;
    return fstat(fd, &descriptor_stat) == 0 && stat("/dev/null", &dev_null_stat) == 0 &&
           S_ISCHR(descriptor_stat.st_mode) &&
           descriptor_stat.st_dev == dev_null_stat.st_dev &&
           descriptor_stat.st_ino == dev_null_stat.st_ino &&
           descriptor_stat.st_rdev == dev_null_stat.st_rdev;
}

static bool is_anonymous_pipe(int fd) {
    struct stat descriptor_stat;
    if (fstat(fd, &descriptor_stat) < 0 || !S_ISFIFO(descriptor_stat.st_mode)) {
        return false;
    }
    char proc_path[64];
    int path_length =
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    if (path_length <= 0 || (size_t)path_length >= sizeof(proc_path)) {
        return false;
    }
    char target[64];
    ssize_t target_length = readlink(proc_path, target, sizeof(target) - 1U);
    if (target_length <= 7 || (size_t)target_length >= sizeof(target)) {
        return false;
    }
    target[target_length] = '\0';
    return strncmp(target, "pipe:[", 6) == 0 && target[target_length - 1] == ']';
}

static bool is_output_fd(int fd) {
    struct stat descriptor_stat;
    return fstat(fd, &descriptor_stat) == 0 &&
           (S_ISREG(descriptor_stat.st_mode) ||
            S_ISFIFO(descriptor_stat.st_mode));
}

static bool write_all(int fd, const char *payload, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, payload + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        offset += (size_t)written;
    }
    return true;
}

static void emit_failure(const char *reason) {
    char payload[128];
    int length = snprintf(payload, sizeof(payload), "{\"reason\":\"%s\"}\n", reason);
    if (length <= 0 || (size_t)length >= sizeof(payload)) {
        return;
    }
    if (report_fd >= 0 && classify_fd(report_fd) == FD_ALLOWED &&
        write_all(report_fd, payload, (size_t)length)) {
        return;
    }
    for (int fd = STDERR_FILENO; fd >= STDOUT_FILENO; --fd) {
        if (fd != report_fd && classify_fd(fd) == FD_ALLOWED &&
            write_all(fd, payload, (size_t)length)) {
            return;
        }
    }
}

static int parse_fd(const char *value, const char **end) {
    char *parsed_end = NULL;
    errno = 0;
    long parsed = strtol(value, &parsed_end, 10);
    if (errno != 0 || parsed_end == value || parsed < 0 ||
        parsed > MAX_REVIEWED_FD) {
        return -1;
    }
    *end = parsed_end;
    return (int)parsed;
}

static bool parse_mapping(const char *value, struct fd_mapping *mapping) {
    const char *end = NULL;
    int source = parse_fd(value, &end);
    if (source < 0) {
        return false;
    }
    int target = source;
    if (*end == ':') {
        const char *target_end = NULL;
        target = parse_fd(end + 1, &target_end);
        if (target < 0 || *target_end != '\0') {
            return false;
        }
    } else if (*end != '\0') {
        return false;
    }
    if (target < 3) {
        return false;
    }
    *mapping = (struct fd_mapping){
        .source = source,
        .target = target,
        .temporary = -1,
        .observed = false,
        .safe_rebound = false,
    };
    return true;
}

static int close_range_checked(unsigned int first, unsigned int last,
                               unsigned int flags) {
    return (int)syscall(SYS_close_range, first, last, flags);
}

static bool target_is_allowed(const struct fd_mapping *mappings, size_t count,
                              int fd) {
    for (size_t index = 0; index < count; ++index) {
        if (mappings[index].target == fd) {
            return true;
        }
    }
    return false;
}

static bool source_is_requested(const struct fd_mapping *mappings, size_t count,
                                int fd) {
    for (size_t index = 0; index < count; ++index) {
        if (mappings[index].source == fd) {
            return true;
        }
    }
    return false;
}

static bool inherited_role_is_allowed(const struct fd_mapping *mappings,
                                      size_t count, int fd) {
    if (fd == STDIN_FILENO) {
        return is_dev_null(fd);
    }
    if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
        return is_output_fd(fd);
    }
    if (fd == report_fd || source_is_requested(mappings, count, fd)) {
        return is_anonymous_pipe(fd);
    }
    return true;
}

static int observe_inherited_fds(struct fd_mapping *mappings, size_t count) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        return EXIT_BOUNDARY_FAILURE;
    }
    int directory_fd = dirfd(directory);
    int outcome = 0;
    errno = 0;
    for (;;) {
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                outcome = EXIT_BOUNDARY_FAILURE;
            }
            break;
        }
        const char *end = NULL;
        int fd = parse_fd(entry->d_name, &end);
        if (fd < 0 || *end != '\0' || fd == directory_fd) {
            continue;
        }
        enum fd_class descriptor_class = classify_fd(fd);
        if (descriptor_class == FD_SOCKET || descriptor_class == FD_UNKNOWN) {
            outcome = EXIT_INHERITED_SOCKET;
            break;
        }
        if (descriptor_class != FD_ALLOWED) {
            outcome = EXIT_BOUNDARY_FAILURE;
            break;
        }
        if (!inherited_role_is_allowed(mappings, count, fd)) {
            outcome = EXIT_INHERITED_SOCKET;
            break;
        }
        for (size_t index = 0; index < count; ++index) {
            if (mappings[index].source == fd) {
                mappings[index].observed = true;
            }
        }
    }
    if (closedir(directory) < 0 && outcome == 0) {
        outcome = EXIT_BOUNDARY_FAILURE;
    }
    return outcome;
}

static int add_standard_fds(struct fd_mapping *mappings, size_t *count) {
    for (int target = 0; target <= 2; ++target) {
        int source = target;
        bool safe_rebound = false;
        if (fcntl(target, F_GETFD) < 0) {
            if (errno != EBADF) {
                return -1;
            }
            int flags = target == STDIN_FILENO ? O_RDONLY : O_WRONLY;
            source = open("/dev/null", flags | O_CLOEXEC | O_NOFOLLOW);
            if (source < 0) {
                return -1;
            }
            safe_rebound = true;
        }
        mappings[*count] = (struct fd_mapping){
            .source = source,
            .target = target,
            .temporary = -1,
            .observed = true,
            .safe_rebound = safe_rebound,
        };
        ++*count;
    }
    return 0;
}

static bool target_role_is_allowed(const struct fd_mapping *mapping) {
    if (mapping->target == STDIN_FILENO) {
        return is_dev_null(mapping->target);
    }
    if (mapping->target == STDOUT_FILENO || mapping->target == STDERR_FILENO) {
        return is_output_fd(mapping->target) ||
               (mapping->safe_rebound && is_dev_null(mapping->target));
    }
    return is_anonymous_pipe(mapping->target);
}

static int sanitize_fds(struct fd_mapping *mappings, size_t count) {
    int maximum_target = 2;
    for (size_t left = 0; left < count; ++left) {
        if (!mappings[left].observed) {
            return -1;
        }
        if (mappings[left].target > maximum_target) {
            maximum_target = mappings[left].target;
        }
        for (size_t right = left + 1; right < count; ++right) {
            if (mappings[left].target == mappings[right].target) {
                return -1;
            }
        }
    }
    if (maximum_target > MAX_REVIEWED_FD - MAX_PASS_FDS) {
        return -1;
    }
    int temporary_base = maximum_target + MAX_PASS_FDS;
    if (temporary_base < 64) {
        temporary_base = 64;
    }
    for (size_t index = 0; index < count; ++index) {
        int temporary = fcntl(mappings[index].source, F_DUPFD_CLOEXEC,
                              temporary_base);
        if (temporary < 0) {
            return -1;
        }
        mappings[index].temporary = temporary;
        temporary_base = temporary + 1;
    }
    unsigned int lower_last = (unsigned int)(maximum_target + MAX_PASS_FDS - 1);
    if (lower_last < 63U) {
        lower_last = 63U;
    }
    if (close_range_checked(3U, lower_last, CLOSE_RANGE_UNSHARE) < 0) {
        return -1;
    }
    for (size_t index = 0; index < count; ++index) {
        if (dup3(mappings[index].temporary, mappings[index].target, 0) < 0) {
            return -1;
        }
    }
    if (close_range_checked((unsigned int)maximum_target + 1U, UINT_MAX, 0) < 0) {
        return -1;
    }
    for (size_t index = 0; index < count; ++index) {
        if (!target_role_is_allowed(&mappings[index])) {
            return -1;
        }
    }

    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        return -1;
    }
    int directory_fd = dirfd(directory);
    bool valid = true;
    errno = 0;
    for (;;) {
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                valid = false;
            }
            break;
        }
        const char *end = NULL;
        int fd = parse_fd(entry->d_name, &end);
        if (fd < 0 || *end != '\0' || fd == directory_fd) {
            continue;
        }
        if (!target_is_allowed(mappings, count, fd) ||
            classify_fd(fd) != FD_ALLOWED) {
            valid = false;
            break;
        }
    }
    if (closedir(directory) < 0) {
        valid = false;
    }
    return valid ? 0 : -1;
}

static int boundary_failure(const char *reason) {
    emit_failure(reason);
    return EXIT_BOUNDARY_FAILURE;
}

int main(int argc, char **argv) {
    struct fd_mapping requested[MAX_PASS_FDS];
    size_t requested_count = 0;
    int command_index = -1;

    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--") == 0) {
            command_index = index + 1;
            break;
        }
        if (strcmp(argv[index], "--report-fd") == 0 && index + 1 < argc) {
            const char *end = NULL;
            report_fd = parse_fd(argv[++index], &end);
            if (report_fd < 3 || *end != '\0') {
                return EXIT_USAGE;
            }
            continue;
        }
        if (strcmp(argv[index], "--pass-fd") == 0 && index + 1 < argc &&
            requested_count < MAX_PASS_FDS - 3 &&
            parse_mapping(argv[++index], &requested[requested_count])) {
            ++requested_count;
            continue;
        }
        return EXIT_USAGE;
    }
    if (command_index < 0 || command_index >= argc ||
        argv[command_index][0] != '/') {
        return EXIT_USAGE;
    }

    pid_t original_parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || original_parent <= 1 ||
        getppid() != original_parent) {
        return boundary_failure("PROCESS_BOUNDARY_FAILED");
    }

    int observed = observe_inherited_fds(requested, requested_count);
    if (observed == EXIT_INHERITED_SOCKET) {
        emit_failure("INHERITED_SOCKET_FD");
        return EXIT_INHERITED_SOCKET;
    }
    if (observed != 0) {
        return boundary_failure("FD_OBSERVATION_FAILED");
    }

    struct fd_mapping mappings[MAX_PASS_FDS];
    size_t mapping_count = 0;
    if (add_standard_fds(mappings, &mapping_count) < 0) {
        return boundary_failure("FD_SANITATION_FAILED");
    }
    for (size_t index = 0; index < requested_count; ++index) {
        mappings[mapping_count++] = requested[index];
    }
    if (sanitize_fds(mappings, mapping_count) < 0) {
        return boundary_failure("FD_SANITATION_FAILED");
    }
    if (setsid() < 0) {
        return boundary_failure("PROCESS_BOUNDARY_FAILED");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        return boundary_failure("SECCOMP_INSTALL_FAILED");
    }
    if (install_tracee_seccomp() < 0) {
        return boundary_failure("SECCOMP_INSTALL_FAILED");
    }
    execv(argv[command_index], &argv[command_index]);
    return boundary_failure("EXEC_FAILED");
}
