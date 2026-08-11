#include <asm/unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum { MAX_INSPECTED_FDS = 64, FINALIZER_TIMEOUT_SECONDS = 4 };

static void timeout_handler(int signal_number) {
    (void)signal_number;
    _exit(124);
}

static int integer_compare(const void *left, const void *right) {
    int left_value = *(const int *)left;
    int right_value = *(const int *)right;
    return (left_value > right_value) - (left_value < right_value);
}

static const char *fd_type(int fd) {
    struct stat descriptor_stat;
    if (fstat(fd, &descriptor_stat) < 0) {
        return "unknown";
    }
    if (S_ISREG(descriptor_stat.st_mode)) {
        return "regular_file";
    }
    if (S_ISCHR(descriptor_stat.st_mode)) {
        return "character_device";
    }
    if (S_ISFIFO(descriptor_stat.st_mode)) {
        return "pipe";
    }
    if (S_ISSOCK(descriptor_stat.st_mode)) {
        return "socket";
    }
    return "unknown";
}

static int inspect_boundary(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        return 70;
    }
    int directory_fd = dirfd(directory);
    int descriptors[MAX_INSPECTED_FDS];
    size_t count = 0;
    errno = 0;
    for (;;) {
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                (void)closedir(directory);
                return 70;
            }
            break;
        }
        char *end = NULL;
        errno = 0;
        long value = strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' || value < 0 ||
            value > 65535 || value == directory_fd) {
            continue;
        }
        if (count == MAX_INSPECTED_FDS) {
            (void)closedir(directory);
            return 70;
        }
        descriptors[count++] = (int)value;
    }
    if (closedir(directory) < 0) {
        return 70;
    }
    qsort(descriptors, count, sizeof(descriptors[0]), integer_compare);

    int parent_death_signal = 0;
    if (prctl(PR_GET_PDEATHSIG, &parent_death_signal) < 0) {
        return 70;
    }
    int no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (no_new_privs < 0) {
        return 70;
    }
    printf("{\"pid\":%ld,\"pgid\":%ld,\"sid\":%ld,"
           "\"no_new_privs\":%d,\"parent_death_signal\":%d,\"fds\":[",
           (long)getpid(), (long)getpgid(0), (long)getsid(0), no_new_privs,
           parent_death_signal);
    for (size_t index = 0; index < count; ++index) {
        printf("%s%d", index == 0 ? "" : ",", descriptors[index]);
    }
    printf("],\"fd_types\":{");
    for (size_t index = 0; index < count; ++index) {
        printf("%s\"%d\":\"%s\"", index == 0 ? "" : ",", descriptors[index],
               fd_type(descriptors[index]));
    }
    puts("}}");
    return ferror(stdout) ? 70 : 0;
}

#ifdef HOLOAGENT_NATIVE_TEST_PROBE
static long clone_probe(unsigned long flags) {
    errno = 0;
    long result = syscall(__NR_clone, flags, NULL, NULL, NULL, 0UL);
    if (result == 0) {
        _exit(0);
    }
    if (result > 0) {
        int status = 0;
        if (waitpid((pid_t)result, &status, 0) != result ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            errno = ECHILD;
            return -1;
        }
        errno = 0;
    }
    return result;
}

static int probe_syscall(const char *name) {
    errno = 0;
    long result = -1;
    if (strcmp(name, "io_uring_setup") == 0) {
        result = syscall(__NR_io_uring_setup, 1U, NULL);
    } else if (strcmp(name, "io_uring_enter") == 0) {
        result = syscall(__NR_io_uring_enter, -1, 0U, 0U, 0U, NULL, 0U);
    } else if (strcmp(name, "io_uring_register") == 0) {
        result = syscall(__NR_io_uring_register, -1, 0U, NULL, 0U);
    } else if (strcmp(name, "pidfd_getfd") == 0) {
        result = syscall(__NR_pidfd_getfd, -1, -1, 0U);
    } else if (strcmp(name, "ptrace") == 0) {
        result = syscall(__NR_ptrace, PTRACE_TRACEME, 0, NULL, NULL);
    } else if (strcmp(name, "clone_untraced") == 0) {
        result = clone_probe(CLONE_UNTRACED | SIGCHLD);
    } else if (strcmp(name, "clone_plain") == 0) {
        result = clone_probe(SIGCHLD);
    } else if (strcmp(name, "clone3") == 0) {
        result = syscall(__NR_clone3, NULL, 0U);
    } else if (strcmp(name, "getpid") == 0) {
        result = syscall(__NR_getpid);
#if defined(__x86_64__)
    } else if (strcmp(name, "x32_ptrace") == 0) {
        result = syscall(__X32_SYSCALL_BIT | __NR_ptrace, PTRACE_TRACEME, 0,
                         NULL, NULL);
#endif
    } else {
        fputs("finalizer_only: unsupported probe\n", stderr);
        return 64;
    }
    int saved_errno = result < 0 ? errno : 0;
    printf("{\"probe\":\"%s\",\"result\":%ld,\"errno\":%d}\n", name,
           result, saved_errno);
    return ferror(stdout) ? 70 : 0;
}

static bool send_one(int fd, char value) {
    struct iovec vector = {.iov_base = &value, .iov_len = 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    return sendmsg(fd, &message, 0) == 1;
}

static bool receive_one(int fd, char expected) {
    char value = '\0';
    struct iovec vector = {.iov_base = &value, .iov_len = 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    return recvmsg(fd, &message, MSG_DONTWAIT) == 1 && value == expected;
}

static int message_round_trip(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair) < 0) {
        return 70;
    }
    errno = 0;
    bool sent = send_one(pair[0], 'a');
    int send_error = sent ? 0 : errno;
    errno = 0;
    bool received = sent && receive_one(pair[1], 'a');
    int receive_error = received ? 0 : errno;

    char outbound = 'b';
    struct iovec send_vector = {.iov_base = &outbound, .iov_len = 1};
    struct mmsghdr send_batch = {
        .msg_hdr = {.msg_iov = &send_vector, .msg_iovlen = 1},
    };
    errno = 0;
    int send_batch_result = sendmmsg(pair[0], &send_batch, 1, 0);
    int send_batch_error = send_batch_result < 0 ? errno : 0;
    bool batch_sent = send_batch_result == 1 && send_batch.msg_len == 1;
    bool message_available = send_batch_result == 1;
    if (!message_available) {
        message_available = send_one(pair[0], 'b');
    }
    char inbound = '\0';
    struct iovec receive_vector = {.iov_base = &inbound, .iov_len = 1};
    struct mmsghdr receive_batch = {
        .msg_hdr = {.msg_iov = &receive_vector, .msg_iovlen = 1},
    };
    errno = 0;
    int receive_batch_result =
        message_available
            ? recvmmsg(pair[1], &receive_batch, 1, MSG_DONTWAIT, NULL)
            : -1;
    int receive_batch_error =
        receive_batch_result < 0 ? (message_available ? errno : EIO) : 0;
    bool batch_received = receive_batch_result == 1 &&
                          receive_batch.msg_len == 1 && inbound == 'b';
    bool close_ok = close(pair[0]) == 0 && close(pair[1]) == 0;
    printf("{\"sendmsg\":%s,\"recvmsg\":%s,\"sendmmsg\":%s,"
           "\"recvmmsg\":%s,\"sendmsg_errno\":%d,"
           "\"recvmsg_errno\":%d,\"sendmmsg_errno\":%d,"
           "\"recvmmsg_errno\":%d}\n",
           sent ? "true" : "false", received ? "true" : "false",
           batch_sent ? "true" : "false", batch_received ? "true" : "false",
           send_error, receive_error, send_batch_error, receive_batch_error);
    return sent && received && batch_sent && batch_received && close_ok &&
                   !ferror(stdout)
               ? 0
               : 70;
}
#endif

static int install_deadline(void) {
    struct sigaction action = {
        .sa_handler = timeout_handler,
    };
    sigset_t alarm_signal;
    if (sigemptyset(&action.sa_mask) < 0 ||
        sigaction(SIGALRM, &action, NULL) < 0 ||
        sigemptyset(&alarm_signal) < 0 ||
        sigaddset(&alarm_signal, SIGALRM) < 0 ||
        sigprocmask(SIG_UNBLOCK, &alarm_signal, NULL) < 0) {
        return -1;
    }
    alarm(FINALIZER_TIMEOUT_SECONDS);
    return 0;
}

int main(int argc, char **argv) {
    if (install_deadline() < 0) {
        return 70;
    }

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--finalize") == 0)) {
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--inspect") == 0) {
        return inspect_boundary();
    }
#ifdef HOLOAGENT_NATIVE_TEST_PROBE
    if (argc == 3 && strcmp(argv[1], "--probe") == 0) {
        return probe_syscall(argv[2]);
    }
    if (argc == 2 && strcmp(argv[1], "--message-round-trip") == 0) {
        return message_round_trip();
    }
    if (argc == 2 && strcmp(argv[1], "--block-forever") == 0) {
        for (;;) {
            pause();
        }
    }
#endif
    fputs("finalizer_only: unsupported operation\n", stderr);
    return 64;
}
