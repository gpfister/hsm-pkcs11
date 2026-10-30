/*
 * POSIX Serial Transport Driver (macOS / Linux)
 */

#if !defined(_WIN32)

#include "serial_transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <poll.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

static int s_debug_enabled = -1;

static bool is_debug(void) {
    if (s_debug_enabled == -1) {
        const char *env = getenv("NRF52840_HSM_DEBUG");
        s_debug_enabled = (env && (strcmp(env, "1") == 0 || strcasecmp(env, "true") == 0 || strcasecmp(env, "trace") == 0)) ? 1 : 0;
    }
    return s_debug_enabled == 1;
}

int serial_init(serial_transport_t *tr) {
    if (!tr) return -EINVAL;
    memset(tr, 0, sizeof(*tr));
    tr->fd = -1;
    tr->baudrate = 115200;
    tr->is_open = false;
    pthread_mutex_init(&tr->lock, NULL);
    return 0;
}

int serial_open(serial_transport_t *tr, const char *port_path, int baudrate) {
    if (!tr || !port_path) return -EINVAL;

    pthread_mutex_lock(&tr->lock);

    if (tr->is_open && tr->fd >= 0) {
        close(tr->fd);
        tr->fd = -1;
        tr->is_open = false;
    }

    int fd = open(port_path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        pthread_mutex_unlock(&tr->lock);
        return -errno;
    }

    struct termios options;
    if (tcgetattr(fd, &options) != 0) {
        close(fd);
        pthread_mutex_unlock(&tr->lock);
        return -errno;
    }

    cfmakeraw(&options);

    speed_t speed = B115200;
    if (baudrate == 9600) speed = B9600;
    else if (baudrate == 19200) speed = B19200;
    else if (baudrate == 38400) speed = B38400;
    else if (baudrate == 57600) speed = B57600;
    else speed = B115200;

    cfsetispeed(&options, speed);
    cfsetospeed(&options, speed);

    options.c_cflag |= (CLOCAL | CREAD);
    options.c_cflag &= ~PARENB;
    options.c_cflag &= ~CSTOPB;
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= CS8;
#if defined(CRTSCTS)
    options.c_cflag &= ~CRTSCTS;
#endif

    options.c_cc[VMIN] = 0;
    options.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &options) != 0) {
        close(fd);
        pthread_mutex_unlock(&tr->lock);
        return -errno;
    }

    tcflush(fd, TCIOFLUSH);

    tr->fd = fd;
    tr->baudrate = baudrate;
    tr->is_open = true;
    strncpy(tr->port_path, port_path, sizeof(tr->port_path) - 1);

    if (is_debug()) {
        fprintf(stderr, "[P11 SERIAL] Opened serial port %s (baud: %d, fd: %d)\n", port_path, baudrate, fd);
    }

    pthread_mutex_unlock(&tr->lock);
    return 0;
}

void serial_close(serial_transport_t *tr) {
    if (!tr) return;
    pthread_mutex_lock(&tr->lock);
    if (tr->is_open && tr->fd >= 0) {
        if (is_debug()) {
            fprintf(stderr, "[P11 SERIAL] Closing serial port %s\n", tr->port_path);
        }
        close(tr->fd);
        tr->fd = -1;
        tr->is_open = false;
    }
    pthread_mutex_unlock(&tr->lock);
}

bool serial_is_open(const serial_transport_t *tr) {
    return (tr && tr->is_open && tr->fd >= 0);
}

int serial_flush(serial_transport_t *tr) {
    if (!serial_is_open(tr)) return -EBADF;
    return tcflush(tr->fd, TCIOFLUSH);
}

int serial_write(serial_transport_t *tr, const void *buf, size_t len) {
    if (!serial_is_open(tr)) return -EBADF;
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t written = 0;

    while (written < len) {
        struct pollfd pfd = { .fd = tr->fd, .events = POLLOUT };
        int poll_ret = poll(&pfd, 1, 2000);
        if (poll_ret <= 0) {
            return (poll_ret == 0) ? -ETIMEDOUT : -errno;
        }

        ssize_t n = write(tr->fd, ptr + written, len - written);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            return -errno;
        }
        written += (size_t)n;
    }
    return (int)written;
}

int serial_read_line(serial_transport_t *tr, char *buf, size_t max_len, int timeout_ms) {
    if (!serial_is_open(tr) || !buf || max_len == 0) return -EINVAL;

    size_t idx = 0;
    while (idx + 1 < max_len) {
        struct pollfd pfd = { .fd = tr->fd, .events = POLLIN };
        int poll_ret = poll(&pfd, 1, timeout_ms);
        if (poll_ret <= 0) {
            if (poll_ret == 0) {
                if (idx > 0) {
                    buf[idx] = '\0';
                    return (int)idx;
                }
                return -ETIMEDOUT;
            }
            if (errno == EINTR) continue;
            return -errno;
        }

        char ch = 0;
        ssize_t n = read(tr->fd, &ch, 1);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                continue;
            }
            return -EIO;
        }

        if (ch == '\r') {
            continue;
        }
        if (ch == '\n') {
            buf[idx] = '\0';
            return (int)idx;
        }

        buf[idx++] = ch;
    }

    buf[idx] = '\0';
    return (int)idx;
}

int serial_transaction(serial_transport_t *tr, const char *cmd, char *resp_buf, size_t max_resp_len, int timeout_ms) {
    if (!tr || !cmd) return -EINVAL;

    pthread_mutex_lock(&tr->lock);

    if (!tr->is_open || tr->fd < 0) {
        pthread_mutex_unlock(&tr->lock);
        return -EBADF;
    }

    /* Flush leftover incoming noise */
    tcflush(tr->fd, TCIFLUSH);

    char full_cmd[512];
    size_t cmd_len = strlen(cmd);
    if (cmd_len >= 2 && cmd[cmd_len - 2] == '\r' && cmd[cmd_len - 1] == '\n') {
        snprintf(full_cmd, sizeof(full_cmd), "%s", cmd);
    } else {
        snprintf(full_cmd, sizeof(full_cmd), "%s\r\n", cmd);
    }

    if (is_debug()) {
        fprintf(stderr, "[P11 TX] %s", full_cmd);
    }

    int write_ret = serial_write(tr, full_cmd, strlen(full_cmd));
    if (write_ret < 0) {
        pthread_mutex_unlock(&tr->lock);
        return write_ret;
    }

    if (resp_buf && max_resp_len > 0) {
        resp_buf[0] = '\0';
    }

    char line[512];
    size_t resp_pos = 0;
    int status = 0;

    while (1) {
        int rlen = serial_read_line(tr, line, sizeof(line), timeout_ms);
        if (rlen < 0) {
            status = rlen;
            break;
        }

        if (is_debug()) {
            fprintf(stderr, "[P11 RX] %s\n", line);
        }

        /* Skip leading empty lines */
        if (rlen == 0) {
            continue;
        }

        if (strcmp(line, "OK") == 0) {
            status = 0;
            break;
        }

        if (strncmp(line, "+CME ERROR:", 11) == 0) {
            int cme_code = 0;
            if (sscanf(line + 11, "%d", &cme_code) == 1) {
                status = cme_code;
            } else {
                status = 1; /* generic error */
            }
            if (resp_buf && resp_pos + strlen(line) + 2 < max_resp_len) {
                resp_pos += (size_t)snprintf(resp_buf + resp_pos, max_resp_len - resp_pos, "%s\n", line);
            }
            break;
        }

        /* Accumulate payload line */
        if (resp_buf && resp_pos + strlen(line) + 2 < max_resp_len) {
            resp_pos += (size_t)snprintf(resp_buf + resp_pos, max_resp_len - resp_pos, "%s\n", line);
        }
    }

    pthread_mutex_unlock(&tr->lock);
    return status;
}

int serial_score_candidate(const char *path) {
    if (!path) return -1;
    size_t len = strlen(path);
    char last = (len > 0) ? path[len - 1] : 0;

#if defined(__APPLE__)
    if (strstr(path, "tty.usbmodem") != NULL) {
        if (last == '3') return 1000;
        if (last != '1') return 600;
        return 200; /* Console logger port */
    }
    if (strstr(path, "cu.usbmodem") != NULL) {
        if (last == '3') return 900;
        if (last != '1') return 500;
        return 100; /* Console logger port */
    }
    if (last == '3') return 800;
    if (last == '1') return 50;
    return 400;
#else
    if (strstr(path, "ttyACM") != NULL) {
        if (last == '1' || last == '3') return 1000;
        if (last == '0') return 200;
        return 500;
    }
    return 300;
#endif
}

typedef struct {
    char path[256];
    int score;
} port_candidate_t;

static int compare_port_candidates(const void *a, const void *b) {
    const port_candidate_t *ca = (const port_candidate_t *)a;
    const port_candidate_t *cb = (const port_candidate_t *)b;
    if (ca->score != cb->score) {
        return cb->score - ca->score; /* Descending by score */
    }
    return strcmp(ca->path, cb->path); /* Deterministic ascending by path */
}

int serial_auto_open(serial_transport_t *tr) {
    if (!tr) return -EINVAL;

    /* 1. Explicit environment override takes precedence */
    const char *env_port = getenv("NRF52840_HSM_PORT");
    if (env_port && env_port[0] != '\0') {
        if (is_debug()) {
            fprintf(stderr, "[P11 SERIAL] Using explicit NRF52840_HSM_PORT override: %s\n", env_port);
        }
        return serial_open(tr, env_port, 115200);
    }

    /* 2. Explicit serial number targeting: NRF52840_HSM_SERIAL */
    const char *env_serial = getenv("NRF52840_HSM_SERIAL");
    if (env_serial && env_serial[0] != '\0') {
        char direct_path[256];
        size_t slen = strlen(env_serial);

        if (strncmp(env_serial, "/dev/", 5) == 0) {
            snprintf(direct_path, sizeof(direct_path), "%s", env_serial);
        } else if (slen > 0 && env_serial[slen - 1] == '3') {
            snprintf(direct_path, sizeof(direct_path), "/dev/tty.usbmodem%s", env_serial);
        } else {
            snprintf(direct_path, sizeof(direct_path), "/dev/tty.usbmodem%s3", env_serial);
        }

        if (is_debug()) {
            fprintf(stderr, "[P11 SERIAL] Targeting serial '%s' via direct port %s\n", env_serial, direct_path);
        }

        if (serial_open(tr, direct_path, 115200) == 0) {
            char resp[64];
            int ret = serial_transaction(tr, "AT", resp, sizeof(resp), 500);
            if (ret == 0) {
                return 0;
            }
            serial_close(tr);
        }

        /* Fallback to cu.usbmodem<SERIAL>3 if tty.usbmodem was busy or unavailable */
        if (strncmp(env_serial, "/dev/", 5) != 0) {
            if (slen > 0 && env_serial[slen - 1] == '3') {
                snprintf(direct_path, sizeof(direct_path), "/dev/cu.usbmodem%s", env_serial);
            } else {
                snprintf(direct_path, sizeof(direct_path), "/dev/cu.usbmodem%s3", env_serial);
            }

            if (is_debug()) {
                fprintf(stderr, "[P11 SERIAL] Fallback targeting serial '%s' via direct port %s\n", env_serial, direct_path);
            }

            if (serial_open(tr, direct_path, 115200) == 0) {
                char resp[64];
                int ret = serial_transaction(tr, "AT", resp, sizeof(resp), 500);
                if (ret == 0) {
                    return 0;
                }
                serial_close(tr);
            }
        }
    }

    /* 3. Scan ports on macOS / Linux */
    DIR *dir = opendir("/dev");
    if (!dir) return -ENOENT;

    struct dirent *entry;
    port_candidate_t candidates[64];
    int candidate_count = 0;

    while ((entry = readdir(dir)) != NULL) {
        bool is_match = false;
#if defined(__APPLE__)
        /* Look for /dev/tty.usbmodem* and /dev/cu.usbmodem* */
        if (strncmp(entry->d_name, "tty.usbmodem", 12) == 0 ||
            strncmp(entry->d_name, "cu.usbmodem", 11) == 0) {
            is_match = true;
        }
#else
        /* Look for /dev/ttyACM* */
        if (strncmp(entry->d_name, "ttyACM", 6) == 0) {
            is_match = true;
        }
#endif
        if (!is_match) {
            continue;
        }

        /* If NRF52840_HSM_SERIAL was set, only retain matching device entries */
        if (env_serial && env_serial[0] != '\0') {
            if (strstr(entry->d_name, env_serial) == NULL) {
                continue;
            }
        }

        snprintf(candidates[candidate_count].path, sizeof(candidates[candidate_count].path), "/dev/%s", entry->d_name);
        candidates[candidate_count].score = serial_score_candidate(candidates[candidate_count].path);
        candidate_count++;
        if (candidate_count >= 64) break;
    }
    closedir(dir);

    /* Sort candidates by priority score descending (suffix '3' first, suffix '1' last) */
    if (candidate_count > 1) {
        qsort(candidates, candidate_count, sizeof(port_candidate_t), compare_port_candidates);
    }

    if (is_debug()) {
        for (int i = 0; i < candidate_count; i++) {
            fprintf(stderr, "[P11 SERIAL] Candidate [%d]: %s (score=%d)\n", i, candidates[i].path, candidates[i].score);
        }
    }

    /* Test each candidate port in prioritized order with AT ping */
    for (int i = 0; i < candidate_count; i++) {
        if (serial_open(tr, candidates[i].path, 115200) == 0) {
            char resp[64];
            int ret = serial_transaction(tr, "AT", resp, sizeof(resp), 500);
            if (ret == 0) {
                return 0; /* Successfully matched and opened */
            }
            serial_close(tr);
        }
    }

    return -ENODEV;
}

#endif /* !_WIN32 */
