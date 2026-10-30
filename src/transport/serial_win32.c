/*
 * Win32 Serial Transport Driver
 */

#if defined(_WIN32)

#include "serial_transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int serial_init(serial_transport_t *tr) {
    if (!tr) return -1;
    memset(tr, 0, sizeof(*tr));
    tr->handle = INVALID_HANDLE_VALUE;
    tr->baudrate = 115200;
    tr->is_open = false;
    InitializeCriticalSection(&tr->lock);
    return 0;
}

int serial_open(serial_transport_t *tr, const char *port_path, int baudrate) {
    if (!tr || !port_path) return -1;

    EnterCriticalSection(&tr->lock);

    if (tr->is_open && tr->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(tr->handle);
        tr->handle = INVALID_HANDLE_VALUE;
        tr->is_open = false;
    }

    char full_name[256];
    if (strncmp(port_path, "\\\\.\\", 4) == 0) {
        snprintf(full_name, sizeof(full_name), "%s", port_path);
    } else {
        snprintf(full_name, sizeof(full_name), "\\\\.\\%s", port_path);
    }

    HANDLE h = CreateFileA(full_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&tr->lock);
        return -1;
    }

    DCB dcb;
    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(h, &dcb)) {
        CloseHandle(h);
        LeaveCriticalSection(&tr->lock);
        return -1;
    }

    dcb.BaudRate = (DWORD)baudrate;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;

    if (!SetCommState(h, &dcb)) {
        CloseHandle(h);
        LeaveCriticalSection(&tr->lock);
        return -1;
    }

    COMMTIMEOUTS timeouts;
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = 2000;
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 2000;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    SetCommTimeouts(h, &timeouts);

    PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);

    tr->handle = h;
    tr->baudrate = baudrate;
    tr->is_open = true;
    strncpy(tr->port_path, port_path, sizeof(tr->port_path) - 1);

    LeaveCriticalSection(&tr->lock);
    return 0;
}

void serial_close(serial_transport_t *tr) {
    if (!tr) return;
    EnterCriticalSection(&tr->lock);
    if (tr->is_open && tr->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(tr->handle);
        tr->handle = INVALID_HANDLE_VALUE;
        tr->is_open = false;
    }
    LeaveCriticalSection(&tr->lock);
}

bool serial_is_open(const serial_transport_t *tr) {
    return (tr && tr->is_open && tr->handle != INVALID_HANDLE_VALUE);
}

int serial_flush(serial_transport_t *tr) {
    if (!serial_is_open(tr)) return -1;
    PurgeComm(tr->handle, PURGE_RXCLEAR | PURGE_TXCLEAR);
    return 0;
}

int serial_write(serial_transport_t *tr, const void *buf, size_t len) {
    if (!serial_is_open(tr)) return -1;
    DWORD written = 0;
    if (!WriteFile(tr->handle, buf, (DWORD)len, &written, NULL)) {
        return -1;
    }
    return (int)written;
}

int serial_read_line(serial_transport_t *tr, char *buf, size_t max_len, int timeout_ms) {
    if (!serial_is_open(tr) || !buf || max_len == 0) return -1;

    COMMTIMEOUTS timeouts;
    timeouts.ReadIntervalTimeout = 20;
    timeouts.ReadTotalTimeoutConstant = (DWORD)timeout_ms;
    timeouts.ReadTotalTimeoutMultiplier = 1;
    SetCommTimeouts(tr->handle, &timeouts);

    size_t idx = 0;
    while (idx + 1 < max_len) {
        char ch = 0;
        DWORD bytes_read = 0;
        if (!ReadFile(tr->handle, &ch, 1, &bytes_read, NULL) || bytes_read == 0) {
            if (idx > 0) {
                buf[idx] = '\0';
                return (int)idx;
            }
            return -1;
        }

        if (ch == '\r') continue;
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
    if (!tr || !cmd) return -1;

    EnterCriticalSection(&tr->lock);

    if (!tr->is_open || tr->handle == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&tr->lock);
        return -1;
    }

    PurgeComm(tr->handle, PURGE_RXCLEAR);

    char full_cmd[512];
    size_t cmd_len = strlen(cmd);
    if (cmd_len >= 2 && cmd[cmd_len - 2] == '\r' && cmd[cmd_len - 1] == '\n') {
        snprintf(full_cmd, sizeof(full_cmd), "%s", cmd);
    } else {
        snprintf(full_cmd, sizeof(full_cmd), "%s\r\n", cmd);
    }

    int write_ret = serial_write(tr, full_cmd, strlen(full_cmd));
    if (write_ret < 0) {
        LeaveCriticalSection(&tr->lock);
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
        if (rlen == 0) continue;

        if (strcmp(line, "OK") == 0) {
            status = 0;
            break;
        }

        if (strncmp(line, "+CME ERROR:", 11) == 0) {
            int cme_code = 0;
            if (sscanf(line + 11, "%d", &cme_code) == 1) {
                status = cme_code;
            } else {
                status = 1;
            }
            if (resp_buf && resp_pos + strlen(line) + 2 < max_resp_len) {
                resp_pos += (size_t)snprintf(resp_buf + resp_pos, max_resp_len - resp_pos, "%s\n", line);
            }
            break;
        }

        if (resp_buf && resp_pos + strlen(line) + 2 < max_resp_len) {
            resp_pos += (size_t)snprintf(resp_buf + resp_pos, max_resp_len - resp_pos, "%s\n", line);
        }
    }

    LeaveCriticalSection(&tr->lock);
    return status;
}

int serial_score_candidate(const char *path) {
    (void)path;
    return 100;
}

int serial_auto_open(serial_transport_t *tr) {
    if (!tr) return -1;
    const char *env_port = getenv("NRF52840_HSM_PORT");
    if (env_port && env_port[0] != '\0') {
        return serial_open(tr, env_port, 115200);
    }

    for (int i = 1; i <= 32; i++) {
        char port[32];
        snprintf(port, sizeof(port), "COM%d", i);
        if (serial_open(tr, port, 115200) == 0) {
            char resp[64];
            int ret = serial_transaction(tr, "AT", resp, sizeof(resp), 500);
            if (ret == 0) {
                return 0;
            }
            serial_close(tr);
        }
    }
    return -1;
}

#endif /* _WIN32 */
