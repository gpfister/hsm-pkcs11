/*
 * Serial Transport Interface for nRF52840 PKCS#11 Library
 */

#ifndef SERIAL_TRANSPORT_H
#define SERIAL_TRANSPORT_H 1

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

typedef struct serial_transport {
#if defined(_WIN32)
    HANDLE handle;
    CRITICAL_SECTION lock;
#else
    int fd;
    pthread_mutex_t lock;
#endif
    char port_path[256];
    bool is_open;
    int baudrate;
} serial_transport_t;

int serial_init(serial_transport_t *tr);
int serial_open(serial_transport_t *tr, const char *port_path, int baudrate);
int serial_auto_open(serial_transport_t *tr);
int serial_score_candidate(const char *path);
void serial_close(serial_transport_t *tr);
bool serial_is_open(const serial_transport_t *tr);
int serial_flush(serial_transport_t *tr);
int serial_write(serial_transport_t *tr, const void *buf, size_t len);
int serial_read_line(serial_transport_t *tr, char *buf, size_t max_len, int timeout_ms);
int serial_transaction(serial_transport_t *tr, const char *cmd, char *resp_buf, size_t max_resp_len, int timeout_ms);

#endif /* SERIAL_TRANSPORT_H */
