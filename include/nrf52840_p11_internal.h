/*
 * Internal definitions for nRF52840 PKCS#11 Library
 */

#ifndef NRF52840_P11_INTERNAL_H
#define NRF52840_P11_INTERNAL_H 1

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "pkcs11/cryptoki.h"

#define P11_SLOT_ID                 0UL
#define P11_MAX_SESSIONS            16
#define P11_MAX_KEYS                16
#define P11_MAX_MATCHES             32

#define P11_TOKEN_LABEL             "nRF52840 HSM"
#define P11_MANUFACTURER_ID         "pid.codes"
#define P11_MODEL_NAME              "PCA10059"

/* Handle mapping:
 * Key IDs on token are 1..16.
 * Public key handle: (key_id << 1)
 * Private key handle: ((key_id << 1) | 1)
 */
#define P11_HANDLE_IS_VALID(h)      ((h) >= 2 && (h) <= 33)
#define P11_HANDLE_TO_KEY_ID(h)     ((uint8_t)((h) >> 1))
#define P11_HANDLE_IS_PRIVATE(h)    (((h) & 1) != 0)
#define P11_MAKE_PUB_HANDLE(id)     ((CK_OBJECT_HANDLE)(((id) << 1)))
#define P11_MAKE_PRIV_HANDLE(id)    ((CK_OBJECT_HANDLE)(((id) << 1) | 1))

/* Standard prime256v1 (secp256r1) ASN.1 OID: 1.2.840.10045.3.1.7 */
static const uint8_t P11_EC_P256_OID[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};
#define P11_EC_P256_OID_LEN sizeof(P11_EC_P256_OID)

/* Forward declaration of serial transport */
struct serial_transport;

typedef struct p11_key_entry {
    uint8_t key_id;
    char algo[16];
    uint32_t size_bits;
    char label[33];
    uint8_t pubkey[65];
    bool has_pubkey;
    bool exists;
} p11_key_entry_t;

typedef struct p11_search_ctx {
    bool active;
    CK_OBJECT_HANDLE matches[P11_MAX_MATCHES];
    CK_ULONG match_count;
    CK_ULONG current_idx;
} p11_search_ctx_t;

typedef struct p11_sign_ctx {
    bool active;
    CK_OBJECT_HANDLE key_handle;
    CK_MECHANISM_TYPE mechanism;
} p11_sign_ctx_t;

typedef struct p11_session {
    bool in_use;
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
    CK_STATE state;
    CK_FLAGS flags;
    p11_search_ctx_t search_ctx;
    p11_sign_ctx_t sign_ctx;
} p11_session_t;

typedef struct p11_global_ctx {
    bool initialized;
    pthread_mutex_t lock;
    struct serial_transport *transport;

    char fw_version[32];
    char hw_model[32];
    char uid_hex[32];
    char boot_stage[32];
    bool token_present;

    p11_key_entry_t keys[P11_MAX_KEYS + 1]; /* 1..16 */
    p11_session_t sessions[P11_MAX_SESSIONS];

    bool user_logged_in;
    bool so_logged_in;
    int pin_retries;
    bool configured;
    char auth_method[16]; /* "NONE", "PIN", "SHAMIR" */
} p11_global_ctx_t;

/* Singleton context access */
p11_global_ctx_t *p11_get_ctx(void);

/* Synchronize key cache with token */
CK_RV p11_refresh_keys(p11_global_ctx_t *ctx);

/* Ensure transport is open */
CK_RV p11_ensure_transport_open(p11_global_ctx_t *ctx);

/* Session state machine helpers */
void p11_session_notify_device_lock(p11_global_ctx_t *ctx);
CK_RV p11_session_sync_state(p11_global_ctx_t *ctx);

/* Logging helper */
void p11_log(const char *fmt, ...);

#endif /* NRF52840_P11_INTERNAL_H */
