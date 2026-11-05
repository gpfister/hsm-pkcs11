/*
 * AT Protocol Client Header for nRF52840 HSM
 */

#ifndef AT_CLIENT_H
#define AT_CLIENT_H 1

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "serial_transport.h"
#include "nrf52840_p11_internal.h"

int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_max_len, size_t *out_len);
int bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_max_len);

CK_RV at_error_to_ckr(int cme_code);

CK_RV at_ping(serial_transport_t *tr);
CK_RV at_get_info(serial_transport_t *tr, char *fw, size_t fw_len, char *hw, size_t hw_len, char *uid, size_t uid_len, char *boot, size_t boot_len);
CK_RV at_get_status(serial_transport_t *tr, bool *auth, int *retries, int *keycount, bool *configured, char *method, size_t method_len);
CK_RV at_auth(serial_transport_t *tr, const char *pin);
CK_RV at_lock(serial_transport_t *tr);
CK_RV at_reset(serial_transport_t *tr);
CK_RV at_get_slots(serial_transport_t *tr, p11_key_entry_t *keys, size_t max_keys, size_t *out_count);
CK_RV at_keygen(serial_transport_t *tr, uint8_t key_id, const char *algo, uint8_t *out_pubkey_65b);
CK_RV at_pubkey(serial_transport_t *tr, uint8_t key_id, uint8_t *out_pubkey_65b);
CK_RV at_sign(serial_transport_t *tr, uint8_t key_id, const uint8_t *hash_32b, uint8_t *out_sig_64b);
CK_RV at_random(serial_transport_t *tr, size_t len, uint8_t *out_rand);

#endif /* AT_CLIENT_H */
