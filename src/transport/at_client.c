/*
 * AT Protocol Client Implementation
 */

#include "at_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_max_len, size_t *out_len) {
    if (!hex || !bin || !out_len) return -EINVAL;

    size_t hex_len = strlen(hex);
    size_t written = 0;

    for (size_t i = 0; i < hex_len; ) {
        while (i < hex_len && (isspace((unsigned char)hex[i]) || hex[i] == '\"' || hex[i] == '\'')) {
            i++;
        }
        if (i >= hex_len) break;

        if (i + 1 >= hex_len) {
            return -EINVAL; /* Odd number of hex characters */
        }

        if (written >= bin_max_len) {
            return -ENOBUFS;
        }

        char byte_str[3] = { hex[i], hex[i + 1], '\0' };
        char *endptr = NULL;
        unsigned long val = strtoul(byte_str, &endptr, 16);
        if (endptr != byte_str + 2) {
            return -EINVAL;
        }

        bin[written++] = (uint8_t)val;
        i += 2;
    }

    *out_len = written;
    return 0;
}

int bin_to_hex(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_max_len) {
    if (!bin || !hex || hex_max_len < (bin_len * 2 + 1)) return -EINVAL;

    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + (i * 2), "%02X", bin[i]);
    }
    hex[bin_len * 2] = '\0';
    return 0;
}

CK_RV at_error_to_ckr(int cme_code) {
    if (cme_code <= 0) {
        if (cme_code == 0) return CKR_OK;
        if (cme_code == -ETIMEDOUT) return CKR_DEVICE_ERROR;
        if (cme_code == -EBADF || cme_code == -ENODEV) return CKR_DEVICE_REMOVED;
        return CKR_DEVICE_ERROR;
    }

    switch (cme_code) {
        case 1: return CKR_USER_NOT_LOGGED_IN;    /* DEVICE_LOCKED */
        case 2: return CKR_PIN_INCORRECT;          /* INVALID_PIN */
        case 3: return CKR_PIN_LOCKED;             /* PIN_BLOCKED */
        case 4: return CKR_KEY_HANDLE_INVALID;     /* KEY_NOT_FOUND */
        case 5: return CKR_ARGUMENTS_BAD;          /* INVALID_PARAMETER */
        case 6: return CKR_FUNCTION_FAILED;        /* CRYPTO_FAILURE */
        case 7: return CKR_DEVICE_MEMORY;          /* BUFFER_OVERFLOW */
        case 8: return CKR_FUNCTION_NOT_SUPPORTED; /* COMMAND_UNSUPPORTED */
        default: return CKR_DEVICE_ERROR;
    }
}

static char *extract_quoted_val(const char *src, const char *key, char *dst, size_t dst_len) {
    if (!src || !key || !dst || dst_len == 0) return NULL;
    dst[0] = '\0';

    size_t klen = strlen(key);
    const char *p = src;
    while ((p = strstr(p, key)) != NULL) {
        if (p == src || isspace((unsigned char)*(p - 1)) || *(p - 1) == ',' || *(p - 1) == ':' || *(p - 1) == '+') {
            const char *after = p + klen;
            while (*after == ' ') after++;
            if (*after == '=') {
                p = after + 1;
                while (*p == ' ') p++;
                if (*p == '\"') {
                    p++;
                    size_t idx = 0;
                    while (*p && *p != '\"' && idx + 1 < dst_len) {
                        dst[idx++] = *p++;
                    }
                    dst[idx] = '\0';
                    return dst;
                }
                size_t idx = 0;
                while (*p && *p != ',' && *p != '\r' && *p != '\n' && !isspace((unsigned char)*p) && idx + 1 < dst_len) {
                    dst[idx++] = *p++;
                }
                dst[idx] = '\0';
                return dst;
            }
        }
        p += klen;
    }
    return NULL;
}

CK_RV at_ping(serial_transport_t *tr) {
    char resp[128];
    int ret = serial_transaction(tr, "AT", resp, sizeof(resp), 1000);
    return at_error_to_ckr(ret);
}

CK_RV at_get_info(serial_transport_t *tr, char *fw, size_t fw_len, char *hw, size_t hw_len, char *uid, size_t uid_len, char *boot, size_t boot_len) {
    char resp[256];
    int ret = serial_transaction(tr, "AT+INFO?", resp, sizeof(resp), 1500);
    if (ret != 0) return at_error_to_ckr(ret);

    if (fw && fw_len > 0) extract_quoted_val(resp, "FW", fw, fw_len);
    if (hw && hw_len > 0) extract_quoted_val(resp, "HW", hw, hw_len);
    if (uid && uid_len > 0) extract_quoted_val(resp, "UID", uid, uid_len);
    if (boot && boot_len > 0) extract_quoted_val(resp, "BOOT", boot, boot_len);

    return CKR_OK;
}

CK_RV at_get_status(serial_transport_t *tr, bool *auth, int *retries, int *keycount, bool *configured, char *method, size_t method_len) {
    char resp[256];
    int ret = serial_transaction(tr, "AT+STATUS?", resp, sizeof(resp), 1500);
    if (ret != 0) return at_error_to_ckr(ret);

    char val[32];
    if (auth) {
        *auth = false;
        if (extract_quoted_val(resp, "AUTH", val, sizeof(val))) {
            *auth = (atoi(val) != 0);
        }
    }
    if (retries) {
        *retries = 3;
        if (extract_quoted_val(resp, "RETRIES", val, sizeof(val))) {
            *retries = atoi(val);
        }
    }
    if (keycount) {
        *keycount = 0;
        if (extract_quoted_val(resp, "KEYCOUNT", val, sizeof(val))) {
            *keycount = atoi(val);
        }
    }
    if (configured) {
        *configured = true;
        if (extract_quoted_val(resp, "CONFIGURED", val, sizeof(val))) {
            *configured = (atoi(val) != 0);
        }
    }
    if (method && method_len > 0) {
        strncpy(method, "PIN", method_len - 1);
        method[method_len - 1] = '\0';
        if (extract_quoted_val(resp, "METHOD", val, sizeof(val))) {
            strncpy(method, val, method_len - 1);
            method[method_len - 1] = '\0';
        }
    }

    return CKR_OK;
}

CK_RV at_auth(serial_transport_t *tr, const char *pin) {
    if (!pin) return CKR_ARGUMENTS_BAD;

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "AT+AUTH=%s", pin);

    char resp[128];
    int ret = serial_transaction(tr, cmd, resp, sizeof(resp), 2000);
    return at_error_to_ckr(ret);
}

CK_RV at_lock(serial_transport_t *tr) {
    char resp[128];
    int ret = serial_transaction(tr, "AT+LOCK", resp, sizeof(resp), 1000);
    return at_error_to_ckr(ret);
}

CK_RV at_reset(serial_transport_t *tr) {
    char resp[128];
    int ret = serial_transaction(tr, "AT+RESET", resp, sizeof(resp), 1000);
    return at_error_to_ckr(ret);
}

CK_RV at_get_slots(serial_transport_t *tr, p11_key_entry_t *keys, size_t max_keys, size_t *out_count) {
    if (!keys || !out_count || max_keys == 0) return CKR_ARGUMENTS_BAD;

    *out_count = 0;
    char resp[1024];
    int ret = serial_transaction(tr, "AT+SLOTS?", resp, sizeof(resp), 2000);
    if (ret != 0) return at_error_to_ckr(ret);

    char *saveptr = NULL;
    char *line = strtok_r(resp, "\r\n", &saveptr);
    size_t count = 0;

    while (line && count < max_keys) {
        if (strncmp(line, "+SLOTS:", 7) == 0) {
            const char *p = line + 7;
            while (*p == ' ') p++;

            int id = 0, size = 256;
            char algo[32] = {0};
            char label[64] = {0};

            /* Format: <id>,<algo>,<size>,<label> */
            if (sscanf(p, "%d,%31[^,],%d,%63s", &id, algo, &size, label) >= 2) {
                if (id >= 1 && id <= P11_MAX_KEYS) {
                    keys[count].key_id = (uint8_t)id;
                    strncpy(keys[count].algo, algo, sizeof(keys[count].algo) - 1);
                    keys[count].size_bits = (uint32_t)size;
                    strncpy(keys[count].label, label, sizeof(keys[count].label) - 1);
                    keys[count].exists = true;
                    keys[count].has_pubkey = false;
                    count++;
                }
            }
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }

    *out_count = count;
    return CKR_OK;
}

CK_RV at_keygen(serial_transport_t *tr, uint8_t key_id, const char *algo, uint8_t *out_pubkey_65b) {
    if (key_id < 1 || key_id > P11_MAX_KEYS || !out_pubkey_65b) return CKR_ARGUMENTS_BAD;

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "AT+KEYGEN=%d,%s", key_id, algo ? algo : "EC_P256");

    char resp[256];
    int ret = serial_transaction(tr, cmd, resp, sizeof(resp), 4000);
    if (ret != 0) return at_error_to_ckr(ret);

    char hex_pub[256] = {0};
    if (!extract_quoted_val(resp, "PUB", hex_pub, sizeof(hex_pub))) {
        /* Fallback: check without quotes */
        const char *p = strstr(resp, "PUB=");
        if (p) {
            p += 4;
            sscanf(p, "%255s", hex_pub);
        }
    }

    size_t bin_len = 0;
    if (hex_to_bin(hex_pub, out_pubkey_65b, 65, &bin_len) != 0 || bin_len != 65) {
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

CK_RV at_pubkey(serial_transport_t *tr, uint8_t key_id, uint8_t *out_pubkey_65b) {
    if (key_id < 1 || key_id > P11_MAX_KEYS || !out_pubkey_65b) return CKR_ARGUMENTS_BAD;

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "AT+PUBKEY=%d", key_id);

    char resp[256];
    int ret = serial_transaction(tr, cmd, resp, sizeof(resp), 2000);
    if (ret != 0) return at_error_to_ckr(ret);

    char hex_pub[256] = {0};
    if (!extract_quoted_val(resp, "PUB", hex_pub, sizeof(hex_pub))) {
        const char *p = strstr(resp, "PUB=");
        if (p) {
            p += 4;
            sscanf(p, "%255s", hex_pub);
        }
    }

    size_t bin_len = 0;
    if (hex_to_bin(hex_pub, out_pubkey_65b, 65, &bin_len) != 0 || bin_len != 65) {
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

CK_RV at_sign(serial_transport_t *tr, uint8_t key_id, const uint8_t *hash_32b, uint8_t *out_sig_64b) {
    if (key_id < 1 || key_id > P11_MAX_KEYS || !hash_32b || !out_sig_64b) return CKR_ARGUMENTS_BAD;

    char hash_hex[65];
    bin_to_hex(hash_32b, 32, hash_hex, sizeof(hash_hex));

    char cmd[160];
    snprintf(cmd, sizeof(cmd), "AT+SIGN=%d,%s", key_id, hash_hex);

    char resp[256];
    int ret = serial_transaction(tr, cmd, resp, sizeof(resp), 3000);
    if (ret != 0) return at_error_to_ckr(ret);

    /* Response: +SIGN: <r_hex_32B><s_hex_32B> */
    const char *p = strstr(resp, "+SIGN:");
    if (!p) return CKR_DEVICE_ERROR;

    p += 6;
    while (*p == ' ') p++;

    char sig_hex[160] = {0};
    sscanf(p, "%159s", sig_hex);

    size_t bin_len = 0;
    if (hex_to_bin(sig_hex, out_sig_64b, 64, &bin_len) != 0 || bin_len != 64) {
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

CK_RV at_random(serial_transport_t *tr, size_t len, uint8_t *out_rand) {
    if (!out_rand || len == 0) return CKR_ARGUMENTS_BAD;

    size_t total_read = 0;
    while (total_read < len) {
        size_t chunk_len = (len - total_read > 64) ? 64 : (len - total_read);
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "AT+RANDOM=%zu", chunk_len);

        char resp[256];
        int ret = serial_transaction(tr, cmd, resp, sizeof(resp), 2000);
        if (ret != 0) return at_error_to_ckr(ret);

        const char *p = strstr(resp, "+RANDOM:");
        if (!p) return CKR_DEVICE_ERROR;

        p += 8;
        while (*p == ' ') p++;

        char rand_hex[256] = {0};
        sscanf(p, "%255s", rand_hex);

        size_t bin_len = 0;
        if (hex_to_bin(rand_hex, out_rand + total_read, chunk_len, &bin_len) != 0 || bin_len != chunk_len) {
            return CKR_DEVICE_ERROR;
        }
        total_read += bin_len;
    }

    return CKR_OK;
}
