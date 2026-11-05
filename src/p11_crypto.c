/*
 * PKCS#11 Cryptographic Operations (Keypair Gen, ECDSA Sign, Random)
 */

#include "nrf52840_p11_internal.h"
#include "transport/serial_transport.h"
#include "transport/at_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
    if (!pMechanism || !phPublicKey || !phPrivateKey) {
        return CKR_ARGUMENTS_BAD;
    }

    if (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN) {
        return CKR_MECHANISM_INVALID;
    }

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!ctx->user_logged_in && !ctx->so_logged_in) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    if (!(ctx->sessions[hSession - 1].flags & CKF_RW_SESSION)) {
        return CKR_SESSION_READ_ONLY;
    }

    /* Extract requested key ID and label if supplied */
    uint8_t target_key_id = 0;
    char label[33] = {0};

    for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
        if (pPublicKeyTemplate[i].type == CKA_ID && pPublicKeyTemplate[i].pValue) {
            if (pPublicKeyTemplate[i].ulValueLen == 1) {
                target_key_id = *(uint8_t *)pPublicKeyTemplate[i].pValue;
            } else if (pPublicKeyTemplate[i].ulValueLen == sizeof(CK_ULONG)) {
                target_key_id = (uint8_t)(*(CK_ULONG_PTR)pPublicKeyTemplate[i].pValue);
            }
        }
        if (pPublicKeyTemplate[i].type == CKA_LABEL && pPublicKeyTemplate[i].pValue) {
            size_t len = pPublicKeyTemplate[i].ulValueLen;
            if (len > 32) len = 32;
            memcpy(label, pPublicKeyTemplate[i].pValue, len);
            label[len] = '\0';
        }
    }

    for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
        if (target_key_id == 0 && pPrivateKeyTemplate[i].type == CKA_ID && pPrivateKeyTemplate[i].pValue) {
            if (pPrivateKeyTemplate[i].ulValueLen == 1) {
                target_key_id = *(uint8_t *)pPrivateKeyTemplate[i].pValue;
            } else if (pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_ULONG)) {
                target_key_id = (uint8_t)(*(CK_ULONG_PTR)pPrivateKeyTemplate[i].pValue);
            }
        }
        if (label[0] == '\0' && pPrivateKeyTemplate[i].type == CKA_LABEL && pPrivateKeyTemplate[i].pValue) {
            size_t len = pPrivateKeyTemplate[i].ulValueLen;
            if (len > 32) len = 32;
            memcpy(label, pPrivateKeyTemplate[i].pValue, len);
            label[len] = '\0';
        }
    }

    pthread_mutex_lock(&ctx->lock);

    /* If no slot specified, find first unused slot */
    if (target_key_id < 1 || target_key_id > P11_MAX_KEYS) {
        target_key_id = 0;
        for (int kid = 1; kid <= P11_MAX_KEYS; kid++) {
            if (!ctx->keys[kid].exists) {
                target_key_id = (uint8_t)kid;
                break;
            }
        }
    }

    if (target_key_id == 0) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_DEVICE_MEMORY;
    }

    uint8_t pubkey[65];
    CK_RV rv = at_keygen(ctx->transport, target_key_id, "EC_P256", pubkey);
    if (rv == CKR_USER_NOT_LOGGED_IN) {
        p11_session_notify_device_lock(ctx);
        pthread_mutex_unlock(&ctx->lock);
        return rv;
    }
    if (rv != CKR_OK) {
        pthread_mutex_unlock(&ctx->lock);
        return rv;
    }

    /* Cache new key entry */
    ctx->keys[target_key_id].key_id = target_key_id;
    ctx->keys[target_key_id].exists = true;
    ctx->keys[target_key_id].size_bits = 256;
    strncpy(ctx->keys[target_key_id].algo, "EC_P256", sizeof(ctx->keys[target_key_id].algo) - 1);
    if (label[0] != '\0') {
        strncpy(ctx->keys[target_key_id].label, label, sizeof(ctx->keys[target_key_id].label) - 1);
    } else {
        snprintf(ctx->keys[target_key_id].label, sizeof(ctx->keys[target_key_id].label), "Key-%d", target_key_id);
    }
    memcpy(ctx->keys[target_key_id].pubkey, pubkey, 65);
    ctx->keys[target_key_id].has_pubkey = true;

    *phPublicKey = P11_MAKE_PUB_HANDLE(target_key_id);
    *phPrivateKey = P11_MAKE_PRIV_HANDLE(target_key_id);

    /* Gracefully handle device self-locking post-keygen */
    if (ctx->transport && serial_is_open(ctx->transport)) {
        bool auth = false;
        int retries = 0, keycount = 0;
        if (at_get_status(ctx->transport, &auth, &retries, &keycount, NULL, NULL, 0) == CKR_OK && !auth) {
            p11_session_notify_device_lock(ctx);
        }
    }

    pthread_mutex_unlock(&ctx->lock);
    p11_log("C_GenerateKeyPair created key_id=%d pub_handle=%lu priv_handle=%lu",
            target_key_id, (unsigned long)*phPublicKey, (unsigned long)*phPrivateKey);
    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!pMechanism) return CKR_ARGUMENTS_BAD;

    if (pMechanism->mechanism != CKM_ECDSA && pMechanism->mechanism != CKM_ECDSA_SHA256) {
        return CKR_MECHANISM_INVALID;
    }

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!P11_HANDLE_IS_VALID(hKey) || !P11_HANDLE_IS_PRIVATE(hKey)) {
        return CKR_KEY_HANDLE_INVALID;
    }

    if (!ctx->user_logged_in) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    uint8_t key_id = P11_HANDLE_TO_KEY_ID(hKey);

    pthread_mutex_lock(&ctx->lock);

    if (!ctx->keys[key_id].exists) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_KEY_HANDLE_INVALID;
    }

    p11_session_t *s = &ctx->sessions[hSession - 1];
    s->sign_ctx.active = true;
    s->sign_ctx.key_handle = hKey;
    s->sign_ctx.mechanism = pMechanism->mechanism;

    pthread_mutex_unlock(&ctx->lock);
    p11_log("C_SignInit handle=%lu key=%lu", (unsigned long)hSession, (unsigned long)hKey);
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (!pulSignatureLen) return CKR_ARGUMENTS_BAD;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!ctx->user_logged_in) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    p11_session_t *s = &ctx->sessions[hSession - 1];
    if (!s->sign_ctx.active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    /* P-256 raw signature length (R || S) = 32 + 32 = 64 bytes */
    const CK_ULONG sig_len = 64;

    if (!pSignature) {
        *pulSignatureLen = sig_len;
        return CKR_OK;
    }

    if (*pulSignatureLen < sig_len) {
        *pulSignatureLen = sig_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    if (!pData || ulDataLen != 32) {
        return CKR_DATA_LEN_RANGE;
    }

    uint8_t key_id = P11_HANDLE_TO_KEY_ID(s->sign_ctx.key_handle);

    pthread_mutex_lock(&ctx->lock);

    uint8_t sig_raw[64];
    CK_RV rv = at_sign(ctx->transport, key_id, pData, sig_raw);

    /* Operation completed: reset sign state */
    s->sign_ctx.active = false;

    if (rv == CKR_USER_NOT_LOGGED_IN) {
        p11_session_notify_device_lock(ctx);
    } else if (rv == CKR_OK) {
        memcpy(pSignature, sig_raw, sig_len);
        *pulSignatureLen = sig_len;

        /* Gracefully handle device self-locking post-signing */
        if (ctx->transport && serial_is_open(ctx->transport)) {
            bool auth = false;
            int retries = 0, keycount = 0;
            if (at_get_status(ctx->transport, &auth, &retries, &keycount, NULL, NULL, 0) == CKR_OK && !auth) {
                p11_session_notify_device_lock(ctx);
            }
        }
    }

    pthread_mutex_unlock(&ctx->lock);
    p11_log("C_Sign rv=%lu", (unsigned long)rv);
    return rv;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen) {
    if (!RandomData || ulRandomLen == 0) return CKR_ARGUMENTS_BAD;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_RV rv = p11_ensure_transport_open(ctx);
    if (rv != CKR_OK) return rv;

    return at_random(ctx->transport, (size_t)ulRandomLen, RandomData);
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    (void)hSession; (void)pSeed; (void)ulSeedLen;
    return CKR_RANDOM_SEED_NOT_SUPPORTED;
}
