/*
 * PKCS#11 Slot and Token Management
 */

#include "nrf52840_p11_internal.h"
#include "transport/serial_transport.h"
#include "transport/at_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void pad_string(CK_UTF8CHAR_PTR dst, size_t dst_len, const char *src) {
    size_t src_len = src ? strlen(src) : 0;
    if (src_len > dst_len) src_len = dst_len;

    if (src_len > 0) {
        memcpy(dst, src, src_len);
    }
    if (dst_len > src_len) {
        memset(dst + src_len, ' ', dst_len - src_len);
    }
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    if (!pulCount) return CKR_ARGUMENTS_BAD;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_ensure_transport_open(ctx);

    CK_ULONG count = 1;
    if (tokenPresent && !ctx->token_present) {
        count = 0;
    }

    if (!pSlotList) {
        *pulCount = count;
        return CKR_OK;
    }

    if (*pulCount < count) {
        *pulCount = count;
        return CKR_BUFFER_TOO_SMALL;
    }

    if (count > 0) {
        pSlotList[0] = P11_SLOT_ID;
    }
    *pulCount = count;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    if (slotID != P11_SLOT_ID) return CKR_SLOT_ID_INVALID;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_ensure_transport_open(ctx);

    pad_string(pInfo->slotDescription, sizeof(pInfo->slotDescription), "nRF52840 HSM Dongle (PCA10059)");
    pad_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), P11_MANUFACTURER_ID);

    pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    if (ctx->token_present) {
        pInfo->flags |= CKF_TOKEN_PRESENT;
    }

    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    if (slotID != P11_SLOT_ID) return CKR_SLOT_ID_INVALID;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_ensure_transport_open(ctx);
    if (!ctx->token_present) return CKR_TOKEN_NOT_PRESENT;

    pad_string(pInfo->label, sizeof(pInfo->label), P11_TOKEN_LABEL);
    pad_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), P11_MANUFACTURER_ID);
    pad_string(pInfo->model, sizeof(pInfo->model), P11_MODEL_NAME);

    const char *serial = ctx->uid_hex[0] ? ctx->uid_hex : "0102030405060708";
    pad_string((CK_UTF8CHAR_PTR)pInfo->serialNumber, sizeof(pInfo->serialNumber), serial);

    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
    if (ctx->pin_retries == 0) {
        pInfo->flags |= CKF_USER_PIN_LOCKED;
    } else if (ctx->pin_retries == 1) {
        pInfo->flags |= (CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_COUNT_LOW);
    } else if (ctx->pin_retries <= 2) {
        pInfo->flags |= CKF_USER_PIN_COUNT_LOW;
    }

    CK_ULONG session_count = 0;
    CK_ULONG rw_session_count = 0;
    for (int i = 0; i < P11_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].in_use) {
            session_count++;
            if (ctx->sessions[i].flags & CKF_RW_SESSION) {
                rw_session_count++;
            }
        }
    }

    pInfo->ulMaxSessionCount = P11_MAX_SESSIONS;
    pInfo->ulSessionCount = session_count;
    pInfo->ulMaxRwSessionCount = P11_MAX_SESSIONS;
    pInfo->ulRwSessionCount = rw_session_count;
    pInfo->ulMaxPinLen = 16;
    pInfo->ulMinPinLen = 4;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    memcpy(pInfo->utcTime, "2026103000000000", 16);

    return CKR_OK;
}

static const CK_MECHANISM_TYPE s_supported_mechanisms[] = {
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
};
#define NUM_SUPPORTED_MECHANISMS (sizeof(s_supported_mechanisms) / sizeof(s_supported_mechanisms[0]))

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    if (slotID != P11_SLOT_ID) return CKR_SLOT_ID_INVALID;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!pMechanismList) {
        *pulCount = NUM_SUPPORTED_MECHANISMS;
        return CKR_OK;
    }

    if (*pulCount < NUM_SUPPORTED_MECHANISMS) {
        *pulCount = NUM_SUPPORTED_MECHANISMS;
        return CKR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < NUM_SUPPORTED_MECHANISMS; i++) {
        pMechanismList[i] = s_supported_mechanisms[i];
    }
    *pulCount = NUM_SUPPORTED_MECHANISMS;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    if (slotID != P11_SLOT_ID) return CKR_SLOT_ID_INVALID;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    switch (type) {
        case CKM_EC_KEY_PAIR_GEN:
            pInfo->ulMinKeySize = 256;
            pInfo->ulMaxKeySize = 256;
            pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
            return CKR_OK;

        case CKM_ECDSA:
            pInfo->ulMinKeySize = 256;
            pInfo->ulMaxKeySize = 256;
            pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
            return CKR_OK;

        case CKM_ECDSA_SHA256:
            pInfo->ulMinKeySize = 256;
            pInfo->ulMaxKeySize = 256;
            pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
            return CKR_OK;

        default:
            return CKR_MECHANISM_INVALID;
    }
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
    (void)pPin; (void)ulPinLen; (void)pLabel;
    if (slotID != P11_SLOT_ID) return CKR_SLOT_ID_INVALID;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_RV rv = p11_ensure_transport_open(ctx);
    if (rv != CKR_OK) return rv;

    pthread_mutex_lock(&ctx->lock);

    /* C_InitToken can only be called when no user is logged in (PKCS#11 v2.40) */
    if (ctx->user_logged_in || ctx->so_logged_in) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    rv = at_reset(ctx->transport);
    if (rv == CKR_OK) {
        p11_session_notify_device_lock(ctx);
        ctx->pin_retries = 3;
    }

    pthread_mutex_unlock(&ctx->lock);

    if (rv == CKR_OK) {
        p11_refresh_keys(ctx);
    }
    return rv;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    if (!pPin) return CKR_ARGUMENTS_BAD;
    if (ulPinLen < 4 || ulPinLen > 16) return CKR_PIN_LEN_RANGE;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pthread_mutex_lock(&ctx->lock);

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* C_InitPIN can only be called in CKS_RW_SO_FUNCTIONS state (PKCS#11 v2.40) */
    if (!ctx->so_logged_in || ctx->sessions[hSession - 1].state != CKS_RW_SO_FUNCTIONS) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_USER_NOT_LOGGED_IN;
    }

    pthread_mutex_unlock(&ctx->lock);
    return CKR_OK;
}
