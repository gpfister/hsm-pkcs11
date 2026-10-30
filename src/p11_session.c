/*
 * PKCS#11 Session Management
 */

#include "nrf52840_p11_internal.h"
#include "transport/serial_transport.h"
#include "transport/at_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static p11_session_t *get_session(p11_global_ctx_t *ctx, CK_SESSION_HANDLE hSession) {
    if (!ctx || hSession == 0 || hSession > P11_MAX_SESSIONS) {
        return NULL;
    }
    p11_session_t *s = &ctx->sessions[hSession - 1];
    return s->in_use ? s : NULL;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_RV (*Notify)(CK_SESSION_HANDLE, CK_FLAGS, CK_VOID_PTR),
                    CK_SESSION_HANDLE_PTR phSession) {
    (void)pApplication;
    (void)Notify;

    if (!phSession) return CKR_ARGUMENTS_BAD;
    if (slotID != P11_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!(flags & CKF_SERIAL_SESSION)) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_RV rv = p11_ensure_transport_open(ctx);
    if (rv != CKR_OK) return rv;

    pthread_mutex_lock(&ctx->lock);

    p11_session_t *free_session = NULL;
    for (int i = 0; i < P11_MAX_SESSIONS; i++) {
        if (!ctx->sessions[i].in_use) {
            free_session = &ctx->sessions[i];
            break;
        }
    }

    if (!free_session) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_SESSION_COUNT;
    }

    free_session->in_use = true;
    free_session->slot_id = slotID;
    free_session->flags = flags;
    free_session->search_ctx.active = false;
    free_session->sign_ctx.active = false;

    if (ctx->user_logged_in) {
        free_session->state = (flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    } else {
        free_session->state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    }

    *phSession = free_session->handle;

    pthread_mutex_unlock(&ctx->lock);
    p11_log("C_OpenSession handle=%lu state=%lu", (unsigned long)*phSession, (unsigned long)free_session->state);
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pthread_mutex_lock(&ctx->lock);

    p11_session_t *s = get_session(ctx, hSession);
    if (!s) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_SESSION_HANDLE_INVALID;
    }

    s->in_use = false;
    s->search_ctx.active = false;
    s->sign_ctx.active = false;

    pthread_mutex_unlock(&ctx->lock);
    p11_log("C_CloseSession handle=%lu", (unsigned long)hSession);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    if (slotID != P11_SLOT_ID) return CKR_SLOT_ID_INVALID;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pthread_mutex_lock(&ctx->lock);

    for (int i = 0; i < P11_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].in_use && ctx->sessions[i].slot_id == slotID) {
            ctx->sessions[i].in_use = false;
            ctx->sessions[i].search_ctx.active = false;
            ctx->sessions[i].sign_ctx.active = false;
        }
    }

    pthread_mutex_unlock(&ctx->lock);
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pthread_mutex_lock(&ctx->lock);

    p11_session_t *s = get_session(ctx, hSession);
    if (!s) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_SESSION_HANDLE_INVALID;
    }

    pInfo->slotID = s->slot_id;
    pInfo->state = s->state;
    pInfo->flags = s->flags;
    pInfo->ulDeviceError = 0;

    pthread_mutex_unlock(&ctx->lock);
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    if (!pPin) return CKR_ARGUMENTS_BAD;
    if (ulPinLen < 4 || ulPinLen > 16) return CKR_PIN_LEN_RANGE;
    if (userType != CKU_USER && userType != CKU_SO) return CKR_USER_TYPE_INVALID;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pthread_mutex_lock(&ctx->lock);

    p11_session_t *s = get_session(ctx, hSession);
    if (!s) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (ctx->user_logged_in) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    char pin_str[32];
    memcpy(pin_str, pPin, ulPinLen);
    pin_str[ulPinLen] = '\0';

    CK_RV rv = at_auth(ctx->transport, pin_str);
    if (rv == CKR_OK) {
        ctx->user_logged_in = true;
        ctx->pin_retries = 3;

        for (int i = 0; i < P11_MAX_SESSIONS; i++) {
            if (ctx->sessions[i].in_use) {
                ctx->sessions[i].state = (ctx->sessions[i].flags & CKF_RW_SESSION)
                    ? CKS_RW_USER_FUNCTIONS
                    : CKS_RO_USER_FUNCTIONS;
            }
        }
        pthread_mutex_unlock(&ctx->lock);

        /* Refresh cached keys on token */
        p11_refresh_keys(ctx);
        p11_log("C_Login successful");
        return CKR_OK;
    }

    if (rv == CKR_PIN_INCORRECT && ctx->pin_retries > 0) {
        ctx->pin_retries--;
    } else if (rv == CKR_PIN_LOCKED) {
        ctx->pin_retries = 0;
    }

    pthread_mutex_unlock(&ctx->lock);
    p11_log("C_Login failed with code %lu", (unsigned long)rv);
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    pthread_mutex_lock(&ctx->lock);

    p11_session_t *s = get_session(ctx, hSession);
    if (!s) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!ctx->user_logged_in) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_USER_NOT_LOGGED_IN;
    }

    CK_RV rv = at_lock(ctx->transport);
    ctx->user_logged_in = false;

    for (int i = 0; i < P11_MAX_SESSIONS; i++) {
        if (ctx->sessions[i].in_use) {
            ctx->sessions[i].state = (ctx->sessions[i].flags & CKF_RW_SESSION)
                ? CKS_RW_PUBLIC_SESSION
                : CKS_RO_PUBLIC_SESSION;
        }
    }

    pthread_mutex_unlock(&ctx->lock);
    p11_log("C_Logout completed");
    return rv;
}
