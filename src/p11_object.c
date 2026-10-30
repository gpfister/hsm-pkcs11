/*
 * PKCS#11 Object Management
 */

#include "nrf52840_p11_internal.h"
#include "transport/serial_transport.h"
#include "transport/at_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool match_attribute(p11_key_entry_t *key, bool is_priv, CK_ATTRIBUTE_PTR attr) {
    if (!attr) return true;

    switch (attr->type) {
        case CKA_CLASS: {
            if (attr->ulValueLen != sizeof(CK_OBJECT_CLASS) || !attr->pValue) return false;
            CK_OBJECT_CLASS cls = *(CK_OBJECT_CLASS_PTR)attr->pValue;
            if (is_priv && cls != CKO_PRIVATE_KEY) return false;
            if (!is_priv && cls != CKO_PUBLIC_KEY) return false;
            return true;
        }
        case CKA_KEY_TYPE: {
            if (attr->ulValueLen != sizeof(CK_KEY_TYPE) || !attr->pValue) return false;
            CK_KEY_TYPE kt = *(CK_KEY_TYPE_PTR)attr->pValue;
            return (kt == CKK_EC);
        }
        case CKA_TOKEN: {
            if (attr->ulValueLen != sizeof(CK_BBOOL) || !attr->pValue) return false;
            return (*(CK_BBOOL *)attr->pValue == CK_TRUE);
        }
        case CKA_PRIVATE: {
            if (attr->ulValueLen != sizeof(CK_BBOOL) || !attr->pValue) return false;
            CK_BBOOL priv = *(CK_BBOOL *)attr->pValue;
            return (priv == (is_priv ? CK_TRUE : CK_FALSE));
        }
        case CKA_LABEL: {
            if (!attr->pValue) return true;
            size_t klen = strlen(key->label);
            if (attr->ulValueLen != klen) return false;
            return (memcmp(key->label, attr->pValue, klen) == 0);
        }
        case CKA_ID: {
            if (!attr->pValue) return true;
            if (attr->ulValueLen == 1) {
                return (*(uint8_t *)attr->pValue == key->key_id);
            } else if (attr->ulValueLen == sizeof(CK_ULONG)) {
                return (*(CK_ULONG_PTR)attr->pValue == (CK_ULONG)key->key_id);
            }
            return false;
        }
        default:
            /* Ignore unrecognized filter attributes */
            return true;
    }
}

static bool match_template(p11_key_entry_t *key, bool is_priv, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (!match_attribute(key, is_priv, &pTemplate[i])) {
            return false;
        }
    }
    return true;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    p11_session_t *s = &ctx->sessions[hSession - 1];
    if (s->search_ctx.active) {
        return CKR_OPERATION_ACTIVE;
    }

    p11_refresh_keys(ctx);

    pthread_mutex_lock(&ctx->lock);

    s->search_ctx.match_count = 0;
    s->search_ctx.current_idx = 0;

    for (int kid = 1; kid <= P11_MAX_KEYS; kid++) {
        if (!ctx->keys[kid].exists) continue;

        /* Check public key handle */
        if (match_template(&ctx->keys[kid], false, pTemplate, ulCount)) {
            if (s->search_ctx.match_count < P11_MAX_MATCHES) {
                s->search_ctx.matches[s->search_ctx.match_count++] = P11_MAKE_PUB_HANDLE(kid);
            }
        }

        /* Check private key handle */
        if (match_template(&ctx->keys[kid], true, pTemplate, ulCount)) {
            if (s->search_ctx.match_count < P11_MAX_MATCHES) {
                s->search_ctx.matches[s->search_ctx.match_count++] = P11_MAKE_PRIV_HANDLE(kid);
            }
        }
    }

    s->search_ctx.active = true;
    pthread_mutex_unlock(&ctx->lock);

    p11_log("C_FindObjectsInit matched %lu objects", (unsigned long)s->search_ctx.match_count);
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    if (!phObject || !pulObjectCount) return CKR_ARGUMENTS_BAD;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    p11_session_t *s = &ctx->sessions[hSession - 1];
    if (!s->search_ctx.active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    pthread_mutex_lock(&ctx->lock);

    CK_ULONG returned = 0;
    while (s->search_ctx.current_idx < s->search_ctx.match_count && returned < ulMaxObjectCount) {
        phObject[returned++] = s->search_ctx.matches[s->search_ctx.current_idx++];
    }

    *pulObjectCount = returned;
    pthread_mutex_unlock(&ctx->lock);

    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    p11_session_t *s = &ctx->sessions[hSession - 1];
    if (!s->search_ctx.active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    pthread_mutex_lock(&ctx->lock);
    s->search_ctx.active = false;
    pthread_mutex_unlock(&ctx->lock);

    return CKR_OK;
}

static CK_RV fill_attribute(CK_ATTRIBUTE_PTR attr, const void *data, CK_ULONG len) {
    if (!attr->pValue) {
        attr->ulValueLen = len;
        return CKR_OK;
    }
    if (attr->ulValueLen < len) {
        attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(attr->pValue, data, len);
    attr->ulValueLen = len;
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    if (!pTemplate && ulCount > 0) return CKR_ARGUMENTS_BAD;

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (hSession == 0 || hSession > P11_MAX_SESSIONS || !ctx->sessions[hSession - 1].in_use) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!P11_HANDLE_IS_VALID(hObject)) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    uint8_t key_id = P11_HANDLE_TO_KEY_ID(hObject);
    bool is_priv = P11_HANDLE_IS_PRIVATE(hObject);

    pthread_mutex_lock(&ctx->lock);

    if (!ctx->keys[key_id].exists) {
        pthread_mutex_unlock(&ctx->lock);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    /* Ensure public key is fetched */
    if (!ctx->keys[key_id].has_pubkey && !is_priv) {
        if (at_pubkey(ctx->transport, key_id, ctx->keys[key_id].pubkey) == CKR_OK) {
            ctx->keys[key_id].has_pubkey = true;
        }
    }

    CK_RV overall_rv = CKR_OK;
    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE_PTR a = &pTemplate[i];
        CK_RV attr_rv = CKR_OK;

        switch (a->type) {
            case CKA_CLASS: {
                CK_OBJECT_CLASS cls = is_priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
                attr_rv = fill_attribute(a, &cls, sizeof(cls));
                break;
            }
            case CKA_KEY_TYPE: {
                CK_KEY_TYPE kt = CKK_EC;
                attr_rv = fill_attribute(a, &kt, sizeof(kt));
                break;
            }
            case CKA_TOKEN: {
                attr_rv = fill_attribute(a, &b_true, sizeof(b_true));
                break;
            }
            case CKA_PRIVATE: {
                CK_BBOOL priv = is_priv ? CK_TRUE : CK_FALSE;
                attr_rv = fill_attribute(a, &priv, sizeof(priv));
                break;
            }
            case CKA_LABEL: {
                const char *lbl = ctx->keys[key_id].label[0] ? ctx->keys[key_id].label : "nRF52840 EC Key";
                attr_rv = fill_attribute(a, lbl, (CK_ULONG)strlen(lbl));
                break;
            }
            case CKA_ID: {
                uint8_t id_byte = key_id;
                attr_rv = fill_attribute(a, &id_byte, sizeof(id_byte));
                break;
            }
            case CKA_EC_PARAMS: {
                attr_rv = fill_attribute(a, P11_EC_P256_OID, P11_EC_P256_OID_LEN);
                break;
            }
            case CKA_EC_POINT: {
                if (is_priv) {
                    attr_rv = CKR_ATTRIBUTE_TYPE_INVALID;
                } else {
                    /* DER OCTET STRING containing the 65-byte uncompressed public key:
                     * 0x04, 0x41, <65 bytes pubkey starting with 0x04>
                     */
                    uint8_t ec_point_der[67];
                    ec_point_der[0] = 0x04;
                    ec_point_der[1] = 0x41;
                    memcpy(ec_point_der + 2, ctx->keys[key_id].pubkey, 65);
                    attr_rv = fill_attribute(a, ec_point_der, sizeof(ec_point_der));
                }
                break;
            }
            case CKA_SIGN: {
                CK_BBOOL sign = is_priv ? CK_TRUE : CK_FALSE;
                attr_rv = fill_attribute(a, &sign, sizeof(sign));
                break;
            }
            case CKA_VERIFY: {
                CK_BBOOL verify = is_priv ? CK_FALSE : CK_TRUE;
                attr_rv = fill_attribute(a, &verify, sizeof(verify));
                break;
            }
            case CKA_SENSITIVE:
            case CKA_ALWAYS_SENSITIVE: {
                CK_BBOOL sens = is_priv ? CK_TRUE : CK_FALSE;
                attr_rv = fill_attribute(a, &sens, sizeof(sens));
                break;
            }
            case CKA_EXTRACTABLE: {
                attr_rv = fill_attribute(a, &b_false, sizeof(b_false));
                break;
            }
            case CKA_NEVER_EXTRACTABLE:
            case CKA_LOCAL: {
                attr_rv = fill_attribute(a, &b_true, sizeof(b_true));
                break;
            }
            default:
                attr_rv = CKR_ATTRIBUTE_TYPE_INVALID;
                break;
        }

        if (attr_rv != CKR_OK && overall_rv == CKR_OK) {
            overall_rv = attr_rv;
        }
    }

    pthread_mutex_unlock(&ctx->lock);
    return overall_rv;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    (void)hSession;
    if (!P11_HANDLE_IS_VALID(hObject)) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    return CKR_ACTION_PROHIBITED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
    (void)hSession; (void)pTemplate; (void)ulCount; (void)phObject;
    return CKR_ACTION_PROHIBITED;
}
