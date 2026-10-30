/*
 * PKCS#11 General Purpose Functions & Entrypoints
 */

#include "nrf52840_p11_internal.h"
#include "transport/serial_transport.h"
#include "transport/at_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static p11_global_ctx_t g_p11_ctx = {
    .initialized = false,
    .user_logged_in = false,
    .so_logged_in = false,
    .pin_retries = 3,
    .token_present = false,
};

static serial_transport_t g_serial_tr;

p11_global_ctx_t *p11_get_ctx(void) {
    return &g_p11_ctx;
}

void p11_log(const char *fmt, ...) {
    const char *env = getenv("NRF52840_HSM_DEBUG");
    if (!env || (strcmp(env, "1") != 0 && strcasecmp(env, "true") != 0 && strcasecmp(env, "trace") != 0)) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[P11 LIB] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

CK_RV p11_ensure_transport_open(p11_global_ctx_t *ctx) {
    if (!ctx) return CKR_GENERAL_ERROR;

    if (serial_is_open(ctx->transport)) {
        return CKR_OK;
    }

    if (serial_auto_open(ctx->transport) != 0) {
        ctx->token_present = false;
        return CKR_DEVICE_ERROR;
    }

    /* Query device information */
    ctx->token_present = true;
    at_get_info(ctx->transport,
                ctx->fw_version, sizeof(ctx->fw_version),
                ctx->hw_model, sizeof(ctx->hw_model),
                ctx->uid_hex, sizeof(ctx->uid_hex),
                ctx->boot_stage, sizeof(ctx->boot_stage));

    bool auth = false;
    int retries = 3;
    int keycount = 0;
    if (at_get_status(ctx->transport, &auth, &retries, &keycount) == CKR_OK) {
        ctx->user_logged_in = auth;
        ctx->pin_retries = retries;
    }

    return CKR_OK;
}

CK_RV p11_refresh_keys(p11_global_ctx_t *ctx) {
    if (!ctx || !ctx->initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;

    CK_RV rv = p11_ensure_transport_open(ctx);
    if (rv != CKR_OK) return rv;

    p11_key_entry_t raw_keys[P11_MAX_KEYS];
    size_t key_count = 0;
    rv = at_get_slots(ctx->transport, raw_keys, P11_MAX_KEYS, &key_count);
    if (rv != CKR_OK) return rv;

    /* Clear existing key cache */
    for (int i = 1; i <= P11_MAX_KEYS; i++) {
        ctx->keys[i].exists = false;
    }

    for (size_t i = 0; i < key_count; i++) {
        uint8_t kid = raw_keys[i].key_id;
        if (kid >= 1 && kid <= P11_MAX_KEYS) {
            ctx->keys[kid] = raw_keys[i];
            /* Fetch public key for this slot if not yet cached */
            if (!ctx->keys[kid].has_pubkey) {
                if (at_pubkey(ctx->transport, kid, ctx->keys[kid].pubkey) == CKR_OK) {
                    ctx->keys[kid].has_pubkey = true;
                }
            }
        }
    }

    return CKR_OK;
}


static CK_RV C_SetPIN_stub(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
    (void)hSession; (void)pOldPin; (void)ulOldLen; (void)pNewPin; (void)ulNewLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_GetOperationState_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
    (void)hSession; (void)pOperationState; (void)pulOperationStateLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SetOperationState_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
    (void)hSession; (void)pOperationState; (void)ulOperationStateLen; (void)hEncryptionKey; (void)hAuthenticationKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_CopyObject_stub(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount; (void)phNewObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_GetObjectSize_stub(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
    (void)hSession; (void)hObject; (void)pulSize;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SetAttributeValue_stub(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_EncryptInit_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_Encrypt_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pEncryptedData; (void)pulEncryptedDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_EncryptUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_EncryptFinal_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
    (void)hSession; (void)pLastEncryptedPart; (void)pulLastEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptInit_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_Decrypt_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    (void)hSession; (void)pEncryptedData; (void)ulEncryptedDataLen; (void)pData; (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pDecryptedPart; (void)pulDecryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptFinal_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
    (void)hSession; (void)pLastPart; (void)pulLastPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DigestInit_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
    (void)hSession; (void)pMechanism;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_Digest_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pDigest; (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DigestUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DigestKey_stub(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DigestFinal_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    (void)hSession; (void)pDigest; (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignFinal_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    (void)hSession; (void)pSignature; (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignRecoverInit_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignRecover_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_VerifyInit_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_Verify_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_VerifyUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_VerifyFinal_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    (void)hSession; (void)pSignature; (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_VerifyRecoverInit_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_VerifyRecover_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    (void)hSession; (void)pSignature; (void)ulSignatureLen; (void)pData; (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DigestEncryptUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptDigestUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_SignEncryptUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DecryptVerifyUpdate_stub(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_GenerateKey_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)pTemplate; (void)ulCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_WrapKey_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
    (void)hSession; (void)pMechanism; (void)hWrappingKey; (void)hKey; (void)pWrappedKey; (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_UnwrapKey_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)hUnwrappingKey; (void)pWrappedKey; (void)ulWrappedKeyLen; (void)pTemplate; (void)ulAttributeCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_DeriveKey_stub(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)hBaseKey; (void)pTemplate; (void)ulAttributeCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_GetFunctionStatus_stub(CK_SESSION_HANDLE hSession) {
    (void)hSession;
    return CKR_FUNCTION_NOT_PARALLEL;
}

static CK_RV C_CancelFunction_stub(CK_SESSION_HANDLE hSession) {
    (void)hSession;
    return CKR_FUNCTION_NOT_PARALLEL;
}

static CK_RV C_WaitForSlotEvent_stub(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
    (void)flags; (void)pSlot; (void)pReserved;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_FUNCTION_LIST g_function_list = {
    .version = { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN_stub,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState_stub,
    .C_SetOperationState = C_SetOperationState_stub,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject_stub,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize_stub,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue_stub,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit_stub,
    .C_Encrypt = C_Encrypt_stub,
    .C_EncryptUpdate = C_EncryptUpdate_stub,
    .C_EncryptFinal = C_EncryptFinal_stub,
    .C_DecryptInit = C_DecryptInit_stub,
    .C_Decrypt = C_Decrypt_stub,
    .C_DecryptUpdate = C_DecryptUpdate_stub,
    .C_DecryptFinal = C_DecryptFinal_stub,
    .C_DigestInit = C_DigestInit_stub,
    .C_Digest = C_Digest_stub,
    .C_DigestUpdate = C_DigestUpdate_stub,
    .C_DigestKey = C_DigestKey_stub,
    .C_DigestFinal = C_DigestFinal_stub,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate_stub,
    .C_SignFinal = C_SignFinal_stub,
    .C_SignRecoverInit = C_SignRecoverInit_stub,
    .C_SignRecover = C_SignRecover_stub,
    .C_VerifyInit = C_VerifyInit_stub,
    .C_Verify = C_Verify_stub,
    .C_VerifyUpdate = C_VerifyUpdate_stub,
    .C_VerifyFinal = C_VerifyFinal_stub,
    .C_VerifyRecoverInit = C_VerifyRecoverInit_stub,
    .C_VerifyRecover = C_VerifyRecover_stub,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate_stub,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate_stub,
    .C_SignEncryptUpdate = C_SignEncryptUpdate_stub,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate_stub,
    .C_GenerateKey = C_GenerateKey_stub,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey_stub,
    .C_UnwrapKey = C_UnwrapKey_stub,
    .C_DeriveKey = C_DeriveKey_stub,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus_stub,
    .C_CancelFunction = C_CancelFunction_stub,
    .C_WaitForSlotEvent = C_WaitForSlotEvent_stub,
};

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    p11_global_ctx_t *ctx = p11_get_ctx();

    if (ctx->initialized) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    if (pInitArgs != NULL) {
        CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
        if (args->pReserved != NULL) {
            return CKR_ARGUMENTS_BAD;
        }
    }

    pthread_mutex_init(&ctx->lock, NULL);
    ctx->transport = &g_serial_tr;
    serial_init(ctx->transport);

    for (int i = 0; i < P11_MAX_SESSIONS; i++) {
        ctx->sessions[i].in_use = false;
        ctx->sessions[i].handle = (CK_SESSION_HANDLE)(i + 1);
    }
    for (int i = 1; i <= P11_MAX_KEYS; i++) {
        ctx->keys[i].exists = false;
        ctx->keys[i].has_pubkey = false;
    }

    /* Auto-connect if port available (non-fatal if device not attached yet) */
    p11_ensure_transport_open(ctx);

    ctx->initialized = true;
    p11_log("C_Initialize successful");
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    if (pReserved != NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pthread_mutex_lock(&ctx->lock);

    for (int i = 0; i < P11_MAX_SESSIONS; i++) {
        ctx->sessions[i].in_use = false;
    }

    if (ctx->transport) {
        serial_close(ctx->transport);
    }

    ctx->initialized = false;
    ctx->token_present = false;
    ctx->user_logged_in = false;
    ctx->so_logged_in = false;

    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);

    p11_log("C_Finalize successful");
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }

    p11_global_ctx_t *ctx = p11_get_ctx();
    if (!ctx->initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
    pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;

    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, P11_MANUFACTURER_ID, strlen(P11_MANUFACTURER_ID));

    pInfo->flags = 0;

    const char *desc = "nRF52840 PKCS#11 Library";
    memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
    memcpy(pInfo->libraryDescription, desc, strlen(desc));

    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;

    return CKR_OK;
}

__attribute__((visibility("default")))
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (!ppFunctionList) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &g_function_list;
    return CKR_OK;
}
