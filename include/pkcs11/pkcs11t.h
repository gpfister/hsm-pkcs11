/*
 * PKCS #11 v2.40 Data Types and Constants
 * OASIS Standard Cryptoki Specification
 */

#ifndef _PKCS11T_H_
#define _PKCS11T_H_ 1

#include <stddef.h>
#include <stdint.h>

#define CRYPTOKI_VERSION_MAJOR 2
#define CRYPTOKI_VERSION_MINOR 40
#define CRYPTOKI_VERSION_AMENDMENT 0

/* Primitive Types */
typedef unsigned char     CK_BYTE;
typedef char              CK_CHAR;
typedef unsigned char     CK_UTF8CHAR;
typedef unsigned char     CK_BBOOL;
typedef unsigned long int CK_ULONG;
typedef long int          CK_LONG;
typedef CK_ULONG          CK_FLAGS;

typedef void *            CK_VOID_PTR;
typedef CK_BYTE *         CK_BYTE_PTR;
typedef CK_CHAR *         CK_CHAR_PTR;
typedef CK_UTF8CHAR *     CK_UTF8CHAR_PTR;
typedef CK_ULONG *        CK_ULONG_PTR;
typedef CK_VOID_PTR *     CK_VOID_PTR_PTR;

#define CK_TRUE  1
#define CK_FALSE 0

#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0UL
#define CK_INVALID_HANDLE          0UL

/* Version Structure */
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;
typedef CK_VERSION * CK_VERSION_PTR;

/* Cryptoki Info */
typedef struct CK_INFO {
    CK_VERSION    cryptokiVersion;
    CK_UTF8CHAR   manufacturerID[32];
    CK_FLAGS      flags;
    CK_UTF8CHAR   libraryDescription[32];
    CK_VERSION    libraryVersion;
} CK_INFO;
typedef CK_INFO * CK_INFO_PTR;

/* Slot ID and Slot Info */
typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID * CK_SLOT_ID_PTR;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS    flags;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO * CK_SLOT_INFO_PTR;

/* Slot Flags */
#define CKF_TOKEN_PRESENT     0x00000001UL
#define CKF_REMOVABLE_DEVICE  0x00000002UL
#define CKF_HW_SLOT           0x00000004UL

/* Token Info */
typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR     serialNumber[16];
    CK_FLAGS    flags;
    CK_ULONG    ulMaxSessionCount;
    CK_ULONG    ulSessionCount;
    CK_ULONG    ulMaxRwSessionCount;
    CK_ULONG    ulRwSessionCount;
    CK_ULONG    ulMaxPinLen;
    CK_ULONG    ulMinPinLen;
    CK_ULONG    ulTotalPublicMemory;
    CK_ULONG    ulFreePublicMemory;
    CK_ULONG    ulTotalPrivateMemory;
    CK_ULONG    ulFreePrivateMemory;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
    CK_CHAR     utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO * CK_TOKEN_INFO_PTR;

/* Token Flags */
#define CKF_RNG                     0x00000001UL
#define CKF_WRITE_PROTECTED         0x00000002UL
#define CKF_LOGIN_REQUIRED          0x00000004UL
#define CKF_USER_PIN_INITIALIZED    0x00000008UL
#define CKF_RESTORE_KEY_NOT_NEEDED  0x00000020UL
#define CKF_CLOCK_ON_TOKEN          0x00000040UL
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100UL
#define CKF_DUAL_CRYPTO_OPERATIONS  0x00000200UL
#define CKF_TOKEN_INITIALIZED       0x00000400UL
#define CKF_SECONDARY_AUTHENTICATION 0x00000800UL
#define CKF_USER_PIN_COUNT_LOW      0x00010000UL
#define CKF_USER_PIN_FINAL_TRY      0x00020000UL
#define CKF_USER_PIN_LOCKED         0x00040000UL
#define CKF_USER_PIN_TO_BE_CHANGED  0x00080000UL
#define CKF_SO_PIN_COUNT_LOW        0x00100000UL
#define CKF_SO_PIN_FINAL_TRY        0x00200000UL
#define CKF_SO_PIN_LOCKED           0x00400000UL
#define CKF_SO_PIN_TO_BE_CHANGED    0x00800000UL

/* Session Handles and Types */
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE * CK_SESSION_HANDLE_PTR;

typedef CK_ULONG CK_USER_TYPE;
#define CKU_SO      0UL
#define CKU_USER    1UL
#define CKU_CONTEXT_SPECIFIC 2UL

typedef CK_ULONG CK_STATE;
#define CKS_RO_PUBLIC_SESSION 0UL
#define CKS_RO_USER_FUNCTIONS 1UL
#define CKS_RW_PUBLIC_SESSION 2UL
#define CKS_RW_USER_FUNCTIONS 3UL
#define CKS_RW_SO_FUNCTIONS   4UL

/* Session Flags */
#define CKF_RW_SESSION     0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_STATE   state;
    CK_FLAGS   flags;
    CK_ULONG   ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO * CK_SESSION_INFO_PTR;

/* Objects and Attributes */
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE * CK_OBJECT_HANDLE_PTR;

typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_OBJECT_CLASS * CK_OBJECT_CLASS_PTR;
#define CKO_DATA              0x00000000UL
#define CKO_CERTIFICATE       0x00000001UL
#define CKO_PUBLIC_KEY        0x00000002UL
#define CKO_PRIVATE_KEY       0x00000003UL
#define CKO_SECRET_KEY        0x00000004UL
#define CKO_HW_FEATURE        0x00000005UL
#define CKO_DOMAIN_PARAMETERS 0x00000006UL
#define CKO_MECHANISM         0x00000007UL
#define CKO_OTP_KEY           0x00000008UL

typedef CK_ULONG CK_KEY_TYPE;
typedef CK_KEY_TYPE * CK_KEY_TYPE_PTR;
#define CKK_RSA    0x00000000UL
#define CKK_DSA    0x00000001UL
#define CKK_DH     0x00000002UL
#define CKK_EC     0x00000003UL
#define CKK_X9_42_DH 0x00000004UL
#define CKK_AES    0x0000001FUL

typedef CK_ULONG CK_ATTRIBUTE_TYPE;
#define CKA_CLASS              0x00000000UL
#define CKA_TOKEN              0x00000001UL
#define CKA_PRIVATE            0x00000002UL
#define CKA_LABEL              0x00000003UL
#define CKA_APPLICATION        0x00000010UL
#define CKA_VALUE              0x00000011UL
#define CKA_OBJECT_ID          0x00000012UL
#define CKA_CERTIFICATE_TYPE   0x00000080UL
#define CKA_ISSUER             0x00000081UL
#define CKA_SERIAL_NUMBER      0x00000082UL
#define CKA_KEY_TYPE           0x00000100UL
#define CKA_SUBJECT            0x00000101UL
#define CKA_ID                 0x00000102UL
#define CKA_SENSITIVE          0x00000103UL
#define CKA_ENCRYPT            0x00000104UL
#define CKA_DECRYPT            0x00000105UL
#define CKA_WRAP               0x00000106UL
#define CKA_UNWRAP             0x00000107UL
#define CKA_SIGN               0x00000108UL
#define CKA_SIGN_RECOVER       0x00000109UL
#define CKA_VERIFY             0x0000010AUL
#define CKA_VERIFY_RECOVER     0x0000010BUL
#define CKA_DERIVE             0x0000010CUL
#define CKA_START_DATE         0x00000110UL
#define CKA_END_DATE           0x00000111UL
#define CKA_MODULUS            0x00000120UL
#define CKA_MODULUS_BITS       0x00000121UL
#define CKA_PUBLIC_EXPONENT    0x00000122UL
#define CKA_PRIVATE_EXPONENT   0x00000123UL
#define CKA_EC_PARAMS          0x00000180UL
#define CKA_EC_POINT           0x00000181UL
#define CKA_ALWAYS_SENSITIVE   0x00000165UL
#define CKA_NEVER_EXTRACTABLE  0x00000164UL
#define CKA_MODIFIABLE         0x00000170UL
#define CKA_EXTRACTABLE        0x00000162UL
#define CKA_LOCAL              0x00000163UL

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE * CK_ATTRIBUTE_PTR;

/* Mechanism Types and Info */
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE * CK_MECHANISM_TYPE_PTR;

#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000UL
#define CKM_RSA_PKCS              0x00000001UL
#define CKM_EC_KEY_PAIR_GEN       0x00001040UL
#define CKM_ECDSA                 0x00001041UL
#define CKM_ECDSA_SHA1            0x00001042UL
#define CKM_ECDSA_SHA224          0x00001043UL
#define CKM_ECDSA_SHA256          0x00001044UL
#define CKM_ECDSA_SHA384          0x00001045UL
#define CKM_ECDSA_SHA512          0x00001046UL
#define CKM_SHA256                0x00000250UL

/* Mechanism Flags */
#define CKF_HW                0x00000001UL
#define CKF_ENCRYPT           0x00000100UL
#define CKF_DECRYPT           0x00000200UL
#define CKF_DIGEST            0x00000400UL
#define CKF_SIGN              0x00000800UL
#define CKF_SIGN_RECOVER      0x00001000UL
#define CKF_VERIFY            0x00002000UL
#define CKF_VERIFY_RECOVER    0x00004000UL
#define CKF_GENERATE          0x00008000UL
#define CKF_GENERATE_KEY_PAIR 0x00010000UL
#define CKF_WRAP              0x00020000UL
#define CKF_UNWRAP            0x00040000UL
#define CKF_DERIVE            0x00080000UL

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR       pParameter;
    CK_ULONG          ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM * CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO * CK_MECHANISM_INFO_PTR;

/* Mutex Callbacks and Initialize Args */
typedef CK_ULONG CK_RV;

typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR_PTR ppMutex);
typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

#define CKF_OS_LOCKING_OK 0x00000002UL

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX  CreateMutex;
    CK_DESTROYMUTEX DestroyMutex;
    CK_LOCKMUTEX    LockMutex;
    CK_UNLOCKMUTEX  UnlockMutex;
    CK_FLAGS        flags;
    CK_VOID_PTR     pReserved;
} CK_C_INITIALIZE_ARGS;
typedef CK_C_INITIALIZE_ARGS * CK_C_INITIALIZE_ARGS_PTR;

/* Return Values (CK_RV) */
#define CKR_OK                                0x00000000UL
#define CKR_CANCEL                            0x00000001UL
#define CKR_HOST_MEMORY                       0x00000002UL
#define CKR_SLOT_ID_INVALID                   0x00000003UL
#define CKR_GENERAL_ERROR                     0x00000005UL
#define CKR_FUNCTION_FAILED                   0x00000006UL
#define CKR_ARGUMENTS_BAD                     0x00000007UL
#define CKR_NO_EVENT                          0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS            0x00000009UL
#define CKR_CANT_LOCK                         0x0000000AUL
#define CKR_ATTRIBUTE_READ_ONLY               0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE               0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID            0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID           0x00000013UL
#define CKR_ACTION_PROHIBITED                 0x0000001BUL
#define CKR_DATA_INVALID                      0x00000020UL
#define CKR_DATA_LEN_RANGE                    0x00000021UL
#define CKR_DEVICE_ERROR                      0x00000030UL
#define CKR_DEVICE_MEMORY                     0x00000031UL
#define CKR_DEVICE_REMOVED                    0x00000032UL
#define CKR_ENCRYPTED_DATA_INVALID            0x00000040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE          0x00000041UL
#define CKR_FUNCTION_CANCELED                 0x00000050UL
#define CKR_FUNCTION_NOT_PARALLEL             0x00000051UL
#define CKR_FUNCTION_NOT_SUPPORTED            0x00000054UL
#define CKR_KEY_HANDLE_INVALID                0x00000060UL
#define CKR_KEY_SIZE_RANGE                    0x00000062UL
#define CKR_KEY_TYPE_INCONSISTENT             0x00000063UL
#define CKR_KEY_NOT_NEEDED                    0x00000064UL
#define CKR_KEY_CHANGED                       0x00000065UL
#define CKR_KEY_NEEDED                        0x00000066UL
#define CKR_KEY_INDIGESTIBLE                  0x00000067UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED        0x00000068UL
#define CKR_KEY_NOT_WRAPPABLE                 0x00000069UL
#define CKR_KEY_UNEXTRACTABLE                 0x0000006AUL
#define CKR_MECHANISM_INVALID                 0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID           0x00000071UL
#define CKR_OBJECT_HANDLE_INVALID             0x00000082UL
#define CKR_OPERATION_ACTIVE                  0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED         0x00000091UL
#define CKR_PIN_INCORRECT                     0x000000A0UL
#define CKR_PIN_INVALID                       0x000000A1UL
#define CKR_PIN_LEN_RANGE                     0x000000A2UL
#define CKR_PIN_EXPIRED                       0x000000A3UL
#define CKR_PIN_LOCKED                        0x000000A4UL
#define CKR_SESSION_CLOSED                    0x000000B0UL
#define CKR_SESSION_COUNT                     0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID            0x000000B3UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED    0x000000B4UL
#define CKR_SESSION_READ_ONLY                 0x000000B5UL
#define CKR_SESSION_EXISTS                    0x000000B6UL
#define CKR_SESSION_READ_ONLY_EXISTS          0x000000B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS      0x000000B8UL
#define CKR_SIGNATURE_INVALID                 0x000000C0UL
#define CKR_SIGNATURE_LEN_RANGE               0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE               0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT             0x000000D1UL
#define CKR_TOKEN_NOT_PRESENT                 0x000000E0UL
#define CKR_TOKEN_NOT_RECOGNIZED              0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED             0x000000E2UL
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID     0x000000F0UL
#define CKR_UNWRAPPING_KEY_SIZE_RANGE         0x000000F1UL
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2UL
#define CKR_USER_ALREADY_LOGGED_IN            0x00000100UL
#define CKR_USER_NOT_LOGGED_IN                0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED          0x00000102UL
#define CKR_USER_TYPE_INVALID                 0x00000103UL
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104UL
#define CKR_USER_TOO_MANY_SESSIONS            0x00000105UL
#define CKR_WRAPPED_KEY_INVALID               0x00000110UL
#define CKR_WRAPPED_KEY_LEN_RANGE             0x00000112UL
#define CKR_WRAPPING_KEY_HANDLE_INVALID       0x00000113UL
#define CKR_WRAPPING_KEY_SIZE_RANGE           0x00000114UL
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT    0x00000115UL
#define CKR_RANDOM_SEED_NOT_SUPPORTED         0x00000120UL
#define CKR_RANDOM_NO_RNG                     0x00000121UL
#define CKR_DOMAIN_PARAMS_INVALID             0x00000130UL
#define CKR_CURVE_NOT_SUPPORTED               0x00000140UL
#define CKR_BUFFER_TOO_SMALL                  0x00000150UL
#define CKR_SAVED_STATE_INVALID               0x00000160UL
#define CKR_INFORMATION_SENSITIVE             0x00000170UL
#define CKR_STATE_UNSAVEABLE                  0x00000180UL
#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191UL
#define CKR_MUTEX_BAD                         0x000001A0UL
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1UL

/* Forward declaration of function list */
struct CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST * CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR * CK_FUNCTION_LIST_PTR_PTR;

#endif /* _PKCS11T_H_ */
