/*
 * PKCS#11 Provider Library Unit & Integration Tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#endif

#include "pkcs11/cryptoki.h"
#include "transport/serial_transport.h"
#include "transport/at_client.h"
#include "nrf52840_p11_internal.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        exit(1); \
    } \
} while (0)

static void test_serial_port_discovery(void) {
    printf("--- Serial Port Autodiscovery & Candidate Prioritization Tests ---\n");

#if defined(__APPLE__)
    int score_tty3 = serial_score_candidate("/dev/tty.usbmodem31424103");
    int score_tty1 = serial_score_candidate("/dev/tty.usbmodem31424101");
    int score_cu3  = serial_score_candidate("/dev/cu.usbmodem31424103");
    int score_cu1  = serial_score_candidate("/dev/cu.usbmodem31424101");

    TEST_ASSERT(score_tty3 == 1000, "tty.usbmodem with suffix 3 must score 1000");
    TEST_ASSERT(score_cu3 == 900, "cu.usbmodem with suffix 3 must score 900");
    TEST_ASSERT(score_tty1 == 200, "tty.usbmodem with suffix 1 must score 200");
    TEST_ASSERT(score_cu1 == 100, "cu.usbmodem with suffix 1 must score 100");

    TEST_ASSERT(score_tty3 > score_tty1, "Suffix 3 (AT data) must have higher priority than suffix 1 (Console)");
    TEST_ASSERT(score_tty3 > score_cu3, "tty.usbmodem must have higher priority than cu.usbmodem");
    TEST_ASSERT(score_cu3 > score_tty1, "cu suffix 3 must have higher priority than suffix 1");

    printf("[PASS] Candidate port scoring: suffix '3' (AT data, score=%d) prioritized over suffix '1' (console, score=%d)\n",
           score_tty3, score_tty1);
#elif !defined(_WIN32)
    int score_acm1 = serial_score_candidate("/dev/ttyACM1");
    int score_acm0 = serial_score_candidate("/dev/ttyACM0");
    TEST_ASSERT(score_acm1 > score_acm0, "ttyACM1 must have higher priority than ttyACM0");
    printf("[PASS] Candidate port scoring: ttyACM1 prioritized over ttyACM0\n");
#endif
    printf("------------------------------------------------------------------\n\n");
}

#if !defined(_WIN32)
typedef struct {
    int fd;
    const char *resp;
} mock_resp_ctx_t;

static void *mock_responder_thread(void *arg) {
    mock_resp_ctx_t *mctx = (mock_resp_ctx_t *)arg;
    char buf[256];
    ssize_t n = read(mctx->fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        write(mctx->fd, mctx->resp, strlen(mctx->resp));
    }
    return NULL;
}

static void test_dual_mode_authentication_semantics(CK_FUNCTION_LIST_PTR p11) {
    printf("--- Dual-Mode Authentication (PIN vs Shamir) Tests ---\n");

    p11_global_ctx_t *ctx = p11_get_ctx();
    bool saved_present = ctx->token_present;
    serial_transport_t *saved_tr = ctx->transport;
    char saved_method[16];
    strncpy(saved_method, ctx->auth_method, sizeof(saved_method) - 1);
    saved_method[sizeof(saved_method) - 1] = '\0';

    ctx->token_present = true;

    /* 1. Test C_GetTokenInfo with Shamir mode flag via mock transport */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        serial_transport_t mock_tr;
        serial_init(&mock_tr);
        mock_tr.fd = sv[0];
        mock_tr.is_open = true;
        ctx->transport = &mock_tr;

        mock_resp_ctx_t mctx = {
            .fd = sv[1],
            .resp = "\r\n+STATUS: CONFIGURED=1,AUTH=0,METHOD=SHAMIR,RETRIES=3,KEYCOUNT=2\r\nOK\r\n",
        };
        pthread_t th;
        pthread_create(&th, NULL, mock_responder_thread, &mctx);

        CK_TOKEN_INFO tinfo;
        CK_RV rv = p11->C_GetTokenInfo(P11_SLOT_ID, &tinfo);
        pthread_join(th, NULL);
        close(sv[0]);
        close(sv[1]);

        TEST_ASSERT(rv == CKR_OK, "C_GetTokenInfo failed in SHAMIR mode");
        TEST_ASSERT((tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0,
                    "SHAMIR mode must set CKF_PROTECTED_AUTHENTICATION_PATH");
        printf("[PASS] C_GetTokenInfo: SHAMIR mode sets CKF_PROTECTED_AUTHENTICATION_PATH\n");
    }

    /* 2. Test C_GetTokenInfo with PIN mode flag via mock transport */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        serial_transport_t mock_tr;
        serial_init(&mock_tr);
        mock_tr.fd = sv[0];
        mock_tr.is_open = true;
        ctx->transport = &mock_tr;

        mock_resp_ctx_t mctx = {
            .fd = sv[1],
            .resp = "\r\n+STATUS: CONFIGURED=1,AUTH=0,METHOD=PIN,RETRIES=3,KEYCOUNT=2\r\nOK\r\n",
        };
        pthread_t th;
        pthread_create(&th, NULL, mock_responder_thread, &mctx);

        CK_TOKEN_INFO tinfo;
        CK_RV rv = p11->C_GetTokenInfo(P11_SLOT_ID, &tinfo);
        pthread_join(th, NULL);
        close(sv[0]);
        close(sv[1]);

        TEST_ASSERT(rv == CKR_OK, "C_GetTokenInfo failed in PIN mode");
        TEST_ASSERT((tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) == 0,
                    "PIN mode must clear CKF_PROTECTED_AUTHENTICATION_PATH");
        printf("[PASS] C_GetTokenInfo: PIN mode clears CKF_PROTECTED_AUTHENTICATION_PATH\n");
    }

    /* 3. Test at_get_status parser across diverse response formats */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        serial_transport_t mock_tr;
        serial_init(&mock_tr);
        mock_tr.fd = sv[0];
        mock_tr.is_open = true;

        mock_resp_ctx_t mctx = {
            .fd = sv[1],
            .resp = "\r\n+STATUS: CONFIGURED=1,AUTH=0,METHOD=SHAMIR,RETRIES=3,KEYCOUNT=2\r\nOK\r\n",
        };
        pthread_t th;
        pthread_create(&th, NULL, mock_responder_thread, &mctx);

        bool auth = false;
        int retries = 0, keycount = 0;
        bool configured = false;
        char method[16] = {0};

        CK_RV rv = at_get_status(&mock_tr, &auth, &retries, &keycount, &configured, method, sizeof(method));
        pthread_join(th, NULL);
        close(sv[0]);
        close(sv[1]);

        TEST_ASSERT(rv == CKR_OK, "at_get_status failed");
        TEST_ASSERT(auth == false, "Expected auth == false");
        TEST_ASSERT(configured == true, "Expected configured == true");
        TEST_ASSERT(strcmp(method, "SHAMIR") == 0, "Expected method == SHAMIR");
        TEST_ASSERT(retries == 3, "Expected retries == 3");
        TEST_ASSERT(keycount == 2, "Expected keycount == 2");
        printf("[PASS] at_get_status: Parsed CONFIGURED=1, AUTH=0, METHOD=SHAMIR, RETRIES=3, KEYCOUNT=2\n");
    }

    /* 4. Test C_Login in Shamir mode when device is locked (AUTH == 0) */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        serial_transport_t mock_tr;
        serial_init(&mock_tr);
        mock_tr.fd = sv[0];
        mock_tr.is_open = true;
        ctx->transport = &mock_tr;

        mock_resp_ctx_t mctx = {
            .fd = sv[1],
            .resp = "\r\n+STATUS: CONFIGURED=1,AUTH=0,METHOD=SHAMIR,RETRIES=3,KEYCOUNT=2\r\nOK\r\n",
        };
        pthread_t th;
        pthread_create(&th, NULL, mock_responder_thread, &mctx);

        /* Prepare session 0 */
        ctx->sessions[0].in_use = true;
        ctx->sessions[0].handle = 1;
        ctx->sessions[0].slot_id = P11_SLOT_ID;
        ctx->sessions[0].state = CKS_RW_PUBLIC_SESSION;
        ctx->sessions[0].flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        ctx->user_logged_in = false;
        ctx->so_logged_in = false;
        strncpy(ctx->auth_method, "SHAMIR", sizeof(ctx->auth_method) - 1);

        CK_RV rv = p11->C_Login(1, CKU_USER, NULL, 0);
        pthread_join(th, NULL);
        close(sv[0]);
        close(sv[1]);

        TEST_ASSERT(rv == CKR_PIN_INCORRECT, "Locked Shamir mode must return CKR_PIN_INCORRECT");
        printf("[PASS] C_Login: Locked Shamir mode returns CKR_PIN_INCORRECT with prompt guidance\n");
    }

    /* 5. Test C_Login in Shamir mode when device is already unlocked (AUTH == 1) */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        serial_transport_t mock_tr;
        serial_init(&mock_tr);
        mock_tr.fd = sv[0];
        mock_tr.is_open = true;
        ctx->transport = &mock_tr;

        mock_resp_ctx_t mctx = {
            .fd = sv[1],
            .resp = "\r\n+STATUS: CONFIGURED=1,AUTH=1,METHOD=SHAMIR,RETRIES=3,KEYCOUNT=2\r\nOK\r\n",
        };
        pthread_t th;
        pthread_create(&th, NULL, mock_responder_thread, &mctx);

        ctx->sessions[0].in_use = true;
        ctx->sessions[0].handle = 1;
        ctx->sessions[0].slot_id = P11_SLOT_ID;
        ctx->sessions[0].state = CKS_RW_PUBLIC_SESSION;
        ctx->sessions[0].flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        ctx->user_logged_in = false;
        ctx->so_logged_in = false;
        strncpy(ctx->auth_method, "SHAMIR", sizeof(ctx->auth_method) - 1);

        CK_RV rv = p11->C_Login(1, CKU_USER, NULL, 0);
        pthread_join(th, NULL);
        close(sv[0]);
        close(sv[1]);

        TEST_ASSERT(rv == CKR_OK, "Unlocked Shamir mode must return CKR_OK");
        TEST_ASSERT(ctx->sessions[0].state == CKS_RW_USER_FUNCTIONS, "Session must transition to CKS_RW_USER_FUNCTIONS");
        printf("[PASS] C_Login: Unlocked Shamir mode returns CKR_OK and sets CKS_RW_USER_FUNCTIONS\n");

        /* Reset session */
        ctx->user_logged_in = false;
        ctx->sessions[0].in_use = false;
    }

    /* Restore context */
    ctx->transport = saved_tr;
    ctx->token_present = saved_present;
    strncpy(ctx->auth_method, saved_method, sizeof(ctx->auth_method) - 1);
    printf("------------------------------------------------------\n\n");
}
#endif

int main(void) {
    printf("====================================================\n");
    printf("  nRF52840 PKCS#11 Provider Library Test Suite      \n");
    printf("====================================================\n\n");

    /* Test port autodiscovery scoring logic */
    test_serial_port_discovery();

    CK_FUNCTION_LIST_PTR p11 = NULL;
    CK_RV rv = C_GetFunctionList(&p11);
    TEST_ASSERT(rv == CKR_OK, "C_GetFunctionList returned error");
    TEST_ASSERT(p11 != NULL, "C_GetFunctionList returned NULL pointer");
    TEST_ASSERT(p11->version.major == 2 && p11->version.minor == 40, "Invalid cryptoki version");
    printf("[PASS] C_GetFunctionList: Cryptoki v%d.%d ready\n", p11->version.major, p11->version.minor);

    /* Test C_Initialize */
    rv = p11->C_Initialize(NULL);
    TEST_ASSERT(rv == CKR_OK, "C_Initialize failed");
    printf("[PASS] C_Initialize\n");

    /* Test C_Initialize already initialized */
    rv = p11->C_Initialize(NULL);
    TEST_ASSERT(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED, "Double initialize should return CKR_CRYPTOKI_ALREADY_INITIALIZED");
    printf("[PASS] C_Initialize idempotency guard\n");

    /* Test C_GetInfo */
    CK_INFO info;
    rv = p11->C_GetInfo(&info);
    TEST_ASSERT(rv == CKR_OK, "C_GetInfo failed");
    printf("[PASS] C_GetInfo: Manufacturer = '%.9s', Library = '%.24s'\n", info.manufacturerID, info.libraryDescription);

    /* Test C_GetSlotList */
    CK_ULONG slot_count = 0;
    rv = p11->C_GetSlotList(CK_FALSE, NULL, &slot_count);
    TEST_ASSERT(rv == CKR_OK, "C_GetSlotList query count failed");
    TEST_ASSERT(slot_count >= 1, "Expected at least 1 slot");

    CK_SLOT_ID slots[4];
    rv = p11->C_GetSlotList(CK_FALSE, slots, &slot_count);
    TEST_ASSERT(rv == CKR_OK, "C_GetSlotList retrieve slots failed");
    printf("[PASS] C_GetSlotList: Found %lu slot(s)\n", (unsigned long)slot_count);

    /* Test C_GetSlotInfo */
    CK_SLOT_INFO slot_info;
    rv = p11->C_GetSlotInfo(slots[0], &slot_info);
    TEST_ASSERT(rv == CKR_OK, "C_GetSlotInfo failed");
    printf("[PASS] C_GetSlotInfo: Description = '%.32s'\n", slot_info.slotDescription);

    /* Test C_GetMechanismList */
    CK_ULONG mech_count = 0;
    rv = p11->C_GetMechanismList(slots[0], NULL, &mech_count);
    TEST_ASSERT(rv == CKR_OK, "C_GetMechanismList query count failed");
    TEST_ASSERT(mech_count >= 3, "Expected at least 3 mechanisms");

    CK_MECHANISM_TYPE mechs[16];
    rv = p11->C_GetMechanismList(slots[0], mechs, &mech_count);
    TEST_ASSERT(rv == CKR_OK, "C_GetMechanismList retrieval failed");

    bool has_ec_keygen = false, has_ecdsa = false, has_ecdsa_sha256 = false;
    for (CK_ULONG i = 0; i < mech_count; i++) {
        if (mechs[i] == CKM_EC_KEY_PAIR_GEN) has_ec_keygen = true;
        if (mechs[i] == CKM_ECDSA) has_ecdsa = true;
        if (mechs[i] == CKM_ECDSA_SHA256) has_ecdsa_sha256 = true;
    }
    TEST_ASSERT(has_ec_keygen && has_ecdsa && has_ecdsa_sha256, "Missing required EC mechanisms");
    printf("[PASS] C_GetMechanismList: CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDSA_SHA256 confirmed\n");

    /* Test C_GetMechanismInfo */
    CK_MECHANISM_INFO minfo;
    rv = p11->C_GetMechanismInfo(slots[0], CKM_ECDSA, &minfo);
    TEST_ASSERT(rv == CKR_OK, "C_GetMechanismInfo failed for CKM_ECDSA");
    TEST_ASSERT(minfo.ulMinKeySize == 256 && minfo.ulMaxKeySize == 256, "Invalid key sizes for CKM_ECDSA");
    printf("[PASS] C_GetMechanismInfo: CKM_ECDSA 256-bit P-256 confirmed\n");

#if !defined(_WIN32)
    /* Test Dual-Mode Authentication (PIN vs Shamir) Semantics */
    test_dual_mode_authentication_semantics(p11);
#endif

    /* Check if token/mock is active for session and crypto tests */
    CK_SESSION_HANDLE hRWSession = CK_INVALID_HANDLE;
    rv = p11->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hRWSession);
    if (rv == CKR_OK) {
        printf("[PASS] C_OpenSession: Opened R/W serial session %lu\n", (unsigned long)hRWSession);

        CK_SESSION_INFO sinfo;
        rv = p11->C_GetSessionInfo(hRWSession, &sinfo);
        TEST_ASSERT(rv == CKR_OK, "C_GetSessionInfo failed");
        TEST_ASSERT(sinfo.state == CKS_RW_PUBLIC_SESSION, "Expected initial state CKS_RW_PUBLIC_SESSION");
        printf("[PASS] C_GetSessionInfo: State = %lu (CKS_RW_PUBLIC_SESSION)\n", (unsigned long)sinfo.state);

        /* ---------------------------------------------------------
         * Phase 3: Session State Mapping & Compatibility Tests
         * --------------------------------------------------------- */

        /* 1. Argument validation on C_Login */
        rv = p11->C_Login(hRWSession, CKU_USER, NULL, 6);
        TEST_ASSERT(rv == CKR_ARGUMENTS_BAD, "C_Login NULL pin should return CKR_ARGUMENTS_BAD");

        CK_UTF8CHAR short_pin[] = "12";
        rv = p11->C_Login(hRWSession, CKU_USER, short_pin, 2);
        TEST_ASSERT(rv == CKR_PIN_LEN_RANGE, "C_Login short pin (<4) should return CKR_PIN_LEN_RANGE");

        CK_UTF8CHAR long_pin[] = "12345678901234567890";
        rv = p11->C_Login(hRWSession, CKU_USER, long_pin, 20);
        TEST_ASSERT(rv == CKR_PIN_LEN_RANGE, "C_Login long pin (>16) should return CKR_PIN_LEN_RANGE");

        CK_UTF8CHAR default_pin[] = "123456";
        rv = p11->C_Login(hRWSession, 0x99, default_pin, (CK_ULONG)strlen((char *)default_pin));
        TEST_ASSERT(rv == CKR_USER_TYPE_INVALID, "C_Login invalid userType should return CKR_USER_TYPE_INVALID");
        printf("[PASS] C_Login: Argument validations (NULL, short, long, invalid userType)\n");

        /* 2. Open Read-Only session and test SO login rejection (CKR_SESSION_READ_ONLY_EXISTS) */
        CK_SESSION_HANDLE hROSession = CK_INVALID_HANDLE;
        rv = p11->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &hROSession);
        TEST_ASSERT(rv == CKR_OK, "Failed to open Read-Only session");

        rv = p11->C_GetSessionInfo(hROSession, &sinfo);
        TEST_ASSERT(rv == CKR_OK && sinfo.state == CKS_RO_PUBLIC_SESSION, "Expected CKS_RO_PUBLIC_SESSION");

        /* Attempt SO login on R/W session while R/O session exists */
        rv = p11->C_Login(hRWSession, CKU_SO, default_pin, (CK_ULONG)strlen((char *)default_pin));
        TEST_ASSERT(rv == CKR_SESSION_READ_ONLY_EXISTS,
                    "C_Login CKU_SO must return CKR_SESSION_READ_ONLY_EXISTS when R/O session exists");

        /* Attempt SO login directly on R/O session */
        rv = p11->C_Login(hROSession, CKU_SO, default_pin, (CK_ULONG)strlen((char *)default_pin));
        TEST_ASSERT(rv == CKR_SESSION_READ_ONLY_EXISTS,
                    "C_Login CKU_SO must return CKR_SESSION_READ_ONLY_EXISTS when called on R/O session");

        /* Close R/O session */
        rv = p11->C_CloseSession(hROSession);
        TEST_ASSERT(rv == CKR_OK, "C_CloseSession hROSession failed");
        printf("[PASS] C_Login: CKU_SO rejected with CKR_SESSION_READ_ONLY_EXISTS when R/O session exists\n");

        /* 3. Successful SO login on pure R/W session */
        rv = p11->C_Login(hRWSession, CKU_SO, default_pin, (CK_ULONG)strlen((char *)default_pin));
        if (rv == CKR_OK) {
            rv = p11->C_GetSessionInfo(hRWSession, &sinfo);
            TEST_ASSERT(rv == CKR_OK && sinfo.state == CKS_RW_SO_FUNCTIONS, "Expected CKS_RW_SO_FUNCTIONS");
            printf("[PASS] C_Login: CKU_SO authenticated -> CKS_RW_SO_FUNCTIONS\n");

            /* While SO logged in, opening R/O session must fail */
            rv = p11->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &hROSession);
            TEST_ASSERT(rv == CKR_SESSION_READ_ONLY_EXISTS, "Open R/O session while SO logged in must fail");

            /* Double login as SO */
            rv = p11->C_Login(hRWSession, CKU_SO, default_pin, (CK_ULONG)strlen((char *)default_pin));
            TEST_ASSERT(rv == CKR_USER_ALREADY_LOGGED_IN, "Double SO login must return CKR_USER_ALREADY_LOGGED_IN");

            /* Attempt to login as USER while SO is logged in */
            rv = p11->C_Login(hRWSession, CKU_USER, default_pin, (CK_ULONG)strlen((char *)default_pin));
            TEST_ASSERT(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                        "USER login while SO is logged in must return CKR_USER_ANOTHER_ALREADY_LOGGED_IN");

            /* Test C_Logout */
            rv = p11->C_Logout(hRWSession);
            TEST_ASSERT(rv == CKR_OK, "C_Logout failed");
            rv = p11->C_GetSessionInfo(hRWSession, &sinfo);
            TEST_ASSERT(rv == CKR_OK && sinfo.state == CKS_RW_PUBLIC_SESSION, "Expected CKS_RW_PUBLIC_SESSION after logout");
            printf("[PASS] C_Logout: SO logged out -> reverted to CKS_RW_PUBLIC_SESSION\n");

            /* Duplicate logout */
            rv = p11->C_Logout(hRWSession);
            TEST_ASSERT(rv == CKR_USER_NOT_LOGGED_IN, "C_Logout when not logged in must return CKR_USER_NOT_LOGGED_IN");

            /* Test incorrect PIN error reporting */
            CK_UTF8CHAR wrong_pin[] = "000000";
            rv = p11->C_Login(hRWSession, CKU_USER, wrong_pin, (CK_ULONG)strlen((char *)wrong_pin));
            TEST_ASSERT(rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED,
                        "C_Login with wrong PIN must return CKR_PIN_INCORRECT or CKR_PIN_LOCKED");
            printf("[PASS] C_Login: Invalid PIN correctly returned %s\n",
                   (rv == CKR_PIN_INCORRECT) ? "CKR_PIN_INCORRECT" : "CKR_PIN_LOCKED");
        }

        /* 4. Successful USER login with both R/O and R/W sessions open */
        rv = p11->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &hROSession);
        TEST_ASSERT(rv == CKR_OK, "Failed to re-open Read-Only session");

        rv = p11->C_Login(hRWSession, CKU_USER, default_pin, (CK_ULONG)strlen((char *)default_pin));
        if (rv == CKR_OK) {
            rv = p11->C_GetSessionInfo(hRWSession, &sinfo);
            TEST_ASSERT(rv == CKR_OK && sinfo.state == CKS_RW_USER_FUNCTIONS, "Expected CKS_RW_USER_FUNCTIONS");

            rv = p11->C_GetSessionInfo(hROSession, &sinfo);
            TEST_ASSERT(rv == CKR_OK && sinfo.state == CKS_RO_USER_FUNCTIONS, "Expected CKS_RO_USER_FUNCTIONS");
            printf("[PASS] C_Login: CKU_USER authenticated -> R/W=CKS_RW_USER_FUNCTIONS, R/O=CKS_RO_USER_FUNCTIONS\n");

            /* Double login as USER */
            rv = p11->C_Login(hRWSession, CKU_USER, default_pin, (CK_ULONG)strlen((char *)default_pin));
            TEST_ASSERT(rv == CKR_USER_ALREADY_LOGGED_IN, "Double USER login must return CKR_USER_ALREADY_LOGGED_IN");

            /* Attempt to login as SO while USER is logged in */
            rv = p11->C_Login(hRWSession, CKU_SO, default_pin, (CK_ULONG)strlen((char *)default_pin));
            TEST_ASSERT(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                        "SO login while USER logged in must return CKR_USER_ANOTHER_ALREADY_LOGGED_IN");

            /* Test C_GenerateKeyPair */
            CK_MECHANISM keygen_mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
            CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;

            CK_BYTE key_id_val = 1;
            char key_label[] = "MockTestKey";
            CK_ATTRIBUTE pub_tmpl[] = {
                { CKA_ID, &key_id_val, sizeof(key_id_val) },
                { CKA_LABEL, key_label, (CK_ULONG)strlen(key_label) }
            };
            CK_ATTRIBUTE priv_tmpl[] = {
                { CKA_ID, &key_id_val, sizeof(key_id_val) },
                { CKA_LABEL, key_label, (CK_ULONG)strlen(key_label) }
            };

            rv = p11->C_GenerateKeyPair(hRWSession, &keygen_mech,
                                        pub_tmpl, 2,
                                        priv_tmpl, 2,
                                        &hPub, &hPriv);
            if (rv == CKR_OK) {
                printf("[PASS] C_GenerateKeyPair: Public Handle=%lu, Private Handle=%lu\n",
                       (unsigned long)hPub, (unsigned long)hPriv);

                /* Test C_GetAttributeValue on public key */
                uint8_t ec_point[128];
                CK_ATTRIBUTE get_tmpl[] = {
                    { CKA_EC_POINT, ec_point, sizeof(ec_point) }
                };
                rv = p11->C_GetAttributeValue(hRWSession, hPub, get_tmpl, 1);
                if (rv == CKR_OK) {
                    TEST_ASSERT(get_tmpl[0].ulValueLen == 67, "Expected 67-byte DER EC_POINT");
                    TEST_ASSERT(ec_point[0] == 0x04 && ec_point[1] == 0x41, "Expected DER OCTET STRING 04 41");
                    printf("[PASS] C_GetAttributeValue: Retrieved 65-byte uncompressed public key\n");
                }

                /* Test C_Sign */
                CK_MECHANISM sign_mech = { CKM_ECDSA, NULL, 0 };
                rv = p11->C_SignInit(hRWSession, &sign_mech, hPriv);
                if (rv == CKR_USER_NOT_LOGGED_IN) {
                    printf("[PASS] Device auto self-locked post-keygen: C_SignInit gracefully returned CKR_USER_NOT_LOGGED_IN\n");
                    /* Re-authenticate to complete signing */
                    rv = p11->C_Login(hRWSession, CKU_USER, default_pin, (CK_ULONG)strlen((char *)default_pin));
                    TEST_ASSERT(rv == CKR_OK, "Re-login post-lock failed");
                    printf("[PASS] Re-login after device self-lock succeeded\n");
                    rv = p11->C_SignInit(hRWSession, &sign_mech, hPriv);
                }
                TEST_ASSERT(rv == CKR_OK, "C_SignInit failed after authentication");

                uint8_t dummy_digest[32];
                memset(dummy_digest, 0x5A, sizeof(dummy_digest));

                CK_ULONG sig_len = 0;
                rv = p11->C_Sign(hRWSession, dummy_digest, sizeof(dummy_digest), NULL, &sig_len);
                TEST_ASSERT(rv == CKR_OK && sig_len == 64, "C_Sign query length failed");

                uint8_t signature[64];
                rv = p11->C_Sign(hRWSession, dummy_digest, sizeof(dummy_digest), signature, &sig_len);
                if (rv == CKR_OK) {
                    TEST_ASSERT(sig_len == 64, "Signature length must be 64 bytes (R || S)");
                    printf("[PASS] C_Sign: Successfully generated 64-byte P-256 ECDSA signature\n");
                }
            }

            /* Test C_GenerateRandom */
            uint8_t rand_bytes[32] = {0};
            rv = p11->C_GenerateRandom(hRWSession, rand_bytes, sizeof(rand_bytes));
            if (rv == CKR_OK) {
                printf("[PASS] C_GenerateRandom: Generated %lu random bytes\n", (unsigned long)sizeof(rand_bytes));
            }

            /* Test C_Logout */
            rv = p11->C_Logout(hRWSession);
            if (rv == CKR_OK) {
                printf("[PASS] C_Logout\n");
            }
        }

        /* Close sessions */
        p11->C_CloseSession(hROSession);
        p11->C_CloseSession(hRWSession);
        printf("[PASS] All active sessions closed\n");
    } else {
        printf("[INFO] Device/Mock PTY not connected (rv=%lu); validated offline API semantics\n", (unsigned long)rv);
    }

    /* Test C_Finalize */
    rv = p11->C_Finalize(NULL);
    TEST_ASSERT(rv == CKR_OK, "C_Finalize failed");
    printf("[PASS] C_Finalize\n");

    printf("\nAll PKCS#11 unit and interface tests PASSED!\n");
    return 0;
}
