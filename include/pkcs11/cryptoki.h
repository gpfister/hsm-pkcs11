/*
 * Cryptoki compatibility header
 */

#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_ 1

#ifndef CK_PTR
#define CK_PTR *
#endif

#ifndef CK_DEFINE_FUNCTION
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#endif

#ifndef CK_DECLARE_FUNCTION
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#endif

#ifndef CK_DECLARE_FUNCTION_POINTER
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#endif

#ifndef CK_CALLBACK_FUNCTION_POINTER
#define CK_CALLBACK_FUNCTION_POINTER(returnType, name) returnType (* name)
#endif

#ifndef NULL_PTR
#define NULL_PTR ((void *)0)
#endif

#include "pkcs11.h"

#endif /* _CRYPTOKI_H_ */
