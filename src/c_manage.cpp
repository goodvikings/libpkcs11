/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo -at- goodvikings -dot- com> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day, and
 * you think this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include "log.h"
#include "p11.h"

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	rv = CKR_FUNCTION_NOT_SUPPORTED;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	rv = CKR_FUNCTION_NOT_SUPPORTED;

	LOG_RETURNCODE(rv);

	return rv;
}

