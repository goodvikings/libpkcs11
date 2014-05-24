/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include "log.h"
#include "p11.h"

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();
	
	CK_RV rv = CKR_OK;
	
	rv = CKR_FUNCTION_NOT_SUPPORTED;
	
	LOG_RETURNCODE(rv);
	
	return rv;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();
	
	CK_RV rv = CKR_OK;
	
	rv = CKR_FUNCTION_NOT_SUPPORTED;
	
	LOG_RETURNCODE(rv);
	
	return rv;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();
	
	CK_RV rv = CKR_OK;
	
	rv = CKR_FUNCTION_NOT_SUPPORTED;
	
	LOG_RETURNCODE(rv);
	
	return rv;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();
	
	CK_RV rv = CKR_OK;
	
	rv = CKR_FUNCTION_NOT_SUPPORTED;
	
	LOG_RETURNCODE(rv);
	
	return rv;
}

