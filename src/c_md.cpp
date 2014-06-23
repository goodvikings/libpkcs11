/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include "log.h"
#include "mechanisms.h"
#include "p11.h"
#include "slot.h"
#include <openssl/evp.h>
#include <vector>

extern bool cryptokiInitialized;
extern std::vector<slot*>* slots;
extern mechanisms* mechs;

extern int getSlotBySession(CK_SESSION_HANDLE hSession);

EVP_MD_CTX *md = NULL;

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();
	CK_MECHANISM_INFO_PTR pMechInfo = new CK_MECHANISM_INFO;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pMechanism)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && mechs->getMechanismInfo(pMechanism->mechanism, pMechInfo))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && !(pMechInfo->flags & CKF_DIGEST))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && (pMechanism->pParameter || pMechanism->ulParameterLen > 0))
		rv = CKR_MECHANISM_PARAM_INVALID;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && md)
		rv = CKR_OPERATION_ACTIVE;

	if (!rv)
		md = EVP_MD_CTX_create();
	if (!rv && !md)
		rv = CKR_DEVICE_MEMORY;

	if (!rv)
	{
		int evprv = 0;

		switch (pMechanism->mechanism) {
		case CKM_MD5:
			evprv = EVP_DigestInit_ex(md, EVP_md5(), NULL);
			break;
		case CKM_SHA_1:
			evprv = EVP_DigestInit_ex(md, EVP_sha1(), NULL);
			break;
		case CKM_SHA256:
			evprv = EVP_DigestInit_ex(md, EVP_sha256(), NULL);
			break;
		case CKM_SHA384:
			evprv = EVP_DigestInit_ex(md, EVP_sha384(), NULL);
			break;
		case CKM_SHA512:
			evprv = EVP_DigestInit_ex(md, EVP_sha512(), NULL);
			break;
		case CKM_RIPEMD160:
			evprv = EVP_DigestInit_ex(md, EVP_ripemd160(), NULL);
			break;
		default: // shouldn't happen, we checked this already
			rv = CKR_MECHANISM_INVALID;
		}

		if (!evprv)
			rv = CKR_DEVICE_ERROR;
	}

	if (pMechInfo) delete pMechInfo;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	int reqBuffLen = EVP_MD_CTX_size(md);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !md)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv && pDigest && *pulDigestLen < (unsigned long) reqBuffLen)
		rv = CKR_BUFFER_TOO_SMALL;

	if (!rv)
		*pulDigestLen = reqBuffLen;

	if (!rv)
		if (!EVP_DigestUpdate(md, pData, ulDataLen))
			rv = CKR_DEVICE_ERROR;

	if (!rv && pDigest) // if pDigest is null, we only want the required buffer length
	{
		if (!EVP_DigestFinal_ex(md, pDigest, NULL))
			rv = CKR_DEVICE_ERROR;
		if (!rv)
		{
			EVP_MD_CTX_destroy(md);
			md = NULL;
		}
	}

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !md)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv && !pPart)
		rv = CKR_ARGUMENTS_BAD;

	if (!rv)
		if (!EVP_DigestUpdate(md, pPart, ulPartLen))
			rv = CKR_DEVICE_ERROR;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	unsigned char* buff = NULL;
	unsigned int buffLen = 0;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && !md)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !(*slots)[slot]->tokenHasSecretKeyByHandle(hKey))
		rv = CKR_KEY_HANDLE_INVALID;

	if (!rv)
		if (!(*slots)[slot]->getObjectData(hKey, &buff, &buffLen))
			rv = CKR_DEVICE_ERROR;
	if (!rv)
		rv = C_DigestUpdate(hSession, (CK_BYTE_PTR) buff, buffLen);

	if (buff) delete [] buff;
	
	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	int reqBuffLen = EVP_MD_CTX_size(md);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !md)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv && pDigest && *pulDigestLen < (unsigned long) reqBuffLen)
		rv = CKR_BUFFER_TOO_SMALL;

	if (!rv)
		*pulDigestLen = reqBuffLen;

	if (!rv && pDigest) // if pDigest is null, we only want the required buffer length
	{
		if (!EVP_DigestFinal_ex(md, pDigest, NULL))
			rv = CKR_DEVICE_ERROR;
		if (!rv)
		{
			EVP_MD_CTX_destroy(md);
			md = NULL;
		}
	}

	LOG_RETURNCODE(rv);

	return rv;
}
