/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo -at- goodvikings -dot- com> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day, and
 * you think this stuff is worth it, you can buy me a beer in return - Ramo
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

static EVP_CIPHER_CTX* ctx = NULL;

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();
	CK_MECHANISM_INFO_PTR pMechInfo = new CK_MECHANISM_INFO;
	CK_BBOOL t = CK_TRUE;
	unsigned char* keyBuff = NULL;
	unsigned int keyBuffLen = 0;
	const EVP_CIPHER* cipher = NULL;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pMechanism)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && mechs->getMechanismInfo(pMechanism->mechanism, pMechInfo))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && !(pMechInfo->flags & CKF_ENCRYPT))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && ctx)
		rv = CKR_OPERATION_ACTIVE;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && !(*slots)[slot]->tokenHasSecretKeyByHandle(hKey))
		rv = CKR_KEY_HANDLE_INVALID;
	if (!rv && !mechs->keyValidForMechanism((*slots)[slot]->getKeyTypeByHandle(hKey), pMechanism->mechanism))
		rv = CKR_KEY_TYPE_INCONSISTENT;
	if (!rv && !(*slots)[slot]->keyHasAttributeMatch(hKey, CKA_ENCRYPT, &t, sizeof (t)))
		rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
	if (!rv && mechs->requiredIVSizeForMechanism(pMechanism->mechanism) != pMechanism->ulParameterLen)
		rv = CKR_MECHANISM_PARAM_INVALID;
	if (!rv && !(*slots)[slot]->getObjectData(hKey, &keyBuff, &keyBuffLen))
		rv = CKR_DEVICE_ERROR;

	if (!rv)
	{
		switch (pMechanism->mechanism)
		{
		case CKM_DES_ECB:
			cipher = EVP_des_ecb();
			break;
		case CKM_DES_CBC:
			cipher = EVP_des_cbc();
			break;
		case CKM_RC4:
			cipher = EVP_rc4();
			break;
		case CKM_DES3_ECB:
			cipher = EVP_des_ede3_ecb();
			break;
		case CKM_DES3_CBC:
			cipher = EVP_des_ede3_cbc();
			break;
		case CKM_AES_ECB:
			switch (keyBuffLen)
			{
			case 16:
				cipher = EVP_aes_128_ecb();
				break;
			case 24:
				cipher = EVP_aes_192_ecb();
				break;
			case 32:
				cipher = EVP_aes_256_ecb();
				break;
			default:
				rv = CKR_DEVICE_ERROR;
			}
			break;
		case CKM_AES_CBC:
			switch (keyBuffLen)
			{
			case 16:
				cipher = EVP_aes_128_cbc();
				break;
			case 24:
				cipher = EVP_aes_192_cbc();
				break;
			case 32:
				cipher = EVP_aes_256_cbc();
				break;
			default:
				rv = CKR_DEVICE_ERROR;
			}
			break;
		case CKM_AES_CTR:
			switch (keyBuffLen)
			{
			case 16:
				cipher = EVP_aes_128_ctr();
				break;
			case 24:
				cipher = EVP_aes_192_ctr();
				break;
			case 32:
				cipher = EVP_aes_256_ctr();
				break;
			default:
				rv = CKR_DEVICE_ERROR;
			}
			break;
		default:
			rv = CKR_MECHANISM_INVALID;
		}
	}

	if (!rv && !(ctx = EVP_CIPHER_CTX_new()))
		rv = CKR_DEVICE_MEMORY;
	if (!rv)
		EVP_CIPHER_CTX_init(ctx);


	if (!rv && !EVP_EncryptInit_ex(ctx, cipher, NULL, keyBuff, (const unsigned char*) pMechanism->pParameter))
		rv = CKR_DEVICE_ERROR;

	if (keyBuff) delete [] keyBuff;
	delete pMechInfo;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	unsigned long reqBuffLen = 0;

	unsigned long len = *pulEncryptedDataLen;
	unsigned long len2 = 0;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && !ctx)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv)
		reqBuffLen = ((ulDataLen / EVP_CIPHER_CTX_block_size(ctx)) + 1) * EVP_CIPHER_CTX_block_size(ctx);
	if (!rv && reqBuffLen > *pulEncryptedDataLen)
		rv = CKR_BUFFER_TOO_SMALL;
	if (!rv)
		rv = C_EncryptUpdate(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);

	if (!rv)
	{
		len2 = *pulEncryptedDataLen;
		len -= len2;

		rv = C_EncryptFinal(hSession, pEncryptedData + len2, &len);
	}

	*pulEncryptedDataLen = len + len2;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	unsigned int reqBuffLen = 0;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !ctx)
		rv = CKR_OPERATION_NOT_INITIALIZED;

	if (!rv)
		reqBuffLen = ((ulPartLen / EVP_CIPHER_CTX_block_size(ctx)) + 1) * EVP_CIPHER_CTX_block_size(ctx);

	if (!rv && pEncryptedPart && *pulEncryptedPartLen < reqBuffLen)
	{
		*pulEncryptedPartLen = reqBuffLen;
		rv = CKR_BUFFER_TOO_SMALL;
	}

	if (!rv && pEncryptedPart) // if pEncryptedPart is null, we only want the required buffer length
		if (!EVP_EncryptUpdate(ctx, pEncryptedPart, (int*) pulEncryptedPartLen, pPart, ulPartLen))
			rv = CKR_DEVICE_ERROR;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	unsigned int reqBuffLen = EVP_CIPHER_CTX_block_size(ctx);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !ctx)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv && pLastEncryptedPart && *pulLastEncryptedPartLen < reqBuffLen)
	{
		*pulLastEncryptedPartLen = reqBuffLen;
		rv = CKR_BUFFER_TOO_SMALL;
	}

	if (!rv && pLastEncryptedPart) // if pLastEncryptedPart is null, we only want the required buffer length
	{
		if (!EVP_EncryptFinal_ex(ctx, pLastEncryptedPart, (int*) pulLastEncryptedPartLen))
			rv = CKR_DEVICE_ERROR;
		if (!rv)
		{
			EVP_CIPHER_CTX_free(ctx);
			ctx = NULL;
		}
	}

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();
	CK_MECHANISM_INFO_PTR pMechInfo = new CK_MECHANISM_INFO;
	CK_BBOOL t = CK_TRUE;
	unsigned char* keyBuff = NULL;
	unsigned int keyBuffLen = 0;
	const EVP_CIPHER* cipher = NULL;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pMechanism)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && mechs->getMechanismInfo(pMechanism->mechanism, pMechInfo))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && !(pMechInfo->flags & CKF_DECRYPT))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && ctx)
		rv = CKR_OPERATION_ACTIVE;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && !(*slots)[slot]->tokenHasSecretKeyByHandle(hKey))
		rv = CKR_KEY_HANDLE_INVALID;
	if (!rv && !mechs->keyValidForMechanism((*slots)[slot]->getKeyTypeByHandle(hKey), pMechanism->mechanism))
		rv = CKR_KEY_TYPE_INCONSISTENT;
	if (!rv && !(*slots)[slot]->keyHasAttributeMatch(hKey, CKA_DECRYPT, &t, sizeof (t)))
		rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
	if (!rv && mechs->requiredIVSizeForMechanism(pMechanism->mechanism) != pMechanism->ulParameterLen)
		rv = CKR_MECHANISM_PARAM_INVALID;
	if (!rv && !(*slots)[slot]->getObjectData(hKey, &keyBuff, &keyBuffLen))
		rv = CKR_DEVICE_ERROR;

	if (!rv)
	{
		switch (pMechanism->mechanism)
		{
		case CKM_DES_ECB:
			cipher = EVP_des_ecb();
			break;
		case CKM_DES_CBC:
			cipher = EVP_des_cbc();
			break;
		case CKM_RC4:
			cipher = EVP_rc4();
			break;
		case CKM_DES3_ECB:
			cipher = EVP_des_ede3_ecb();
			break;
		case CKM_DES3_CBC:
			cipher = EVP_des_ede3_cbc();
			break;
		case CKM_AES_ECB:
			switch (keyBuffLen)
			{
			case 16:
				cipher = EVP_aes_128_ecb();
				break;
			case 24:
				cipher = EVP_aes_192_ecb();
				break;
			case 32:
				cipher = EVP_aes_256_ecb();
				break;
			default:
				rv = CKR_DEVICE_ERROR;
			}
			break;
		case CKM_AES_CBC:
			switch (keyBuffLen)
			{
			case 16:
				cipher = EVP_aes_128_cbc();
				break;
			case 24:
				cipher = EVP_aes_192_cbc();
				break;
			case 32:
				cipher = EVP_aes_256_cbc();
				break;
			default:
				rv = CKR_DEVICE_ERROR;
			}
			break;
		case CKM_AES_CTR:
			switch (keyBuffLen)
			{
			case 16:
				cipher = EVP_aes_128_ctr();
				break;
			case 24:
				cipher = EVP_aes_192_ctr();
				break;
			case 32:
				cipher = EVP_aes_256_ctr();
				break;
			default:
				rv = CKR_DEVICE_ERROR;
			}
			break;
		default:
			rv = CKR_MECHANISM_INVALID;
		}
	}

	if (!rv && !(ctx = EVP_CIPHER_CTX_new()))
		rv = CKR_DEVICE_MEMORY;
	if (!rv)
		EVP_CIPHER_CTX_init(ctx);


	if (!rv && !EVP_DecryptInit_ex(ctx, cipher, NULL, keyBuff, (const unsigned char*) pMechanism->pParameter))
		rv = CKR_DEVICE_ERROR;

	if (keyBuff) delete [] keyBuff;
	delete pMechInfo;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	unsigned long reqBuffLen = 0;
	unsigned long len = *pulDataLen;
	unsigned long len2 = 0;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && !ctx)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv)
		reqBuffLen = ((ulEncryptedDataLen / EVP_CIPHER_CTX_block_size(ctx)) + 1) * EVP_CIPHER_CTX_block_size(ctx);
	if (!rv && reqBuffLen > *pulDataLen)
		rv = CKR_BUFFER_TOO_SMALL;
	if (!rv)
		rv = C_DecryptUpdate(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);

	if (!rv)
	{
		len2 = *pulDataLen;
		len -= len2;

		rv = C_DecryptFinal(hSession, pData + len2, &len);
	}

	*pulDataLen = len + len2;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	unsigned int reqBuffLen = 0;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !ctx)
		rv = CKR_OPERATION_NOT_INITIALIZED;

	if (!rv)
		reqBuffLen = ((ulEncryptedPartLen / EVP_CIPHER_CTX_block_size(ctx)) + 1) * EVP_CIPHER_CTX_block_size(ctx);

	if (!rv && pPart && *pulPartLen < reqBuffLen)
	{
		*pulPartLen = reqBuffLen;
		rv = CKR_BUFFER_TOO_SMALL;
	}

	if (!rv && pPart) // if pPart is null, we only want the required buffer length
		if (!EVP_DecryptUpdate(ctx, pPart, (int*) pulPartLen, pEncryptedPart, ulEncryptedPartLen))
			rv = CKR_DEVICE_ERROR;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	unsigned int reqBuffLen = EVP_CIPHER_CTX_block_size(ctx);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !ctx)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv && pLastPart && *pulLastPartLen < reqBuffLen)
	{
		*pulLastPartLen = reqBuffLen;
		rv = CKR_BUFFER_TOO_SMALL;
	}

	if (!rv && pLastPart) // if pLastPart is null, we only want the required buffer length
	{
		if (!EVP_DecryptFinal_ex(ctx, pLastPart, (int*) pulLastPartLen))
			rv = CKR_DEVICE_ERROR;
		if (!rv)
		{
			EVP_CIPHER_CTX_free(ctx);
			ctx = NULL;
		}
	}

	LOG_RETURNCODE(rv);

	return rv;
}
