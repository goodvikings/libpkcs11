/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo -at- goodvikings -dot- com> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day, and
 * you think this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <fstream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include "mutex.h"
#include "p11.h"
#include "slot.h"
#include "mechanisms.h"
#include "log.h"
using namespace std;

// externs
extern std::vector<slot*>* slots;

//Local globals
CK_FUNCTION_LIST_PTR fListPtr = NULL;
bool cryptokiInitialized = false;
mechanisms* mechs = NULL;

// local functions
bool checkArgs(CK_C_INITIALIZE_ARGS_PTR args);
void buildFunctionList();
CK_RV loadSlots();

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	LOG_INSTANCE(getenv(PKCS11LOGFILEENV));
	LOG_FUNCTIONCALL();

	CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR) pInitArgs;
	CK_C_INITIALIZE_ARGS_PTR foo = NULL_PTR;
	CK_RV rv = CKR_OK;

	if (cryptokiInitialized)
		rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (!rv && !pInitArgs) // pInitArgs == NULL_PTR
	{
		foo = new CK_C_INITIALIZE_ARGS;

		foo->CreateMutex = NULL_PTR;
		foo->DestroyMutex = NULL_PTR;
		foo->LockMutex = NULL_PTR;
		foo->UnlockMutex = NULL_PTR;
		foo->flags = 0;
		foo->pReserved = NULL_PTR;

		args = foo;
	}

	if (!rv && !checkArgs(args))
		rv = CKR_ARGUMENTS_BAD;

	// Use the system locking, or the provided function pointers
	if (!rv)
	{
		if (args->CreateMutex == NULL_PTR) // checkArgs ensures that if one is set they all are
		{
			createMutex = mutex_create;
			destroyMutex = mutex_destroy;
			lockMutex = mutex_lock;
			unlockMutex = mutex_unlock;
		} else
		{
			createMutex = args->CreateMutex;
			destroyMutex = args->DestroyMutex;
			lockMutex = args->LockMutex;
			unlockMutex = args->UnlockMutex;
		}
	}

	if (!rv)
	{
		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();
	}

	if (foo) delete foo;

	if (!rv) cryptokiInitialized = true;

	if (!slots)
		slots = new std::vector<slot*>;

	if (!mechs)
		mechs = new mechanisms();

	buildFunctionList();
	rv = loadSlots();

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && pReserved)
		rv = CKR_ARGUMENTS_BAD;

	if (!rv)
	{
		cryptokiInitialized = false;
		if (fListPtr) delete fListPtr;
		if (mechs) delete mechs;
		if (slots)
		{
			for (unsigned int i = 0; i < slots->size(); i++)
			{
				(*slots)[i]->closeAllSessions();
				delete (*slots)[i];
			}
			delete slots;
		}
	}

	if (!rv)
	{
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();
		ERR_remove_state(0);
		EVP_cleanup();
	}

	LOG_RETURNCODE(rv);

	LOG_DESTROY();

	return rv;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && !pInfo)
		rv = CKR_ARGUMENTS_BAD;

	if (!rv)
	{
		pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
		pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
		memcpy(pInfo->manufacturerID, LIBMANID, 32);
		pInfo->flags = 0;
		memcpy(pInfo->libraryDescription, LIBLIBRARYDESC, 32);
		pInfo->libraryVersion.major = LIBVERSIONMAJOR;
		pInfo->libraryVersion.minor = LIBVERSIONMINOR;
	}

	LOG_RETURNCODE(rv);

	return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	LOG_INSTANCE(getenv(PKCS11LOGFILEENV));
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	if (!rv && !ppFunctionList)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv)
	{
		buildFunctionList();
		if (!fListPtr)
			rv = CKR_HOST_MEMORY;
	}

	*ppFunctionList = fListPtr;

	LOG_RETURNCODE(rv);

	return rv;
}

bool checkArgs(CK_C_INITIALIZE_ARGS_PTR args)
{
	bool rc = false;

	if (!args->CreateMutex && !args->DestroyMutex && !args->LockMutex && !args->UnlockMutex)
		rc = true;
	if (!rc && args->CreateMutex && args->DestroyMutex && args->LockMutex && args->UnlockMutex)
		rc = true;
	if (!args->pReserved)
		rc = true;

	return rc;
}

void buildFunctionList()
{
	if (fListPtr)
		return;

	fListPtr = new CK_FUNCTION_LIST;
	fListPtr->version.major = CRYPTOKI_VERSION_MAJOR;
	fListPtr->version.minor = CRYPTOKI_VERSION_MINOR;

	fListPtr->C_CancelFunction = &C_CancelFunction;
	fListPtr->C_CloseAllSessions = &C_CloseAllSessions;
	fListPtr->C_CloseSession = &C_CloseSession;
	fListPtr->C_CopyObject = &C_CopyObject;
	fListPtr->C_CreateObject = &C_CreateObject;
	fListPtr->C_Decrypt = &C_Decrypt;
	fListPtr->C_DecryptDigestUpdate = &C_DecryptDigestUpdate;
	fListPtr->C_DecryptFinal = &C_DecryptFinal;
	fListPtr->C_DecryptInit = &C_DecryptInit;
	fListPtr->C_DecryptUpdate = &C_DecryptUpdate;
	fListPtr->C_DecryptVerifyUpdate = &C_DecryptVerifyUpdate;
	fListPtr->C_DeriveKey = &C_DeriveKey;
	fListPtr->C_DestroyObject = &C_DestroyObject;
	fListPtr->C_Digest = &C_Digest;
	fListPtr->C_DigestEncryptUpdate = &C_DigestEncryptUpdate;
	fListPtr->C_DigestFinal = &C_DigestFinal;
	fListPtr->C_DigestInit = &C_DigestInit;
	fListPtr->C_DigestKey = &C_DigestKey;
	fListPtr->C_DigestUpdate = &C_DigestUpdate;
	fListPtr->C_Encrypt = &C_Encrypt;
	fListPtr->C_EncryptFinal = &C_EncryptFinal;
	fListPtr->C_EncryptInit = &C_EncryptInit;
	fListPtr->C_EncryptUpdate = &C_EncryptUpdate;
	fListPtr->C_Finalize = &C_Finalize;
	fListPtr->C_FindObjects = &C_FindObjects;
	fListPtr->C_FindObjectsFinal = &C_FindObjectsFinal;
	fListPtr->C_FindObjectsInit = &C_FindObjectsInit;
	fListPtr->C_GenerateKey = &C_GenerateKey;
	fListPtr->C_GenerateKeyPair = &C_GenerateKeyPair;
	fListPtr->C_GenerateRandom = &C_GenerateRandom;
	fListPtr->C_GetAttributeValue = &C_GetAttributeValue;
	fListPtr->C_GetFunctionList = &C_GetFunctionList;
	fListPtr->C_GetFunctionStatus = &C_GetFunctionStatus;
	fListPtr->C_GetInfo = &C_GetInfo;
	fListPtr->C_GetMechanismInfo = &C_GetMechanismInfo;
	fListPtr->C_GetMechanismList = &C_GetMechanismList;
	fListPtr->C_GetObjectSize = &C_GetObjectSize;
	fListPtr->C_GetOperationState = &C_GetOperationState;
	fListPtr->C_GetSessionInfo = &C_GetSessionInfo;
	fListPtr->C_GetSlotInfo = &C_GetSlotInfo;
	fListPtr->C_GetSlotList = &C_GetSlotList;
	fListPtr->C_GetTokenInfo = &C_GetTokenInfo;
	fListPtr->C_InitPIN = &C_InitPIN;
	fListPtr->C_InitToken = &C_InitToken;
	fListPtr->C_Initialize = &C_Initialize;
	fListPtr->C_Login = &C_Login;
	fListPtr->C_Logout = &C_Logout;
	fListPtr->C_OpenSession = &C_OpenSession;
	fListPtr->C_SeedRandom = &C_SeedRandom;
	fListPtr->C_SetAttributeValue = &C_SetAttributeValue;
	fListPtr->C_SetOperationState = &C_SetOperationState;
	fListPtr->C_SetPIN = &C_SetPIN;
	fListPtr->C_Sign = &C_Sign;
	fListPtr->C_SignEncryptUpdate = &C_SignEncryptUpdate;
	fListPtr->C_SignFinal = &C_SignFinal;
	fListPtr->C_SignInit = &C_SignInit;
	fListPtr->C_SignRecover = &C_SignRecover;
	fListPtr->C_SignRecoverInit = &C_SignRecoverInit;
	fListPtr->C_SignUpdate = &C_SignUpdate;
	fListPtr->C_UnwrapKey = &C_UnwrapKey;
	fListPtr->C_Verify = &C_Verify;
	fListPtr->C_VerifyFinal = &C_VerifyFinal;
	fListPtr->C_VerifyInit = &C_VerifyInit;
	fListPtr->C_VerifyRecover = &C_VerifyRecover;
	fListPtr->C_VerifyRecoverInit = &C_VerifyRecoverInit;
	fListPtr->C_VerifyUpdate = &C_VerifyUpdate;
	fListPtr->C_WaitForSlotEvent = &C_WaitForSlotEvent;
	fListPtr->C_WrapKey = &C_WrapKey;
}

CK_RV loadSlots()
{
	ifstream fin;
	const char* filename = getenv(PKCS11SLOTLISTENV);
	char* buff = new char[128];
	slot* s;
	CK_RV rc = CKR_OK;

	fin.open(filename, ios_base::in);

	if (!fin.is_open())
		rc = CKR_GENERAL_ERROR;

	if (!rc)
	{
		fin.getline(buff, SLOTFILENAMELEN, '\n');
		while (!fin.eof())
		{
			s = new slot(slots->size());
			s->open(buff);
			slots->push_back(s);

			fin.getline(buff, SLOTFILENAMELEN, '\n');
		}
	}

	fin.close();

	delete [] buff;

	return rc;
}
