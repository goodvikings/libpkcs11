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
#include "slot.h"

extern bool cryptokiInitialized;
extern std::vector<slot*>* slots;

int getSlotBySession(CK_SESSION_HANDLE hSession);

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	CK_FLAGS f = 0;
	CK_SESSION_HANDLE_PTR sessionPtr = NULL_PTR;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slotID >= slots->size())
		rv = CKR_SLOT_ID_INVALID;
	if (!rv && !(*slots)[slotID]->isTokenPresent())
		rv = CKR_TOKEN_NOT_PRESENT;
	if (!rv && !(*slots)[slotID]->getTokenFlags(&f) && (f & CKF_WRITE_PROTECTED))
		rv = CKR_TOKEN_WRITE_PROTECTED;
	if (!rv && !(flags & CKF_SERIAL_SESSION))
		rv = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	if (!rv && !phSession)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && (*slots)[slotID]->tokenHasRWSOSession())
		rv = CKR_SESSION_READ_WRITE_SO_EXISTS;

	if (!rv)
	{
		sessionPtr = new CK_SESSION_HANDLE;
	}
	if (!rv && !sessionPtr)
		rv = CKR_HOST_MEMORY;

	if (!rv)
	{
		*sessionPtr = (*slots)[slotID]->openSession(flags);
		*phSession = *sessionPtr;
		if (*sessionPtr == NULL_PTR)
			rv = CKR_GENERAL_ERROR;
	}

	if (sessionPtr) delete sessionPtr;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;

	if (!rv)
	{
		(*slots)[slot]->closeSession(hSession);
	}

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slotID >= slots->size())
		rv = CKR_SLOT_ID_INVALID;
	if (!rv && !(*slots)[slotID]->isTokenPresent())
		rv = CKR_TOKEN_NOT_PRESENT;

	if (!rv)
	{
		(*slots)[slotID]->closeAllSessions();
	}

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pInfo)
		return CKR_ARGUMENTS_BAD;

	(*slots)[slot]->getSessionInfo(hSession, pInfo);

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	rv = CKR_STATE_UNSAVEABLE;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	rv = CKR_SAVED_STATE_INVALID;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pPin)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && userType == CKU_CONTEXT_SPECIFIC)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv && (userType != CKU_SO && userType != CKU_USER))
		rv = CKR_USER_TYPE_INVALID;

	if (!rv)
	{
		rv = (*slots)[slot]->loginToken(hSession, userType, pPin, ulPinLen);
	}

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !(*slots)[slot]->isLoggedIn(hSession))
		rv = CKR_USER_NOT_LOGGED_IN;

	if (!rv)
		rv = (*slots)[slot]->logout();

	LOG_RETURNCODE(rv);

	return rv;
}

int getSlotBySession(CK_SESSION_HANDLE hSession)
{
	for (unsigned int i = 0; i < slots->size(); i++)
	{
		if ((*slots)[i]->hasSession(hSession))
		{
			return i;
		}
	}

	return -1;
}
