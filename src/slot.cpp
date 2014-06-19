/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include "slot.h"
#include "token.h"

std::vector<slot*>* slots = NULL;

slot::slot(CK_SLOT_ID id)
{
	this->id = id;
	t = NULL;
	sessions = new std::vector<CK_SESSION_HANDLE > ();
}

slot::~slot()
{
	delete sessions;
	if (t) delete t;
}

bool slot::open(const char* filename)
{
	bool rv = false;
	struct stat* buffer = new struct stat;

	if (stat (filename, buffer) == 0)
	{
		t = new token;
		rv = t->open(filename);
	} else
	{
		rv = false;
	}

	delete buffer;
	return rv;
}

bool slot::isTokenPresent()
{
	return !!t;
}

CK_RV slot::getTokenInfo(CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;
	unsigned char* buff = NULL;
	int i = 0;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	if (!rv && !isTokenPresent())
		return CKR_TOKEN_NOT_PRESENT;
	if (!rv)
		buff = new unsigned char[TOKENLABELLEN];
	if (!buff)
		return CKR_HOST_MEMORY;

	if (!rv && !t->getLabel(buff, TOKENLABELLEN))
		memcpy(pInfo->label, buff, TOKENLABELLEN);
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getManID(buff, TOKENLABELLEN))
		memcpy(pInfo->manufacturerID, buff, TOKENLABELLEN);
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getModel(buff, TOKENMODELLEN))
		memcpy(pInfo->model, buff, TOKENMODELLEN);
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getSerial(buff, TOKENSERIALLEN))
		memcpy(pInfo->serialNumber, buff, TOKENSERIALLEN);
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getMaxSessionCount(&i))
		pInfo->ulMaxSessionCount = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv)
		pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;

	if (!rv && !t->getMaxRWSessionCount(&i))
		pInfo->ulMaxRwSessionCount = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv)
		pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;

	if (!rv && !t->getMaxPinLen(&i))
		pInfo->ulMaxPinLen = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getMinPinLen(&i))
		pInfo->ulMinPinLen = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getTotalPubMem(&i))
		pInfo->ulTotalPublicMemory = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv)
		pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;

	if (!rv && !t->getTotalPrivMem(&i))
		pInfo->ulTotalPrivateMemory = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv)
		pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

	if (!rv && !t->getHWVerMajor(&i))
		pInfo->hardwareVersion.major = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getHWVerMinor(&i))
		pInfo->hardwareVersion.minor = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getFWVerMajor(&i))
		pInfo->firmwareVersion.major = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv && !t->getFWVerMinor(&i))
		pInfo->firmwareVersion.minor = i;
	else
		rv = CKR_DEVICE_ERROR;

	if (!rv)
		memcpy(pInfo->utcTime, "                ", 16);

	pInfo->flags = t->getFlags();

	if (buff) delete [] buff;
	return rv;
}

CK_RV slot::loginToken(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, const unsigned char* pin, const int pinLen)
{
	if (!isTokenPresent())
		return CKR_GENERAL_ERROR;
	return t->login(hSession, userType, pin, pinLen);
}

CK_RV slot::logout()
{
	return t->logout();
}

CK_RV slot::initToken(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (!isTokenPresent())
		return CKR_TOKEN_NOT_PRESENT;
	return t->initToken(pPin, ulPinLen, pLabel);
}

bool slot::getTokenFlags(CK_FLAGS* flags)
{
	if (!isTokenPresent())
		return false;
	else
	{
		*flags = t->getFlags();
		return false;
	}
}

CK_SESSION_HANDLE slot::openSession(CK_FLAGS f)
{
	if (!isTokenPresent())
		return -1;
	else
	{
		CK_SESSION_HANDLE h = t->openSession(id, f);
		sessions->push_back(h);
		return h;
	}
}

void slot::closeSession(CK_SESSION_HANDLE hSession)
{
	t->closeSession(hSession);

	for (std::vector<CK_SESSION_HANDLE>::iterator i = sessions->begin(); i != sessions->end(); i++)
	{
		if (hSession == *i)
		{
			sessions->erase(i);
			break;
		}
	}
}

void slot::closeAllSessions()
{
	t->closeAllSessions();

	sessions->clear();
}

bool slot::hasSession(CK_SESSION_HANDLE h)
{
	for (unsigned int i = 0; i < sessions->size(); i++)
	{
		if ((*sessions)[i] == h)
		{
			return true;
		}
	}

	return false;
}

bool slot::tokenHasRWSOSession()
{
	if (!isTokenPresent())
		return false;
	else
	{
		return t->hasRWSOSession();
	}
}

void slot::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (isTokenPresent() && hasSession(hSession))
		t->getSessionInfo(hSession, pInfo);
}

bool slot::isLoggedIn(CK_SESSION_HANDLE hSession)
{
	if (isTokenPresent() && hasSession(hSession))
		return t->isLoggedIn();
	else
		return CKR_SESSION_HANDLE_INVALID;
}

CK_STATE slot::getTokenState()
{
	if (isTokenPresent())
		return t->getState();
	else
		return CKS_RO_PUBLIC_SESSION;
}

CK_RV slot::initTokenUserPin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (isTokenPresent())
		return t->initUserPin(pPin, ulPinLen);
	else
		return CKR_TOKEN_NOT_PRESENT;
}

CK_RV slot::setTokenPin(CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	if (isTokenPresent())
		return t->setTokenPin(pOldPin, ulOldLen, pNewPin, ulNewLen);
	else
		return CKR_TOKEN_NOT_PRESENT;
}

CK_RV slot::generateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	if (isTokenPresent())
		return t->generateKey(hSession, pTemplate, ulCount, phKey);
	else
		return CKR_TOKEN_NOT_PRESENT;
}

CK_RV slot::generateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	if (isTokenPresent())
		return t->generateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
	else
		return CKR_TOKEN_NOT_PRESENT;
}

bool slot::tokenHasSecretKeyByHandle(CK_OBJECT_HANDLE hKey)
{
	if (isTokenPresent())
		return t->hasSecretKeyByHandle(hKey);
	else
		return CKR_DEVICE_ERROR; // Would normally return token not present, but not allowed for this function since we have a 'valid' key handle and therefore must have gotten it from a token
}

bool slot::getSecretKeyData(CK_OBJECT_HANDLE hKey, unsigned char** buff, unsigned int* buffLen)
{
	if (isTokenPresent() && t->hasSecretKeyByHandle(hKey))
		return t->getSecretKeyData(hKey, buff, buffLen);
	else
		return false;
}
