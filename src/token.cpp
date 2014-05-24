/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <sqlite3.h>
#include <string.h>
#include <map>
#include "p11.h"
#include "session.h"
#include "token.h"

token::token()
{
	filename = new char[TOKENFILENAMELEN];
	db = NULL;
	tokenInitialized = false;
	loggedIn = false;
	sessions = new std::map<CK_SESSION_HANDLE, session*>();

	state = CKS_RO_PUBLIC_SESSION;
}

token::~token()
{
	delete [] filename;

	for (std::map<CK_SESSION_HANDLE, session*>::iterator i = sessions->begin(); i != sessions->end(); i++)
	{
		delete i->second;
	}

	delete sessions;
	if (db) sqlite3_close(db);
}

bool token::open(const char* filename)
{
	strncpy(this->filename, filename, TOKENFILENAMELEN);

	int rc = 0;
	rc = sqlite3_open_v2(filename, &db, SQLITE_OPEN_READWRITE, NULL);

	int i = getFlags();
	if (!rc && ((i & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED))
		tokenInitialized = true;

	return rc;
}

bool token::getLabel(unsigned char* buff, unsigned int bufflen)
{
	return bufflen < TOKENLABELLEN ? false : getInfoText(buff, bufflen, LABEL);
}

bool token::getManID(unsigned char* buff, unsigned int bufflen)
{
	return bufflen < TOKENMANIDLEN ? false : getInfoText(buff, bufflen, MANID);
}

bool token::getModel(unsigned char* buff, unsigned int bufflen)
{
	return bufflen < TOKENMODELLEN ? false : getInfoText(buff, bufflen, MODEL);
}

bool token::getSerial(unsigned char* buff, unsigned int bufflen)
{
	return bufflen < TOKENSERIALLEN ? false : getInfoText(buff, bufflen, SERIAL);
}

CK_FLAGS token::getFlags()
{
	CK_FLAGS flags = 0;
	int currRetry = 0;
	int maxRetry = 0;

	getMaxRetries(&maxRetry);
	getCurrRetries(&currRetry);

	flags += CKF_RNG;
	flags += CKF_LOGIN_REQUIRED;

	if (isPinInitialized())
		flags += CKF_USER_PIN_INITIALIZED;

	if (isTokenInitialized())
		flags += CKF_TOKEN_INITIALIZED;

	if (currRetry > 0)
		flags += CKF_USER_PIN_COUNT_LOW + CKF_SO_PIN_COUNT_LOW;

	if (currRetry + 1 == maxRetry)
		flags += CKF_USER_PIN_FINAL_TRY + CKF_SO_PIN_FINAL_TRY;

	if (currRetry == maxRetry)
		flags += CKF_USER_PIN_LOCKED + CKF_SO_PIN_LOCKED;

	return flags;
}

bool token::getMaxSessionCount(int* i)
{
	return getInfoInt(i, MAXSESSIONCOUNT);
}

bool token::getMaxRWSessionCount(int* i)
{
	return getInfoInt(i, MAXRWSESSIONCOUNT);
}

bool token::getMaxPinLen(int* i)
{
	*i = MAXPINLEN;
	return false;
}

bool token::getMinPinLen(int* i)
{
	*i = MINPINLEN;
	return false;
}

bool token::getTotalPubMem(int* i)
{
	return getInfoInt(i, TOTALPUBMEM);
}

bool token::getTotalPrivMem(int* i)
{
	return getInfoInt(i, TOTALPRIVMEM);
}

bool token::getHWVerMajor(int* i)
{
	return getInfoInt(i, HWVERMAJOR);
}

bool token::getHWVerMinor(int* i)
{
	return getInfoInt(i, HWVERMINOR);
}

bool token::getFWVerMajor(int* i)
{
	return getInfoInt(i, FWVERMAJOR);
}

bool token::getFWVerMinor(int* i)
{
	return getInfoInt(i, FWVERINOR);
}

bool token::isPinInitialized()
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	bool init = false;

	rc = sqlite3_prepare_v2(db, "select value from pin where name=? and value=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, INITIALIZED, strnlen(INITIALIZED, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, PININITIALIZED);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW)
		init = true;
	sqlite3_finalize(stmt);

	return init;
}

CK_RV token::login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, const unsigned char* pin, const int pinLen)
{
	CK_RV rv = CKR_OK;
	CK_SESSION_INFO_PTR pSessionInfo = new CK_SESSION_INFO;
	int max = 0;
	int curr = 0;

	getSessionInfo(hSession, pSessionInfo);

	if (!rv && (!(pSessionInfo->flags & CKF_RW_SESSION) && userType == CKU_SO))
		rv = CKR_SESSION_READ_ONLY_EXISTS;
	if (!rv && !isPinInitialized())
		rv = CKR_USER_PIN_NOT_INITIALIZED;

	if (!rv && loggedIn)
	{
		if (userType == CKU_SO && (state == CKS_RO_USER_FUNCTIONS || state == CKS_RO_USER_FUNCTIONS))
			rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		else if (userType == CKU_USER && state == CKS_RW_SO_FUNCTIONS)
			rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		else
			rv = CKR_USER_ALREADY_LOGGED_IN;
	}

	if (!rv)
	{
		getMaxRetries(&max);
		getCurrRetries(&curr);

		if (curr >= max)
			rv = CKR_PIN_LOCKED;
	}

	if (!rv)
	{
		if (!checkPin(pin, pinLen))
			rv = CKR_PIN_INCORRECT;
		else
		{
			loggedIn = true;
			if (pSessionInfo->flags & CKF_RW_SESSION)
			{
				state = userType == CKU_SO ? CKS_RW_SO_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
			} else
			{
				state = CKS_RO_USER_FUNCTIONS;
			}
		}
	}

	delete pSessionInfo;

	return rv;
}

CK_RV token::logout()
{
	loggedIn = false;
	state = (state == CKS_RW_SO_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;

	for (std::map<CK_SESSION_HANDLE, session*>::iterator i = sessions->begin(); i != sessions->end(); i++)
	{
		i->second->logout();
	}
	
	return CKR_OK;
}

bool token::getMaxRetries(int* i)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "select value from pin where name=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, MAXRETRIES, strnlen(MAXRETRIES, 16), NULL);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		*i = sqlite3_column_int(stmt, 0);

	rc = sqlite3_finalize(stmt);

	return rc;
}

bool token::getCurrRetries(int* i)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "select value from pin where name=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, CURRRETRIES, strnlen(CURRRETRIES, 16), NULL);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		*i = sqlite3_column_int(stmt, 0);

	rc = sqlite3_finalize(stmt);

	return rc;
}

bool token::getInfoText(unsigned char* buff, unsigned int bufflen, const char* field)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "select value from info where name=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, field, strnlen(field, 16), NULL);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		memcpy(buff, sqlite3_column_text(stmt, 0), bufflen);

	rc = sqlite3_finalize(stmt);

	return rc;
}

bool token::getInfoInt(int* i, const char* field)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "select value from info where name=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, field, strnlen(field, 16), NULL);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		*i = sqlite3_column_int(stmt, 0);

	rc = sqlite3_finalize(stmt);

	return rc;
}

bool token::isTokenInitialized()
{
	return tokenInitialized;
}

bool token::hasRWSOSession()
{
	return state == CKS_RW_SO_FUNCTIONS;
}

CK_SESSION_HANDLE token::openSession(CK_SLOT_ID slotID, CK_FLAGS f)
{
	CK_SESSION_HANDLE handle = getNextHandle();

	session* s = new session(handle, slotID);
	(*sessions)[handle] = s;

	f & CKF_RW_SESSION ? s->setRW() : s->setRO();

	return handle;
}

void token::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	(*sessions)[hSession]->getSessionInfo(pInfo);
}

void token::closeSession(CK_SESSION_HANDLE hSession)
{
	delete (*sessions)[hSession];
	(*sessions)[hSession] = NULL;
}

void token::closeAllSessions()
{
	for (std::map<CK_SESSION_HANDLE, session*>::iterator i = sessions->begin(); i != sessions->end(); i++)
	{
		delete i->second;
	}

	sessions->clear();
}

CK_SESSION_HANDLE token::getNextHandle()
{
	for (std::map<CK_SESSION_HANDLE, session*>::iterator i = sessions->begin(); i != sessions->end(); i++)
	{
		if (i->second == NULL_PTR)
		{
			return i->first;
		}
	}

	return sessions->size() + 1;
}

bool token::checkPin(const unsigned char* pin, const int pinLen)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	bool valid = true;
	int max = 0;
	int curr = 0;

	// check whether we are allowed to attempt a login
	getMaxRetries(&max);
	getCurrRetries(&curr);

	if (curr >= max)
		return false;

	if (valid)
	{
		rc = sqlite3_prepare_v2(db, "select value from pin where name=? and value=?", -1, &stmt, NULL);
		if (!rc)
			rc = sqlite3_bind_text(stmt, 1, USERPIN, strnlen(USERPIN, 16), NULL);
		if (!rc)
			rc = sqlite3_bind_text(stmt, 2, (const char*) pin, pinLen, NULL);
		if (!rc)
			rc = sqlite3_step(stmt);
		if (rc != SQLITE_ROW)
			valid = false;
		sqlite3_finalize(stmt);
	}

	if (!valid) // login failed, increment retries
	{
		rc = sqlite3_prepare_v2(db, "update pin set value=value + 1 where name=?", -1, &stmt, NULL);
		if (!rc)
			rc = sqlite3_bind_text(stmt, 1, CURRRETRIES, strnlen(CURRRETRIES, 16), NULL);
		if (!rc)
			rc = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	} else
	{ // reset the count to 0
		rc = sqlite3_prepare_v2(db, "update pin set value=\"0\" where name=?", -1, &stmt, NULL);
		if (!rc)
			rc = sqlite3_bind_text(stmt, 1, CURRRETRIES, strnlen(CURRRETRIES, 16), NULL);
		if (!rc)
			rc = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}

	return valid;
}

bool token::isLoggedIn()
{
	return loggedIn;
}
