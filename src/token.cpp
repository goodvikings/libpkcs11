/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo -at- goodvikings -dot- com> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day, and
 * you think this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <cstring>
#include <fstream>
#include <map>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sqlite3.h>
#include <string>
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

	if (db) sqlite3_close_v2(db);
}

bool token::open(const char* aFilename)
{
	const char header[16] ={0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00};
	char buff[16];
	int rc = 0;

	strncpy(this->filename, aFilename, TOKENFILENAMELEN);

	std::ifstream fin(aFilename);

	if (fin.good())
	{
		fin.getline(buff, 16);
		fin.close();
	}

	rc = sqlite3_open_v2(aFilename, &db, SQLITE_OPEN_READWRITE, NULL);

	if (!rc && !strncmp(buff, header, 16))
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

CK_STATE token::getState()
{
	return state;
}

bool token::getMaxSessionCount(unsigned int* i)
{
	return getInfoInt(i, MAXSESSIONCOUNT);
}

bool token::getMaxRWSessionCount(unsigned int* i)
{
	return getInfoInt(i, MAXRWSESSIONCOUNT);
}

bool token::getMaxPinLen(unsigned int* i)
{
	*i = TOKENMAXPINLEN;
	return false;
}

bool token::getMinPinLen(unsigned int* i)
{
	*i = TOKENMINPINLEN;
	return false;
}

bool token::getTotalPubMem(unsigned int* i)
{
	return getInfoInt(i, TOTALPUBMEM);
}

bool token::getTotalPrivMem(unsigned int* i)
{
	return getInfoInt(i, TOTALPRIVMEM);
}

bool token::getHWVerMajor(unsigned int* i)
{
	return getInfoInt(i, HWVERMAJOR);
}

bool token::getHWVerMinor(unsigned int* i)
{
	return getInfoInt(i, HWVERMINOR);
}

bool token::getFWVerMajor(unsigned int* i)
{
	return getInfoInt(i, FWVERMAJOR);
}

bool token::getFWVerMinor(unsigned int* i)
{
	return getInfoInt(i, FWVERMINOR);
}

bool token::isPinInitialized()
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	bool init = false;

	rc = sqlite3_prepare_v2(db, "select count(*) from pin where name=? and value=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, INITIALIZED, (int) strnlen(INITIALIZED, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, PININITIALIZED);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		init = sqlite3_column_int(stmt, 0) == PININITIALIZED;
	sqlite3_finalize(stmt);

	return init;
}

CK_RV token::login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, const unsigned char* pin, const int pinLen)
{
	CK_RV rv = CKR_OK;
	CK_SESSION_INFO_PTR pSessionInfo = new CK_SESSION_INFO;

	getSessionInfo(hSession, pSessionInfo);

	if (!rv && (!(pSessionInfo->flags & CKF_RW_SESSION) && userType == CKU_SO))
		rv = CKR_SESSION_READ_ONLY_EXISTS;
	if (!rv && !isPinInitialized() && userType == CKU_USER)
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

	if (!rv && isPinLocked())
	{
		rv = CKR_PIN_LOCKED;
	}

	if (!rv)
	{
		if (!checkPin(pin, pinLen, userType == CKU_USER))
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

CK_RV token::initToken(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	CK_RV rv = CKR_OK;

	if (sessions->size() != 0)
		return CKR_SESSION_EXISTS;

	if (tokenInitialized)
	{
		if (!rv && isPinLocked())
			rv = CKR_PIN_LOCKED;
		if (!rv && !checkPin(pPin, ulPinLen, false))
			rv = CKR_PIN_INCORRECT;
	}

	if (!rv)
		rv = initialize(pPin, ulPinLen, pLabel);

	return rv;
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

bool token::getInfoInt(unsigned int* i, const char* field)
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
	CK_SESSION_HANDLE handle = getNextSessionHandle();

	session* s = new session(handle, slotID);
	(*sessions)[handle] = s;

	f & CKF_RW_SESSION ? s->setRW() : s->setRO();

	state = f & CKF_RW_SESSION ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;

	return handle;
}

void token::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	(*sessions)[hSession]->getSessionInfo(pInfo);
}

void token::closeSession(CK_SESSION_HANDLE hSession)
{
	removeSessionObjects(hSession);

	delete (*sessions)[hSession];
	(*sessions)[hSession] = NULL;
}

void token::closeAllSessions()
{
	for (std::map<CK_SESSION_HANDLE, session*>::iterator i = sessions->begin(); i != sessions->end(); i++)
	{
		closeSession(i->first);
	}

	sessions->clear();
}

void token::removeSessionObjects(CK_SESSION_HANDLE hSession)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	const char* query = "delete from objectAttributes where handle in (select handle from objects where session=?);"
			"delete from objects where session=?;";
	const char** queryPtr = &query;

	rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);

	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hSession);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		sqlite3_finalize(stmt);

	if (rc == SQLITE_DONE)
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hSession);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		sqlite3_finalize(stmt);
}

CK_SESSION_HANDLE token::getNextSessionHandle()
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

bool token::checkPin(const unsigned char* pin, const int pinLen, bool isUser)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	bool valid = true;

	if (isPinLocked())
		return false;

	if (valid)
	{
		rc = sqlite3_prepare_v2(db, "select value from pin where name=? and value=?", -1, &stmt, NULL);
		if (!rc)
			rc = sqlite3_bind_text(stmt, 1, isUser ? USERPIN : SOPIN, strnlen(isUser ? USERPIN : SOPIN, 16), NULL);
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

bool token::isPinLocked()
{
	int max = 0;
	int curr = 0;

	getMaxRetries(&max);
	getCurrRetries(&curr);

	return curr >= max;
}

CK_RV token::initialize(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	const char* query = "CREATE TABLE if not exists info (name varchar(32) NOT NULL, value varchar(32) NOT NULL);"
			"delete from info;"
			"CREATE TABLE if not exists pin (name varchar(32) NOT NULL, value varchar(32) NOT NULL );"
			"delete from pin;"
			"CREATE TABLE if not exists objects (handle int NOT NULL, type int NOT NULL, session int, data blob, PRIMARY KEY (handle));"
			"delete from objects;"
			"CREATE TABLE if not exists objectAttributes (handle int NOT NULL, type int NOT NULL, data blob, FOREIGN KEY (handle) REFERENCES objects(handle));"
			"delete from objectAttributes;"
			"insert into info(name, value) values "
			"(?,?)," // label, 1, 2
			"(?,'Ramo')," // manid 3
			"(?,'PKCS11')," // model 4,
			"(?,'1234567890ABCDEF')," // serial 5
			"(?,'1024')," // flags 6
			"(?,'10')," // MaxSessionCount 7
			"(?,'10')," // MaxRWSessionCount 8
			"(?,'32768')," // TotalPubMem 9
			"(?,'32768')," // TotalPrivMem 10
			"(?,'16')," // MaxPinLen 11
			"(?,'0')," // MinPinLen 12
			"(?,'0')," // HWVerMajor 13
			"(?,'1')," // HWVerMinor 14
			"(?,'0')," // FWVerMajor 15
			"(?,'1');" // FWVerMinor 16
			"insert into pin(name, value) values "
			"(?, ?)," // userpin 1, 2
			"(?, ?)," // sopin 3, 4
			"(?, '10')," // maxretries 5
			"(?, '0')," // currretries 6
			"(?, '0');"; // initialized 7
	const char** queryPtr = &query;

	rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, LABEL, strnlen(LABEL, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 2, (const char*) pLabel, TOKENLABELLEN, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 3, MANID, strnlen(MANID, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 4, MODEL, strnlen(MODEL, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 5, SERIAL, strnlen(SERIAL, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 6, FLAGS, strnlen(FLAGS, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 7, MAXSESSIONCOUNT, strnlen(MAXSESSIONCOUNT, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 8, MAXRWSESSIONCOUNT, strnlen(MAXRWSESSIONCOUNT, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 9, TOTALPUBMEM, strnlen(TOTALPUBMEM, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 10, TOTALPRIVMEM, strnlen(TOTALPRIVMEM, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 11, MAXPINLEN, strnlen(MAXPINLEN, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 12, MINPINLEN, strnlen(MINPINLEN, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 13, HWVERMAJOR, strnlen(HWVERMAJOR, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 14, HWVERMINOR, strnlen(HWVERMINOR, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 15, FWVERMAJOR, strnlen(FWVERMAJOR, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 16, FWVERMINOR, strnlen(FWVERMINOR, 16), NULL);

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	}

	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, USERPIN, strnlen(USERPIN, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 2, "11223344", 8, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 3, SOPIN, strnlen(SOPIN, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 4, (const char*) pPin, ulPinLen, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 5, MAXRETRIES, strnlen(MAXRETRIES, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 6, CURRRETRIES, strnlen(CURRRETRIES, 16), NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 7, INITIALIZED, strnlen(INITIALIZED, 16), NULL);

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		return CKR_OK;
	}

	return CKR_DEVICE_ERROR;
}

CK_RV token::initUserPin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;

	unsigned int max, min;
	getMaxPinLen(&max);
	getMinPinLen(&min);

	if ((unsigned int) ulPinLen < min || (unsigned int) ulPinLen > max)
		rv = CKR_PIN_LEN_RANGE;
	if (!rv)
	{
		for (int i = 0; i < (int) ulPinLen; i++)
		{
			if (pPin[i] < 32 || pPin[i] > 126)
			{
				rv = CKR_PIN_INVALID;
				break;
			}
		}
	}

	if (!rv)
		if (!setPin(pPin, ulPinLen, CKU_USER))
			rv = CKR_DEVICE_ERROR;

	return rv;
}

bool token::setPin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, bool isUser)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "update pin set value=? where name=?;", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, (const char*) pPin, ulPinLen, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 2, isUser ? USERPIN : SOPIN, strnlen(isUser ? USERPIN : SOPIN, 16), NULL);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		sqlite3_finalize(stmt);

	if (isUser)
	{
		if (rc == SQLITE_DONE)
			rc = sqlite3_prepare_v2(db, "update pin set value=? where name=?", -1, &stmt, NULL);
		if (!rc)
			rc = sqlite3_bind_int(stmt, 1, PININITIALIZED);
		if (!rc)
			rc = sqlite3_bind_text(stmt, 2, INITIALIZED, strnlen(INITIALIZED, 16), NULL);
		if (!rc)
			rc = sqlite3_step(stmt);
		if (rc == SQLITE_DONE)
			sqlite3_finalize(stmt);
	}

	return rc == SQLITE_DONE;
}

CK_RV token::setTokenPin(CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_RV rv = CKR_OK;
	bool isUser = true;
	unsigned int max, min;
	getMaxPinLen(&max);
	getMinPinLen(&min);

	if (state == CKS_RW_SO_FUNCTIONS)
		isUser = false;

	if (!rv && ((unsigned int) ulNewLen < min || (unsigned int) ulNewLen > max))
		rv = CKR_PIN_LEN_RANGE;
	if (!rv)
	{
		for (int i = 0; i < (int) ulNewLen; i++)
		{
			if (pNewPin[i] < 32 || pNewPin[i] > 126)
			{
				rv = CKR_PIN_INVALID;
				break;
			}
		}
	}

	if (!rv && isPinLocked())
		rv = CKR_PIN_LOCKED;
	if (!rv && !checkPin(pOldPin, ulOldLen, isUser))
		rv = CKR_PIN_INCORRECT;

	if (!rv)
		if (!setPin(pNewPin, ulNewLen, isUser))
			rv = CKR_DEVICE_ERROR;

	return rv;
}

int token::getNextObjectHandle()
{
	sqlite3_stmt *stmt = NULL;
	int rc = 0;
	int val = -1;

	if (!rc)
		sqlite3_prepare_v2(db, "select max (handle) from objects", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
	{
		val = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt);
	}

	return val + 1;
}

CK_RV token::generateKey(CK_SESSION_HANDLE hSession, std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv = CKR_OK;

	unsigned long handle = getNextObjectHandle();

	unsigned char* key = NULL;
	int len = 0;
	bool persistentObject = false;

	persistentObject = *(CK_BBOOL*) (*defaultTemplate)[CKA_TOKEN]->pValue;
	len = *(CK_ULONG*) (*defaultTemplate)[CKA_VALUE_LEN]->pValue;

	if (len == 0)
	{
		switch (*(CK_KEY_TYPE*) (*defaultTemplate)[CKA_KEY_TYPE]->pValue)
		{
		case CKK_AES:
			len = 16;
			break;
		case CKK_DES:
			len = 8;
			break;
		case CKK_DES3:
			len = 24;
			break;
		}

		*(CK_ULONG*) (*defaultTemplate)[CKA_VALUE_LEN]->pValue = len;
	}

	if (!rv)
	{
		key = new unsigned char[len];
		rv = C_GenerateRandom(hSession, key, len);
	}

	if (!rv)
		if (!saveObject(key, len, persistentObject ? 0 : hSession, handle))
			rv = CKR_DEVICE_ERROR;

	if (!rv)
		if (!saveObjectAttributes(&handle, defaultTemplate))
			rv = CKR_DEVICE_ERROR;

	if (key) delete [] key;

	if (!rv)
		*phKey = handle;

	return rv;
}

CK_RV token::generateKeyPair(CK_SESSION_HANDLE hSession, std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* publicKeyTemplate, std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* privateKeyTemplate, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv = CKR_OK;

	unsigned long pubHandle = getNextObjectHandle();
	unsigned long privHandle = pubHandle + 1;
	int exp = 0;
	int modulusBits = 0;
	bool persistentObject = false;
	RSA *rsa = NULL;
	unsigned char* pubPEM = NULL;
	unsigned char* privPEM = NULL;
	int pubLen = 0;
	int privLen = 0;
	BIO* bio = NULL;

	modulusBits = *(CK_ULONG*) (*publicKeyTemplate)[CKA_MODULUS_BITS]->pValue;
	memcpy(&exp, (*publicKeyTemplate)[CKA_PUBLIC_EXPONENT]->pValue, (*publicKeyTemplate)[CKA_PUBLIC_EXPONENT]->ulValueLen);
	persistentObject = *(CK_BBOOL*) (*publicKeyTemplate)[CKA_TOKEN]->pValue;

	if (!modulusBits || !exp)
		rv = CKR_TEMPLATE_INCOMPLETE;

	if (!rv)
	{
		rsa = RSA_generate_key(modulusBits, exp, NULL, NULL);
		if (!rsa)
			rv = CKR_DEVICE_ERROR;
	}
	if (!rv)
	{
		bio = BIO_new(BIO_s_mem());
		if (!bio)
			rv = CKR_DEVICE_MEMORY;
	}
	if (!rv)
	{
		if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL))
			rv = CKR_DEVICE_ERROR;
	}
	if (!rv)
	{
		privLen = BIO_pending(bio);
		privPEM = new unsigned char[privLen + 1];
		if (!privPEM)
			rv = CKR_DEVICE_MEMORY;
	}
	if (!rv)
	{
		BIO_read(bio, privPEM, privLen);
		privPEM[privLen] = 0;
		if (!PEM_write_bio_RSAPublicKey(bio, rsa))
			rv = CKR_DEVICE_ERROR;
	}
	if (!rv)
	{
		pubLen = BIO_pending(bio);
		pubPEM = new unsigned char[pubLen + 1];
		if (!pubPEM)
			rv = CKR_DEVICE_MEMORY;
	}
	if (!rv)
	{
		BIO_read(bio, pubPEM, pubLen);
		pubPEM[pubLen] = 0;
	}

	if (!rv)
		if (!saveObject(pubPEM, pubLen, persistentObject ? 0 : hSession, pubHandle))
			rv = CKR_DEVICE_ERROR;
	if (!rv)
		if (!saveObject(privPEM, privLen, persistentObject ? 0 : hSession, privHandle))
			rv = CKR_DEVICE_ERROR;
	if (!rv)
		if (!saveObjectAttributes(&pubHandle, publicKeyTemplate))
			rv = CKR_DEVICE_ERROR;
	if (!rv)
		if (!saveObjectAttributes(&privHandle, privateKeyTemplate))
			rv = CKR_DEVICE_ERROR;

	if (!rv)
	{
		*phPublicKey = pubHandle;
		*phPrivateKey = privHandle;
	}

	if (bio) BIO_free_all(bio);
	if (rsa) RSA_free(rsa);
	if (pubPEM) delete [] pubPEM;
	if (privPEM) delete [] privPEM;

	return rv;
}

bool token::saveObject(const unsigned char* data, const int len, CK_SESSION_HANDLE session, const int handle)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "insert into objects(handle, type, session, data) values (?,?,?,?);", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, handle);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, CKO_SECRET_KEY);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 3, session);
	if (!rc)
		rc = sqlite3_bind_blob(stmt, 4, data, len, NULL);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		sqlite3_finalize(stmt);

	return rc == SQLITE_DONE;
}

bool token::hasObjectByHandle(CK_OBJECT_HANDLE hKey)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	bool validHandle = false;

	rc = sqlite3_prepare_v2(db, "select count(*) from objects where handle=? and type=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hKey);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, CKO_SECRET_KEY);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		validHandle = sqlite3_column_int(stmt, 0) == 1;
	sqlite3_finalize(stmt);

	return validHandle;
}

bool token::getObjectDataByHandle(CK_OBJECT_HANDLE hKey, unsigned char** buff, unsigned int* buffLen)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "select data from objects where handle=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hKey);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
	{
		*buffLen = sqlite3_column_bytes(stmt, 0);
		*buff = new unsigned char[*buffLen];

		memcpy(*buff, sqlite3_column_blob(stmt, 0), *buffLen);
	}

	sqlite3_finalize(stmt);

	return rc == SQLITE_ROW;
}

bool token::keyHasAttributeMatch(CK_OBJECT_HANDLE hKey, CK_ATTRIBUTE_TYPE attrType, void* value, int valueLen)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	bool flag = false;

	rc = sqlite3_prepare_v2(db, "select count(*) from objectAttributes where handle=? and type=? and data=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hKey);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, attrType);
	if (!rc)
		rc = sqlite3_bind_blob(stmt, 3, value, valueLen, NULL);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		flag = sqlite3_column_int(stmt, 0) == 1;
	sqlite3_finalize(stmt);

	return flag;
}

CK_KEY_TYPE token::getKeyTypeByHandle(CK_OBJECT_HANDLE hKey)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	unsigned char* buff = NULL;
	unsigned int buffLen = 0;
	unsigned long val = 0;

	rc = sqlite3_prepare_v2(db, "select data from objectAttributes where handle=? and type=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hKey);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, CKA_KEY_TYPE);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
	{
		buffLen = sqlite3_column_bytes(stmt, 0);
		buff = new unsigned char[buffLen];

		memcpy(&val, sqlite3_column_blob(stmt, 0), buffLen);
	}

	sqlite3_finalize(stmt);

	delete [] buff;

	return val;
}

bool token::getObjectAttributeDataByHandle(CK_OBJECT_HANDLE hKey, CK_ATTRIBUTE_TYPE attrType, void** buff, unsigned int* buffLen)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "select data from objectAttributes where handle=? and type=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hKey);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, attrType);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
	{
		*buffLen = sqlite3_column_bytes(stmt, 0);
		*buff = new unsigned char[*buffLen];

		memcpy(*buff, sqlite3_column_blob(stmt, 0), *buffLen);
	}

	sqlite3_finalize(stmt);

	return rc == SQLITE_ROW;
}

bool token::createObject(CK_SESSION_HANDLE session, std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* pTemplate, CK_OBJECT_HANDLE_PTR phObject)
{
	bool rv = false;
	unsigned long handle = getNextObjectHandle();

	rv = saveObject((unsigned char*) (*pTemplate)[CKA_VALUE]->pValue, (*pTemplate)[CKA_VALUE]->ulValueLen, *(CK_BBOOL*) (*pTemplate)[CKA_TOKEN]->pValue ? 0 : session, handle);

	if (rv)
	{
		rv = saveObjectAttributes(&handle, pTemplate);
	}

	return rv;
}

bool token::saveObjectAttributes(CK_OBJECT_HANDLE_PTR phKey, std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* pTemplate)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	for (std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator iter = pTemplate->begin(); iter != pTemplate->end() && !rc; iter++)
	{
		if (iter->first == CKA_VALUE)
			continue;

		rc = sqlite3_prepare_v2(db, "insert into objectAttributes(handle, type, data) values (?,?,?);", -1, &stmt, NULL);

		if (!rc)
			rc = sqlite3_bind_int(stmt, 1, *phKey);
		if (!rc)
			rc = sqlite3_bind_int(stmt, 2, iter->first);
		if (!rc)
			rc = sqlite3_bind_blob(stmt, 3, iter->second->pValue, iter->second->ulValueLen, NULL);
		if (!rc)
			rc = sqlite3_step(stmt);
		if (rc == SQLITE_DONE)
		{
			rc = SQLITE_OK;
			sqlite3_finalize(stmt);
		}
	}

	return rc == SQLITE_OK;
}

bool token::destroyObject(CK_OBJECT_HANDLE hObject)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	const char* query = "delete from objectAttributes where handle=?;"
			"delete from objects where handle=?;";
	const char** queryPtr = &query;

	rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);

	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hObject);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		sqlite3_finalize(stmt);

	if (rc == SQLITE_DONE)
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, hObject);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		sqlite3_finalize(stmt);

	return rc == SQLITE_DONE;
}

bool token::findObjects(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR* results, unsigned int* resultsLen)
{
	int rc = SQLITE_OK;
	char* WHERE = new char[7];
	char* AND = new char[5];
	sqlite3_stmt *stmt = NULL;
	std::string query;
	int loc = 0;

	// first get the count
	strncpy(WHERE, "where ", 7);
	AND[0] = 0;
	query = "select count(distinct(handle)) from objectAttributes ";

	for (unsigned int i = 0; i < ulCount; i++)
	{
		query += WHERE;
		query += AND;

		if (!i)
		{
			WHERE[0] = 0;
			strncpy(AND, "and ", 5);
		}

		query += "handle in (select handle from objectAttributes where type=? and data=?) ";
	}

	rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);

	for (unsigned int i = 0; i < ulCount && !rc; i++)
	{
		rc = sqlite3_bind_int(stmt, 2 * i + 1, pTemplate[i].type);
		if (!rc)
			rc = sqlite3_bind_blob(stmt, 2 * i + 2, pTemplate[i].pValue, pTemplate[i].ulValueLen, NULL);
	}

	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
	{
		rc = SQLITE_OK;
		*resultsLen = sqlite3_column_int(stmt, 0);
		*results = new CK_OBJECT_HANDLE[*resultsLen];
	}

	sqlite3_finalize(stmt);

	// we have the count, now we want the actual values
	if (!rc)
	{
		query.replace(7, 23, "distinct(handle)");

		rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);

		for (unsigned int i = 0; i < ulCount && !rc; i++)
		{
			rc = sqlite3_bind_int(stmt, 2 * i + 1, pTemplate[i].type);
			if (!rc)
				rc = sqlite3_bind_blob(stmt, 2 * i + 2, pTemplate[i].pValue, pTemplate[i].ulValueLen, NULL);
		}
	}

	if (!rc)
	{
		rc = sqlite3_step(stmt);

		while (rc == SQLITE_ROW)
		{
			(*results)[loc] = sqlite3_column_int(stmt, 0);

			loc++;
			rc = sqlite3_step(stmt);
		}
	}

	sqlite3_finalize(stmt);

	delete [] WHERE;
	delete [] AND;

	return true;
}

bool token::getObjectSize(CK_OBJECT_HANDLE handle, unsigned long* size)
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	rc = sqlite3_prepare_v2(db, "select length(data) from objects where handle=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, handle);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		*size = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);

	return rc == SQLITE_ROW;
}

CK_RV token::getAttributeValues(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG count)
{
	CK_RV rv = CKR_OK;
	int rc = SQLITE_OK;
	unsigned int length = 0;
	sqlite3_stmt *stmt = NULL;
	std::string query = "select data from objectAttributes where handle=? and type=?";

	for (unsigned int i = 0; i < count && !rc; i++)
	{
		rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
		if (!rc)
			rc = sqlite3_bind_int(stmt, 1, handle);
		if (!rc)
			rc = sqlite3_bind_int(stmt, 2, pTemplate[i].type);
		if (!rc)
			rc = sqlite3_step(stmt);
		if (rc == SQLITE_ROW)
		{
			length = sqlite3_column_bytes(stmt, 0);

			if (length > pTemplate[i].ulValueLen) // Allocation is not long enough
			{
				pTemplate[i].ulValueLen = length;
				if (pTemplate[i].pValue) // if they just wanted the length anyway
					rv = rv == CKR_OK ? CKR_BUFFER_TOO_SMALL : rv;
			} else
			{
				memcpy(pTemplate[i].pValue, sqlite3_column_blob(stmt, 0), length);
			}
			rc = SQLITE_OK;
		} else if (rc == SQLITE_DONE) // no rows found
		{
			rv = rv == CKR_OK ? CKR_ATTRIBUTE_TYPE_INVALID : rv;
			rc = SQLITE_OK;
		} else
		{
			rv = CKR_DEVICE_ERROR;
		}

		sqlite3_finalize(stmt);
	}

	return rv;
}

CK_RV token::setAttributeValues(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG count, bool isCopyingExisting)
{
	CK_RV rv = CKR_OK;
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	std::string query = "update objectAttributes set data=? where handle=? and type=?";

	for (unsigned int i = 0; i < count; i++)
	{
		switch (pTemplate[i].type)
		{
			// these three are read only depending on whether we are adjusting an existing 
			// object or copying an existing and making changes
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
			if (!isCopyingExisting)
			{
			case CKA_CLASS:
			case CKA_CERTIFICATE_TYPE:
			case CKA_TRUSTED:
			case CKA_SUBJECT:
			case CKA_VALUE:
			case CKA_URL:
			case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
			case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
			case CKA_JAVA_MIDP_SECURITY_DOMAIN:
			case CKA_OWNER:
			case CKA_KEY_TYPE:
			case CKA_LOCAL:
			case CKA_KEY_GEN_MECHANISM:
			case CKA_ALLOWED_MECHANISMS:
			case CKA_WRAP_TEMPLATE:
			case CKA_ALWAYS_SENSITIVE:
			case CKA_NEVER_EXTRACTABLE:
			case CKA_WRAP_WITH_TRUSTED:
			case CKA_UNWRAP_TEMPLATE:
			case CKA_ALWAYS_AUTHENTICATE:
			case CKA_CHECK_VALUE:
				rv = rv == CKR_OK ? CKR_ATTRIBUTE_READ_ONLY : rv;
				continue;
			}
			break;
		}

		rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
		if (!rc)
			rc = sqlite3_bind_blob(stmt, 1, pTemplate[i].pValue, pTemplate[i].ulValueLen, NULL);
		if (!rc)
			rc = sqlite3_bind_int(stmt, 2, handle);
		if (!rc)
			rc = sqlite3_bind_int(stmt, 3, pTemplate[i].type);
		if (!rc)
			rc = sqlite3_step(stmt);

		if (rc != SQLITE_DONE)
			if (sqlite3_changes(db) == 0)
				rv = rv == CKR_OK ? CKR_ATTRIBUTE_TYPE_INVALID : rv;

		sqlite3_finalize(stmt);
	}

	return rv;
}

CK_RV token::copyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG count, CK_OBJECT_HANDLE_PTR newHandle)
{
	CK_RV rv = CKR_OK;
	int rc = SQLITE_OK;
	bool* tokenObject = NULL;
	unsigned int len = 0;
	unsigned int nextHandle = getNextObjectHandle();
	sqlite3_stmt *stmt = NULL;
	const char* query = "insert into objects(handle, type, session, data) values (?, (select type from objects where handle=?), ?, (select data from objects where handle=?));"
			"insert into objectAttributes select ?, type, data from objectAttributes where handle=?;";
	const char** queryPtr = &query;

	// get whether the object we are copying is a permanent object
	getObjectAttributeDataByHandle(handle, CKA_TOKEN, (void**) &tokenObject, &len);

	// are we changing it's permanence?
	for (unsigned int i = 0; i < count; i++)
	{
		if (pTemplate[i].type == CKA_TOKEN)
		{
			memcpy(tokenObject, pTemplate[i].pValue, pTemplate[i].ulValueLen);
			break;
		}
	}

	rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, nextHandle);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, handle);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 3, *tokenObject ? 0 : session);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 4, handle);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		rc = SQLITE_OK;
	sqlite3_finalize(stmt);

	if (!rc)
		rc = sqlite3_prepare_v2(db, *queryPtr, -1, &stmt, queryPtr);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 1, nextHandle);
	if (!rc)
		rc = sqlite3_bind_int(stmt, 2, handle);
	if (!rc)
		rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		rc = SQLITE_OK;
	sqlite3_finalize(stmt);

	if (rc)
		rv = CKR_DEVICE_ERROR;

	if (!rv)
		rv = setAttributeValues(nextHandle, pTemplate, count, true);
	if (rv)
		destroyObject(nextHandle);
	else
		*newHandle = nextHandle;

	if (tokenObject) delete [] tokenObject;

	return rv;
}
