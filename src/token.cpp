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
#include <iosfwd>
#include <iomanip>
#include <ios>
#include <fstream>
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
	const char header[16] ={0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00};
	char buff[16];
	int rc = 0;

	strncpy(this->filename, filename, TOKENFILENAMELEN);

	std::ifstream fin(filename);

	if (fin.good())
	{
		fin.getline(buff, 16);
		fin.close();
	}

	rc = sqlite3_open_v2(filename, &db, SQLITE_OPEN_READWRITE, NULL);

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
	*i = TOKENMAXPINLEN;
	return false;
}

bool token::getMinPinLen(int* i)
{
	*i = TOKENMINPINLEN;
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
	return getInfoInt(i, FWVERMINOR);
}

bool token::isPinInitialized()
{
	int rc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;
	bool init = false;

	rc = sqlite3_prepare_v2(db, "select count(*) from pin where name=? and value=?", -1, &stmt, NULL);
	if (!rc)
		rc = sqlite3_bind_text(stmt, 1, INITIALIZED, strnlen(INITIALIZED, 16), NULL);
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

	state = f & CKF_RW_SESSION ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	
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

	int max, min;
	getMaxPinLen(&max);
	getMinPinLen(&min);

	if ((int) ulPinLen < min || (int) ulPinLen > max)
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
	int max, min;
	getMaxPinLen(&max);
	getMinPinLen(&min);

	if (state == CKS_RW_SO_FUNCTIONS)
		isUser = false;

	if (!rv && ((int) ulNewLen < min || (int) ulNewLen > max))
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
		if(!setPin(pNewPin, ulNewLen, isUser))
			rv = CKR_DEVICE_ERROR;
	
	return rv;
}
