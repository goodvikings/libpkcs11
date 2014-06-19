/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#ifndef TOKEN_H
#define	TOKEN_H

#include <sqlite3.h>
#include <map>
#include "p11.h"
#include "session.h"

#define TOKENFILENAMELEN 256

#define TOKENDESCLEN 64
#define TOKENLABELLEN 32
#define TOKENMANIDLEN 32
#define TOKENMODELLEN 16
#define TOKENSERIALLEN 16
#define TOKENMAXPINLEN 16
#define TOKENMINPINLEN 0
#define PINNOTINITIALIZED 0
#define PININITIALIZED 1

// INFO table
#define LABEL "label"
#define MANID "manID"
#define MODEL "model"
#define SERIAL "serial"
#define FLAGS "flags"
#define MAXPINLEN "MaxPinLen"
#define MINPINLEN "MinPinLen"
#define MAXSESSIONCOUNT "MaxSessionCount"
#define MAXRWSESSIONCOUNT "MaxRWSessionCount"
#define TOTALPUBMEM "TotalPubMem"
#define TOTALPRIVMEM "TotalPrivMem"
#define HWVERMAJOR "HWVerMajor"
#define HWVERMINOR "HWVerMinor"
#define FWVERMAJOR "FWVerMajor"
#define FWVERMINOR "FWVerMinor"

// PIN table
#define USERPIN "userPin"
#define SOPIN "soPin"
#define MAXRETRIES "MaxRetries"
#define CURRRETRIES "CurrRetries"
#define INITIALIZED "initialized"

class token
{
public:
	token();
	~token();
	bool open(const char* filename);

	bool getLabel(unsigned char* buff, unsigned int bufflen);
	bool getManID(unsigned char* buff, unsigned int bufflen);
	bool getModel(unsigned char* buff, unsigned int bufflen);
	bool getSerial(unsigned char* buff, unsigned int bufflen);
	bool getMaxSessionCount(int* i);
	bool getMaxRWSessionCount(int* i);
	bool getMaxPinLen(int* i);
	bool getMinPinLen(int* i);
	bool getTotalPubMem(int* i);
	bool getTotalPrivMem(int* i);
	bool getHWVerMajor(int* i);
	bool getHWVerMinor(int* i);
	bool getFWVerMajor(int* i);
	bool getFWVerMinor(int* i);

	CK_FLAGS getFlags();
	CK_STATE getState();

	bool isTokenInitialized();
	bool isPinInitialized();
	CK_RV login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, const unsigned char* pin, const int pinLen);
	CK_RV logout();
	CK_RV initToken(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
	CK_RV initUserPin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
	CK_RV setTokenPin(CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

	bool getMaxRetries(int* i);
	bool getCurrRetries(int* i);

	bool hasRWSOSession();
	CK_SESSION_HANDLE openSession(CK_SLOT_ID slotID, CK_FLAGS f);
	void getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
	void closeSession(CK_SESSION_HANDLE hSession);
	void closeAllSessions();
	bool isLoggedIn();

	CK_RV generateKey(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
	CK_RV generateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);

	bool hasSecretKeyByHandle(CK_OBJECT_HANDLE hKey);
	bool getSecretKeyData(CK_OBJECT_HANDLE hKey, unsigned char** buff, unsigned int* buffLen);
private:
	sqlite3 *db;
	char* filename;
	bool tokenInitialized;
	bool loggedIn;
	CK_STATE state;
	std::map<CK_SESSION_HANDLE, session*>* sessions;

	bool getInfoText(unsigned char* buff, unsigned int bufflen, const char* field);
	bool getInfoInt(int* i, const char* field);
	CK_SESSION_HANDLE getNextSessionHandle();
	bool checkPin(const unsigned char* pin, const int pinLen, bool isUser);
	bool isPinLocked();
	CK_RV initialize(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
	bool setPin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, bool isUser);
	void removeSessionObjects(CK_SESSION_HANDLE hSession);
	int getNextObjectHandle();
	
	bool saveObjectTemplate(const CK_ATTRIBUTE_PTR pTemplate, const CK_ULONG ulCount, const int handle);
	
	bool saveKey(const unsigned char* key, const int len, CK_SESSION_HANDLE pSession, const int handle);
};

#endif

