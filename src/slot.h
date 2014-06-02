/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#ifndef SLOT_H
#define	SLOT_H

#include <vector>
#include "token.h"
#include "p11.h"

#define SLOTFILENAMELEN TOKENFILENAMELEN

#define SLOTDESLEN 64
#define SLOTMANIDLEN LIBMANIDLEN

#define SLOTDESC "Ramo's PKCS11 Debugging Slot                                    "
#define SLOTMANID LIBMANID
#define SLOTVERSIONMAJOR	LIBVERSIONMAJOR
#define SLOTVERSIONMINOR	LIBVERSIONMINOR

class slot
{
public:
	slot(CK_SLOT_ID id);
	~slot();

	bool open(const char* filename);
	bool isTokenPresent();
	CK_RV getTokenInfo(CK_TOKEN_INFO_PTR pInfo);

	CK_RV loginToken(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, const unsigned char* pin, const int pinLen);
	CK_RV logout();
	bool getTokenFlags(CK_FLAGS* flags);
	CK_SESSION_HANDLE openSession(CK_FLAGS f);
	CK_RV initToken(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
	void closeSession(CK_SESSION_HANDLE hSession);
	void closeAllSessions();
	bool hasSession(CK_SESSION_HANDLE);
	bool tokenHasRWSOSession();
	void getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
	bool isLoggedIn(CK_SESSION_HANDLE hSession);
	CK_STATE getTokenState();
	CK_RV initTokenUserPin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
	CK_RV setTokenPin(CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

	CK_RV generateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
private:
	token* t;
	CK_SLOT_ID id;
	std::vector<CK_SESSION_HANDLE>* sessions;
};

#endif	/* SLOT_H */
