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
	void closeSession(CK_SESSION_HANDLE hSession);
	void closeAllSessions();
	bool hasSession(CK_SESSION_HANDLE);
	bool tokenHasRWSOSession();
	void getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
	bool isLoggedIn(CK_SESSION_HANDLE hSession);
private:
	token* t;
	CK_SLOT_ID id;
	std::vector<CK_SESSION_HANDLE>* sessions;
};

#endif	/* SLOT_H */
