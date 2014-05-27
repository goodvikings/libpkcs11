/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include "log.h"
#include "p11.h"
#include "slot.h"
#include <openssl/rand.h>
#include <vector>

extern bool cryptokiInitialized;
extern std::vector<slot*>* slots;

extern int getSlotBySession(CK_SESSION_HANDLE hSession);

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();

	if (!cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && !pSeed)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && (state == CKS_RO_PUBLIC_SESSION || state == CKS_RW_PUBLIC_SESSION))
		rv = CKR_USER_NOT_LOGGED_IN;

	if (!rv)
		RAND_seed(pSeed, ulSeedLen);

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();

	if (!cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && !RandomData)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && (state == CKS_RO_PUBLIC_SESSION || state == CKS_RW_PUBLIC_SESSION))
		rv = CKR_USER_NOT_LOGGED_IN;

	if (!rv)
	{
		int ret = RAND_bytes(RandomData, ulRandomLen);
		if (ret == 0)
			rv = CKR_DEVICE_ERROR;
	}
	LOG_RETURNCODE(rv);

	return rv;
}

