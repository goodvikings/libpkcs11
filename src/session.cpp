/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <string.h>
#include "session.h"

session::session(CK_SESSION_HANDLE aHandle, CK_SLOT_ID slotID)
{
	this->handle = aHandle;

	pInfo = new CK_SESSION_INFO;

	pInfo->slotID = slotID;
	pInfo->state = CKS_RO_PUBLIC_SESSION;
	pInfo->ulDeviceError = 0;
	pInfo->flags = 0;
}

session::~session()
{
	delete pInfo;
}

void session::getSessionInfo(CK_SESSION_INFO_PTR out)
{
	if (out)
		memcpy(out, pInfo, sizeof (CK_SESSION_INFO));
}

void session::setRW()
{
	pInfo->flags |= CKF_RW_SESSION;
}

void session::setRO()
{
	pInfo->flags &= ~(unsigned long) CKF_RW_SESSION;
}

void session::logout()
{
	pInfo->state = (pInfo->state == CKS_RW_SO_FUNCTIONS || pInfo->state == CKS_RW_USER_FUNCTIONS) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
}
