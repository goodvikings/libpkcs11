/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#ifndef SESSION_H
#define	SESSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "p11.h"

class session
{
public:
	session(CK_SESSION_HANDLE handle, CK_SLOT_ID slotID);
	~session();
	
	void getSessionInfo(CK_SESSION_INFO_PTR out);
	bool hasRWSOSession();
	void setRW();
	void setRO();
	void logout();
private:
	CK_SESSION_HANDLE handle;
	CK_SESSION_INFO_PTR pInfo;
	
	// will need temporary objects
};

#ifdef __cplusplus
}
#endif

#endif	/* SESSION_H */
