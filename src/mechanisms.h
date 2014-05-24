/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#ifndef MECHANISMS_H
#define	MECHANISMS_H

#include <map>
#include "p11.h"

class mechanisms
{
public:
	mechanisms();
	~mechanisms();

	CK_ULONG getSize();
	CK_RV getMachanismList(CK_MECHANISM_TYPE_PTR pType, CK_ULONG_PTR pCount);
	CK_RV getMechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
private:
	std::map<CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR> m;
};

#endif	/* MECHANISMS_H */

