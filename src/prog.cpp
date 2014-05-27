/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <iostream>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "p11.h"
using namespace std;

int main(int argc, char** argv)
{
	unsigned long slotCount = 0;
	CK_SLOT_ID_PTR pSlotID = NULL_PTR;
	CK_SLOT_INFO_PTR pSlotInfo = new CK_SLOT_INFO;
	CK_TOKEN_INFO_PTR pTokenInfo = new CK_TOKEN_INFO;
	CK_SESSION_HANDLE_PTR pSessionHandle = new CK_SESSION_HANDLE;
	unsigned char* randData = new unsigned char[1024*1024*1024];
	
	
	assert(C_Initialize(NULL_PTR) == CKR_OK);

	assert(C_GetSlotList(false, pSlotID, &slotCount) == CKR_OK);
	pSlotID = new CK_SLOT_ID[slotCount];
	assert(C_GetSlotList(false, pSlotID, &slotCount) == CKR_OK);

	assert(C_GetSlotInfo(pSlotID[0], pSlotInfo) == CKR_OK);

	assert(C_GetTokenInfo(pSlotID[0], pTokenInfo) == CKR_OK);

	assert(C_OpenSession(pSlotID[0], CKF_SERIAL_SESSION, NULL, NULL, pSessionHandle) == CKR_OK);

	assert(C_Login(*pSessionHandle, CKU_USER, (unsigned char*) "11223344", 8) == CKR_OK);

	assert(C_GenerateRandom(*pSessionHandle, randData, 1024*1024*1024) == CKR_OK);
	
	
	
	
	
	
	
	
	
	



	assert(C_Finalize(NULL_PTR) == CKR_OK);

	delete [] randData;
	delete [] pSlotID;
	delete pSlotInfo;
	delete pTokenInfo;
	delete pSessionHandle;

	return 0;
}
