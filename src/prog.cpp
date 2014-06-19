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
#include <iomanip>
#include "p11.h"
using namespace std;

void generateKey(CK_SESSION_HANDLE_PTR phSession);
void generateKeyPair(CK_SESSION_HANDLE_PTR phSession);

int main(int argc, char** argv)
{
	unsigned long slotCount = 0;
	CK_SLOT_ID_PTR pSlotID = NULL_PTR;
	CK_SESSION_HANDLE hSession;

	assert(C_Initialize(NULL_PTR) == CKR_OK);
	assert(C_GetSlotList(false, pSlotID, &slotCount) == CKR_OK);

	pSlotID = new CK_SLOT_ID[slotCount];

	assert(C_GetSlotList(false, pSlotID, &slotCount) == CKR_OK);
	assert(C_OpenSession(pSlotID[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession) == CKR_OK);

	assert(C_Login(hSession, CKU_USER, (unsigned char*) "11223344", 8) == CKR_OK);

	//	generateKey(&hSession);

	generateKeyPair(&hSession);

	assert(C_Finalize(NULL_PTR) == CKR_OK);

	delete [] pSlotID;

	return 0;
}

void generateKey(CK_SESSION_HANDLE_PTR phSession)
{
	CK_OBJECT_HANDLE hObject;
	CK_MECHANISM mech ={CKM_AES_KEY_GEN, NULL, 0};

	CK_OBJECT_CLASS objclass = CKO_SECRET_KEY;
	CK_BBOOL f = false;

	CK_ATTRIBUTE temp[] ={
		{CKA_CLASS, &objclass, sizeof (objclass)},
		{CKA_TOKEN, &f, sizeof (f)}
	};




	assert(C_GenerateKey(*phSession, &mech, temp, 2, &hObject) == CKR_OK);
}

void generateKeyPair(CK_SESSION_HANDLE_PTR phSession)
{
	CK_OBJECT_HANDLE hPubKey;
	CK_OBJECT_HANDLE hPrivKey;
	CK_MECHANISM mech ={CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
	CK_BBOOL t = CK_TRUE;
	CK_KEY_TYPE pubKeyType = CKK_RSA;
	CK_BYTE exp[] ={0x01, 0x00, 0x01};
	CK_ULONG modBits = 512;

	CK_ATTRIBUTE pubTemplate[] ={
		{CKA_ENCRYPT, &t, sizeof (t)},
		{CKA_VERIFY, &t, sizeof (t)},
		{CKA_WRAP, &t, sizeof (t)},
		{CKA_KEY_TYPE, &pubKeyType, sizeof (pubKeyType)},
		{CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		{CKA_MODULUS_BITS, &modBits, sizeof (modBits)},
		{CKA_TOKEN, &t, sizeof (t)}
	};

	CK_ATTRIBUTE privTemplate[] ={
		{CKA_PRIVATE, &t, sizeof (t)},
		{CKA_SENSITIVE, &t, sizeof (t)},
		{CKA_DECRYPT, &t, sizeof (t)},
		{CKA_SIGN, &t, sizeof (t)},
		{CKA_UNWRAP, &t, sizeof (t)},
		{CKA_TOKEN, &t, sizeof (t)}
	};

	assert(C_GenerateKeyPair(*phSession, &mech, pubTemplate, sizeof (pubTemplate) / sizeof (CK_ATTRIBUTE), privTemplate, sizeof (privTemplate) / sizeof (CK_ATTRIBUTE), &hPubKey, &hPrivKey) == CKR_OK);
}
