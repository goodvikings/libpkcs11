/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo -at- goodvikings -dot- com> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day, and
 * you think this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

/*
 * This is just a testing driver for the library. To build the library, use
 * makefile.shared which leaves this out and builds a .so file.
 */

#include <iostream>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <iomanip>
#include "p11.h"
using namespace std;

unsigned char iv[] ={0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void generateKey(CK_SESSION_HANDLE_PTR phSession, CK_OBJECT_HANDLE_PTR pHandle);
void encrypt(CK_SESSION_HANDLE_PTR phSession, CK_OBJECT_HANDLE_PTR pHandle);
void generateKeyPair(CK_SESSION_HANDLE_PTR phSession);

int main(int argc, char** argv)
{
	unsigned long slotCount = 0;
	CK_SLOT_ID_PTR pSlotID = NULL_PTR;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE handle = 0;

	assert(C_Initialize(NULL_PTR) == CKR_OK);
	assert(C_GetSlotList(false, pSlotID, &slotCount) == CKR_OK);

	pSlotID = new CK_SLOT_ID[slotCount];

	assert(C_GetSlotList(false, pSlotID, &slotCount) == CKR_OK);
	assert(C_OpenSession(pSlotID[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession) == CKR_OK);

	assert(C_Login(hSession, CKU_USER, (unsigned char*) "11223344", 8) == CKR_OK);


	assert(C_Finalize(NULL_PTR) == CKR_OK);

	delete [] pSlotID;

	return 0;
}

void generateKey(CK_SESSION_HANDLE_PTR phSession, CK_OBJECT_HANDLE_PTR pHandle)
{
	CK_MECHANISM mech ={CKM_AES_KEY_GEN, NULL, 0};
	CK_OBJECT_CLASS objclass = CKO_SECRET_KEY;
	CK_BBOOL f = true;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ULONG valueLen = 32;

	CK_ATTRIBUTE temp[] ={
		{CKA_CLASS, &objclass, sizeof (objclass)},
		{CKA_TOKEN, &f, sizeof (f)},
		{CKA_KEY_TYPE, &keyType, sizeof (keyType)},
		{CKA_VALUE_LEN, &valueLen, sizeof (valueLen)}
	};

	assert(C_GenerateKey(*phSession, &mech, temp, sizeof (temp) / sizeof (CK_ATTRIBUTE), pHandle) == CKR_OK);
}

void encrypt(CK_SESSION_HANDLE_PTR phSession, CK_OBJECT_HANDLE_PTR pHandle)
{
	const unsigned char plain[] = "The quick brown fox jumps over the lazy dog";
	CK_MECHANISM mech ={CKM_AES_CBC, (char*) iv, 16};
	unsigned long len = 80;
	unsigned char* cipherText = new unsigned char[len];
	bzero(cipherText, len);
	unsigned char* out = new unsigned char[len];
	bzero(out, len);

	assert(C_GenerateRandom(*phSession, iv, 16) == CKR_OK);

	assert(C_EncryptInit(*phSession, &mech, *pHandle) == CKR_OK);

	assert(C_Encrypt(*phSession, (unsigned char*) plain, strnlen((char*) plain, 128), cipherText, &len) == CKR_OK);

	int cipherLen = len;
	len = 80;

	assert(C_DecryptInit(*phSession, &mech, *pHandle) == CKR_OK);

	assert(C_Decrypt(*phSession, cipherText, cipherLen, out, &len) == CKR_OK);


	for (unsigned int i = 0; i < len; i++)
		cout << out[i];
	cout << endl;



	delete [] cipherText;
	delete [] out;
}

void generateKeyPair(CK_SESSION_HANDLE_PTR phSession)
{
	CK_OBJECT_HANDLE hPubKey;
	CK_OBJECT_HANDLE hPrivKey;
	CK_MECHANISM mech ={CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
	CK_BBOOL t = CK_TRUE;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BYTE exp[] ={0x01, 0x00, 0x01};
	CK_ULONG modBits = 2048;

	CK_ATTRIBUTE pubTemplate[] ={
		{CKA_ENCRYPT, &t, sizeof (t)},
		{CKA_VERIFY, &t, sizeof (t)},
		{CKA_WRAP, &t, sizeof (t)},
		{CKA_KEY_TYPE, &keyType, sizeof (keyType)},
		{CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		{CKA_MODULUS_BITS, &modBits, sizeof (modBits)},
		{CKA_TOKEN, &t, sizeof (t)}
	};

	CK_ATTRIBUTE privTemplate[] ={
		{CKA_KEY_TYPE, &keyType, sizeof (keyType)},
		{CKA_PRIVATE, &t, sizeof (t)},
		{CKA_SENSITIVE, &t, sizeof (t)},
		{CKA_DECRYPT, &t, sizeof (t)},
		{CKA_SIGN, &t, sizeof (t)},
		{CKA_UNWRAP, &t, sizeof (t)},
		{CKA_TOKEN, &t, sizeof (t)}
	};

	assert(C_GenerateKeyPair(*phSession, &mech, pubTemplate, sizeof (pubTemplate) / sizeof (CK_ATTRIBUTE), privTemplate, sizeof (privTemplate) / sizeof (CK_ATTRIBUTE), &hPubKey, &hPrivKey) == CKR_OK);
}
