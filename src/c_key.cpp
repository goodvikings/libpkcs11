/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include "log.h"
#include "mechanisms.h"
#include "p11.h"
#include "slot.h"
#include <map>
#include <vector>
#include <string.h>
#include <iostream>

extern bool cryptokiInitialized;
extern std::vector<slot*>* slots;
extern mechanisms* mechs;

extern int getSlotBySession(CK_SESSION_HANDLE hSession);

CK_RV checkGenerateKeyAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_MECHANISM_TYPE mechType, CK_ATTRIBUTE_PTR fullTemplate);
bool populateDefaultGenerateKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* dest, const CK_MECHANISM_TYPE mechanism);
bool mapAttribute(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* dest, const CK_ATTRIBUTE src);

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	int fullTempleteLen = 29;
	CK_STATE state = (*slots)[slot]->getTokenState();
	CK_MECHANISM_INFO_PTR pMechInfo = new CK_MECHANISM_INFO;
	CK_ATTRIBUTE_PTR fullTemplate = new CK_ATTRIBUTE[fullTempleteLen];

	memset(fullTemplate, 0, sizeof (CK_ATTRIBUTE) * fullTempleteLen);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pMechanism)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && mechs->getMechanismInfo(pMechanism->mechanism, pMechInfo))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && !(pMechInfo->flags & CKF_GENERATE))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && (state == CKS_RO_USER_FUNCTIONS || state == CKS_RO_PUBLIC_SESSION))
		rv = CKR_SESSION_READ_ONLY;
	if (!rv && (pMechanism->pParameter || pMechanism->ulParameterLen > 0))
		rv = CKR_MECHANISM_PARAM_INVALID;
	if (!rv && !(*slots)[slot]->isTokenPresent())
		rv = CKR_TOKEN_NOT_PRESENT;

	if (!rv)
		rv = checkGenerateKeyAttributes(pTemplate, ulCount, pMechanism->mechanism, fullTemplate);

	if (!rv)
		rv = (*slots)[slot]->generateKey(hSession, pMechanism, fullTemplate, fullTempleteLen, phKey);

	for (int i = 0; i < fullTempleteLen; i++)
		if (fullTemplate[i].pValue)
			delete [] (char*) fullTemplate[i].pValue;

	delete [] fullTemplate;
	delete pMechInfo;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	rv = CKR_FUNCTION_NOT_SUPPORTED;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	rv = CKR_FUNCTION_NOT_SUPPORTED;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	rv = CKR_FUNCTION_NOT_SUPPORTED;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	rv = CKR_FUNCTION_NOT_SUPPORTED;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV checkGenerateKeyAttributes(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_MECHANISM_TYPE mechType, CK_ATTRIBUTE_PTR fullTemplate)
{
	/**
	 Attributes:
	
	 secret key is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_SECRET_KEY
	 [storage]
		CKA_TOKEN - Defaults to false
		CKA_PRIVATE - defaults to true for secret keys
		CKA_MODIFIABLE - defaults to true
		CKA_LABEL - defaults to empty string
	 [Key]
		CKA_KEY_TYPE - if specified, must match the appropriate mechanism
		CKA_ID - default empty
		CKA_START_DATE - default empty
		CKA_END_DATE - default empty
		CKA_DERIVE - default false
		CKA_LOCAL - Read only, set depending on generation or import
		CKA_KEY_GEN_MECHANISM - Read only, may be CK_UNAVAILABLE_INFORMATION if CKA_LOCAL is false
		CKA_ALLOWED_MECHANISMS - Read only
	 [Secret key]
		CKA_SENSITIVE - default false
		CKA_ENCRYPT - default true
		CKA_DECRYPT - default true
		CKA_SIGN - default false
		CKA_VERIFY - default false
		CKA_WRAP - default true
		CKA_UNWRAP - default true
		CKA_EXTRACTABLE - default true
		CKA_ALWAYS_SENSITIVE - Read only, depends on CKA_SENSITIVE
		CKA_NEVER_EXTRACTABLE - Read only, depends on CKA_EXTRACTABLE
		CKA_CHECK_VALUE - optional, no default
		CKA_WRAP_WITH_TRUSTED - default false
		CKA_TRUSTED - Only set by SO
		CKA_WRAP_TEMPLATE - default empty
		CKA_UNWRAP_TEMPLATE - default empty
	 */

	CK_RV rv = CKR_OK;
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* attrMap = NULL;
	bool keyLenRequired = false;
	bool keylenProvided = true;
	
	attrMap = new std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>;

	if (!attrMap)
		rv = CKR_DEVICE_MEMORY;

	for (unsigned int i = 0; i < ulCount && !rv; i++)
	{
		switch (pTemplate[i].type) {
		case CKA_CLASS:
			if (*(CK_OBJECT_CLASS_PTR) pTemplate[i].pValue != CKO_SECRET_KEY)
				rv = CKR_TEMPLATE_INCONSISTENT;
			break;
		case CKA_KEY_TYPE:
			if (!mechs->isSupportedSecretKeyType(*(CK_OBJECT_CLASS_PTR) pTemplate[i].pValue))
				rv = CKR_ATTRIBUTE_TYPE_INVALID;
			else
				if ((*(CK_OBJECT_CLASS_PTR)pTemplate[i].pValue) == CKK_AES || (*(CK_OBJECT_CLASS_PTR)pTemplate[i].pValue) == CKK_RC4)
					keyLenRequired = true;
			break;
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_ALLOWED_MECHANISMS:
		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
		case CKA_TRUSTED:
			rv = CKR_ATTRIBUTE_READ_ONLY;
			break;
		case CKA_VALUE_LEN:
			keylenProvided = true;
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_LABEL:
		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:
		case CKA_DERIVE:
		case CKA_SENSITIVE:
		case CKA_ENCRYPT:
		case CKA_DECRYPT:
		case CKA_SIGN:
		case CKA_VERIFY:
		case CKA_WRAP:
		case CKA_UNWRAP:
		case CKA_EXTRACTABLE:
		case CKA_CHECK_VALUE:
		case CKA_WRAP_WITH_TRUSTED:
		case CKA_WRAP_TEMPLATE:
		case CKA_UNWRAP_TEMPLATE:
			break;
		default:
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
		}

		if (!rv && !mapAttribute(attrMap, pTemplate[i]))
			rv = CKR_DEVICE_MEMORY;
	}

	if (!rv && keyLenRequired && !keylenProvided)
		rv = CKR_TEMPLATE_INCOMPLETE;
	
	if (!rv && populateDefaultGenerateKeyTemplate(attrMap, mechType))
		rv = CKR_DEVICE_MEMORY;

	int i = 0;
	for (std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator iter = attrMap->begin(); iter != attrMap->end() && !rv; iter++, i++)
	{
		memcpy(&fullTemplate[i], iter->second, sizeof(CK_ATTRIBUTE));
	}
	
	if (attrMap)
	{
		for (std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator iter = attrMap->begin(); iter != attrMap->end(); iter++)
		{
			delete iter->second;
		}

		delete attrMap;
	}

	return rv;
}

bool populateDefaultGenerateKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* dest, const CK_MECHANISM_TYPE mechType)
{
	bool good = true;

	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS objclass = CKO_SECRET_KEY;
	CK_BBOOL t = true;
	CK_BBOOL f = false;
	CK_KEY_TYPE keyType;
	CK_MECHANISM_TYPE_PTR pMechTypes = NULL;
	int pMechTypesLen = 0;
	CK_ULONG length;
	
	switch (mechType) {
	case CKM_DES3_KEY_GEN:
		keyType = CKK_DES3;
		length = 24;
		break;
	case CKM_RC4_KEY_GEN:
		keyType = CKK_RC4;
		length = 16;
		break;
	case CKM_DES_KEY_GEN:
		keyType = CKK_DES;
		length = 8;
		break;
	case CKM_AES_KEY_GEN:
		keyType = CKK_AES;
		length = 16;
		break;
	default:
		good = false;
	}

	mechs->getMechanismsByKeyType(keyType, &pMechTypes, &pMechTypesLen);

	if (good && !(*dest)[CKA_CLASS])
	{
		attr.type = CKA_CLASS;
		attr.ulValueLen = sizeof (objclass);
		attr.pValue = new CK_OBJECT_CLASS;
		memcpy(attr.pValue, &objclass, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_OBJECT_CLASS_PTR) attr.pValue;
	}

	if (good && !(*dest)[CKA_TOKEN])
	{
		attr.type = CKA_TOKEN;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &f, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_PRIVATE])
	{
		attr.type = CKA_PRIVATE;
		attr.ulValueLen = sizeof (t);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &t, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_MODIFIABLE])
	{
		attr.type = CKA_MODIFIABLE;
		attr.ulValueLen = sizeof (t);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &t, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_LABEL])
	{
		attr.type = CKA_LABEL;
		attr.ulValueLen = 0;

		good = mapAttribute(dest, attr);
	}

	if (good && !(*dest)[CKA_KEY_TYPE])
	{
		attr.type = CKA_KEY_TYPE;
		attr.ulValueLen = sizeof (keyType);
		attr.pValue = new CK_KEY_TYPE;
		memcpy(attr.pValue, &keyType, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_KEY_TYPE*) attr.pValue;
	}

	if (good && !(*dest)[CKA_VALUE_LEN])
	{
		attr.type = CKA_VALUE_LEN;
		attr.ulValueLen = sizeof (CK_ULONG);
		attr.pValue = new CK_ULONG;
		memcpy(attr.pValue, &length, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_KEY_TYPE*) attr.pValue;
	}

	if (good && !(*dest)[CKA_ID])
	{
		attr.type = CKA_ID;
		attr.ulValueLen = 0;

		good = mapAttribute(dest, attr);
	}

	if (good && !(*dest)[CKA_START_DATE])
	{
		attr.type = CKA_START_DATE;
		attr.ulValueLen = 0;

		good = mapAttribute(dest, attr);
	}

	if (good && !(*dest)[CKA_END_DATE])
	{
		attr.type = CKA_END_DATE;
		attr.ulValueLen = 0;

		good = mapAttribute(dest, attr);
	}

	if (good && !(*dest)[CKA_DERIVE])
	{
		attr.type = CKA_DERIVE;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &f, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_LOCAL])
	{
		attr.type = CKA_LOCAL;
		attr.ulValueLen = sizeof (t);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &t, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_KEY_GEN_MECHANISM])
	{
		attr.type = CKA_KEY_GEN_MECHANISM;
		attr.ulValueLen = sizeof (mechType);
		attr.pValue = new CK_MECHANISM_TYPE;
		memcpy(attr.pValue, &mechType, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_MECHANISM_TYPE*) attr.pValue;
	}

	if (good && !(*dest)[CKA_ALLOWED_MECHANISMS])
	{
		attr.type = CKA_ALLOWED_MECHANISMS;
		attr.ulValueLen = sizeof (CK_MECHANISM_TYPE) * pMechTypesLen;
		attr.pValue = new CK_MECHANISM_TYPE[pMechTypesLen];
		memcpy(attr.pValue, pMechTypes, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete [] (CK_MECHANISM_TYPE_PTR) attr.pValue;
	}

	if (good && !(*dest)[CKA_SENSITIVE])
	{
		attr.type = CKA_SENSITIVE;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &f, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_ENCRYPT])
	{
		attr.type = CKA_ENCRYPT;
		attr.ulValueLen = sizeof (t);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &t, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_DECRYPT])
	{
		attr.type = CKA_DECRYPT;
		attr.ulValueLen = sizeof (t);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &t, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_SIGN])
	{
		attr.type = CKA_SIGN;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &f, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_VERIFY])
	{
		attr.type = CKA_VERIFY;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &f, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_WRAP])
	{
		attr.type = CKA_WRAP;
		attr.ulValueLen = sizeof (t);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &t, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_UNWRAP])
	{
		attr.type = CKA_UNWRAP;
		attr.ulValueLen = sizeof (t);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &t, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_EXTRACTABLE])
	{
		attr.type = CKA_EXTRACTABLE;
		attr.ulValueLen = sizeof (t);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &t, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_ALWAYS_SENSITIVE])
	{
		attr.type = CKA_ALWAYS_SENSITIVE;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, (*dest)[CKA_SENSITIVE]->pValue, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_NEVER_EXTRACTABLE])
	{
		attr.type = CKA_NEVER_EXTRACTABLE;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, (*dest)[CKA_EXTRACTABLE]->pValue, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_CHECK_VALUE])
	{
		attr.type = CKA_CHECK_VALUE;
		attr.ulValueLen = 0;

		good = mapAttribute(dest, attr);
	}

	if (good && !(*dest)[CKA_WRAP_WITH_TRUSTED])
	{
		attr.type = CKA_WRAP_WITH_TRUSTED;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &f, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_TRUSTED])
	{
		attr.type = CKA_TRUSTED;
		attr.ulValueLen = sizeof (f);
		attr.pValue = new CK_BBOOL;
		memcpy(attr.pValue, &f, attr.ulValueLen);

		good = mapAttribute(dest, attr);

		delete (CK_BBOOL*) attr.pValue;
	}

	if (good && !(*dest)[CKA_WRAP_TEMPLATE])
	{
		attr.type = CKA_WRAP_TEMPLATE;
		attr.ulValueLen = 0;
	
		good = mapAttribute(dest, attr);
	}

	if (good && !(*dest)[CKA_UNWRAP_TEMPLATE])
	{
		attr.type = CKA_UNWRAP_TEMPLATE;
		attr.ulValueLen = 0;
	
		good = mapAttribute(dest, attr);
	}

	if (pMechTypes) delete [] pMechTypes;

	return !good;
}

bool mapAttribute(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* dest, const CK_ATTRIBUTE src)
{
	(*dest)[src.type] = NULL;
	(*dest)[src.type] = new CK_ATTRIBUTE;

	if (!(*dest)[src.type])
		return false;

	(*dest)[src.type]->type = src.type;
	(*dest)[src.type]->ulValueLen = src.ulValueLen;
	if (src.pValue)
	{
		(*dest)[src.type]->pValue = new char[(*dest)[src.type]->ulValueLen];

		if ((*dest)[src.type]->pValue)
			memcpy((*dest)[src.type]->pValue, src.pValue, (*dest)[src.type]->ulValueLen);
		else
			return false;
	}
	
	return true;
}
