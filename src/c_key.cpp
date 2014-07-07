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

#define GENERATEKEYTEMPLATELENGTH 29
#define GENERATEPUBKEYTEMPLATELENGTH 22
#define GENERATEPRIVKEYTEMPLATELENGTH 25

extern bool cryptokiInitialized;
extern std::vector<slot*>* slots;
extern mechanisms* mechs;

extern int getSlotBySession(CK_SESSION_HANDLE hSession);

// eventually these should replace the above, to be similar to the create object template creation
static void generateDefaultPubKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static void generateDefaultPrivKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static void generateDefaultSecKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static CK_RV applyPubKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV applyPrivKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV applySecKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();
	CK_MECHANISM_INFO_PTR pMechInfo = new CK_MECHANISM_INFO;
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate = NULL;

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
	{
		defaultTemplate = new std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>;
		if (!defaultTemplate)
			rv = CKR_DEVICE_MEMORY;
	}

	if (!rv)
	{
		generateDefaultSecKeyTemplate(defaultTemplate);
		rv = applySecKeyTemplate(defaultTemplate, pTemplate, ulCount);
	}

	if (!rv)
		rv = (*slots)[slot]->generateKey(hSession, defaultTemplate, phKey);

	// cleanup
	if (pMechInfo) delete pMechInfo;
	if (defaultTemplate)
	{
		for (std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator iter = defaultTemplate->begin(); iter != defaultTemplate->end(); iter++)
		{
			if (iter->second->pValue) delete [] (unsigned char*) iter->second->pValue;
			if (iter->second) delete iter->second;
		}

		delete defaultTemplate;
	}
	
	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();
	CK_MECHANISM_INFO_PTR pMechInfo = new CK_MECHANISM_INFO;
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultPubTemplate = NULL;
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultPrivTemplate = NULL;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && !(*slots)[slot]->isTokenPresent())
		rv = CKR_TOKEN_NOT_PRESENT;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pMechanism)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && mechs->getMechanismInfo(pMechanism->mechanism, pMechInfo))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && !(pMechInfo->flags & CKF_GENERATE_KEY_PAIR))
		rv = CKR_MECHANISM_INVALID;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && (state == CKS_RO_USER_FUNCTIONS || state == CKS_RO_PUBLIC_SESSION))
		rv = CKR_SESSION_READ_ONLY;
	if (!rv && (pMechanism->pParameter || pMechanism->ulParameterLen > 0))
		rv = CKR_MECHANISM_PARAM_INVALID;

	if (!rv)
	{
		defaultPubTemplate = new std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>;
		if (!defaultPubTemplate)
			rv = CKR_DEVICE_MEMORY;
	}
	if (!rv)
	{
		defaultPrivTemplate = new std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>;
		if (!defaultPrivTemplate)
			rv = CKR_DEVICE_MEMORY;
	}
	
	// create and apply the templates
	if (!rv)
	{
		generateDefaultPubKeyTemplate(defaultPubTemplate);
		rv = applyPubKeyTemplate(defaultPubTemplate, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	}
	if (!rv)
	{
		generateDefaultPrivKeyTemplate(defaultPrivTemplate);
		rv = applyPrivKeyTemplate(defaultPrivTemplate, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	}
	
	if (!rv)
		rv = (*slots)[slot]->generateKeyPair(hSession, defaultPubTemplate, defaultPrivTemplate, phPublicKey, phPrivateKey);
	
	// clean up
	delete pMechInfo;
	if (defaultPubTemplate)
	{
		for (std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator iter = defaultPubTemplate->begin(); iter != defaultPubTemplate->end(); iter++)
		{
			if (iter->second->pValue) delete [] (unsigned char*) iter->second->pValue;
			if (iter->second) delete iter->second;
		}

		delete defaultPubTemplate;
	}
	if (defaultPrivTemplate)
	{
		for (std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator iter = defaultPrivTemplate->begin(); iter != defaultPrivTemplate->end(); iter++)
		{
			if (iter->second->pValue) delete [] (unsigned char*) iter->second->pValue;
			if (iter->second) delete iter->second;
		}

		delete defaultPrivTemplate;
	}
	
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

static void generateDefaultPubKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate)
{
	/**
	 Attributes:
	
	 public key is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_PUBLIC_KEY
	 [storage]
		CKA_TOKEN - Defaults to false
		CKA_PRIVATE - defaults to true for secret keys
		CKA_MODIFIABLE - defaults to true
		CKA_LABEL - defaults to empty string
	 [Key]
		CKA_KEY_TYPE - optional, but if specified must match key gen mechanism
		CKA_ID - default empty
		CKA_START_DATE - default empty
		CKA_END_DATE - default empty
		CKA_DERIVE - default false
		CKA_LOCAL - Read only
		CKA_KEY_GEN_MECHANISM - Read only, may be CK_UNAVAILABLE_INFORMATION if CKA_LOCAL is false
		CKA_ALLOWED_MECHANISMS - Read only
	 [Public Key]
		CKA_SUBJECT - Default empty
		CKA_ENCRYPT - default true
		CKA_VERIFY - default true
		CKA_VERIFY_RECOVER - default true
		CKA_WRAP - default true
		CKA_TRUSTED - Only set by SO
		CKA_WRAP_TEMPLATE - default empty
	 [Other] - required since we're only going to support RSA keypair generation
		CKA_MODULUS - read only
		CKA_MODULUS_BITS - optional, has default
		CKA_PUBLIC_EXPONENT - optional, will have default
	 */

	CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
	CK_BBOOL b = CK_TRUE;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ULONG modLen = 0;

	// CKA_CLASS -> CKO_DATA
	(*defaultTemplate)[CKA_CLASS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CLASS]->type = CKA_CLASS;
	(*defaultTemplate)[CKA_CLASS]->ulValueLen = sizeof (objClass);
	(*defaultTemplate)[CKA_CLASS]->pValue = new unsigned char*[sizeof (objClass)];
	memcpy((*defaultTemplate)[CKA_CLASS]->pValue, &objClass, (*defaultTemplate)[CKA_CLASS]->ulValueLen);

	// CKA_TOKEN -> true
	b = CK_FALSE;
	(*defaultTemplate)[CKA_TOKEN] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_TOKEN]->type = CKA_TOKEN;
	(*defaultTemplate)[CKA_TOKEN]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_TOKEN]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_TOKEN]->pValue, &b, (*defaultTemplate)[CKA_TOKEN]->ulValueLen);

	// CKA_PRIVATE -> false
	b = CK_FALSE;
	(*defaultTemplate)[CKA_PRIVATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_PRIVATE]->type = CKA_PRIVATE;
	(*defaultTemplate)[CKA_PRIVATE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_PRIVATE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_PRIVATE]->pValue, &b, (*defaultTemplate)[CKA_PRIVATE]->ulValueLen);

	// CKA_MODIFIABLE -> true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_MODIFIABLE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_MODIFIABLE]->type = CKA_MODIFIABLE;
	(*defaultTemplate)[CKA_MODIFIABLE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_MODIFIABLE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_MODIFIABLE]->pValue, &b, (*defaultTemplate)[CKA_MODIFIABLE]->ulValueLen);

	// CKA_LABEL -> empty string
	(*defaultTemplate)[CKA_LABEL] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_LABEL]->type = CKA_LABEL;
	(*defaultTemplate)[CKA_LABEL]->ulValueLen = 0;
	(*defaultTemplate)[CKA_LABEL]->pValue = NULL;

	// CKA_KEY_TYPE - optional, but if specified must match key gen mechanism
	(*defaultTemplate)[CKA_KEY_TYPE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_KEY_TYPE]->type = CKA_KEY_TYPE;
	(*defaultTemplate)[CKA_KEY_TYPE]->ulValueLen = sizeof (keyType);
	(*defaultTemplate)[CKA_KEY_TYPE]->pValue = new unsigned char*[sizeof (keyType)];
	memcpy((*defaultTemplate)[CKA_KEY_TYPE]->pValue, &keyType, (*defaultTemplate)[CKA_KEY_TYPE]->ulValueLen);

	// CKA_ID - default empty
	(*defaultTemplate)[CKA_ID] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ID]->type = CKA_ID;
	(*defaultTemplate)[CKA_ID]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ID]->pValue = NULL;

	// CKA_START_DATE - default empty
	(*defaultTemplate)[CKA_START_DATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_START_DATE]->type = CKA_START_DATE;
	(*defaultTemplate)[CKA_START_DATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_START_DATE]->pValue = NULL;

	// CKA_END_DATE - default empty
	(*defaultTemplate)[CKA_END_DATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_END_DATE]->type = CKA_END_DATE;
	(*defaultTemplate)[CKA_END_DATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_END_DATE]->pValue = NULL;

	// CKA_DERIVE - default FALSE
	b = CK_FALSE;
	(*defaultTemplate)[CKA_DERIVE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_DERIVE]->type = CKA_DERIVE;
	(*defaultTemplate)[CKA_DERIVE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_DERIVE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_DERIVE]->pValue, &b, (*defaultTemplate)[CKA_DERIVE]->ulValueLen);

	// CKA_LOCAL - read only
	b = CK_FALSE;
	(*defaultTemplate)[CKA_LOCAL] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_LOCAL]->type = CKA_LOCAL;
	(*defaultTemplate)[CKA_LOCAL]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_LOCAL]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_LOCAL]->pValue, &b, (*defaultTemplate)[CKA_LOCAL]->ulValueLen);

	// CKA_KEY_GEN_MECHANISM - read only
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->type = CKA_KEY_GEN_MECHANISM;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->ulValueLen = 0;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->pValue = NULL;

	// CKA_ALLOWED_MECHANISMS - read only
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->type = CKA_ALLOWED_MECHANISMS;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->pValue = NULL;

	// CKA_SUBJECT - default empty
	(*defaultTemplate)[CKA_SUBJECT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SUBJECT]->type = CKA_SUBJECT;
	(*defaultTemplate)[CKA_SUBJECT]->ulValueLen = 0;
	(*defaultTemplate)[CKA_SUBJECT]->pValue = NULL;

	// CKA_ENCRYPT - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_ENCRYPT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ENCRYPT]->type = CKA_ENCRYPT;
	(*defaultTemplate)[CKA_ENCRYPT]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_ENCRYPT]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_ENCRYPT]->pValue, &b, (*defaultTemplate)[CKA_ENCRYPT]->ulValueLen);

	// CKA_VERIFY - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_VERIFY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VERIFY]->type = CKA_VERIFY;
	(*defaultTemplate)[CKA_VERIFY]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_VERIFY]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_VERIFY]->pValue, &b, (*defaultTemplate)[CKA_VERIFY]->ulValueLen);

	// CKA_VERIFY_RECOVER - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_VERIFY_RECOVER] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VERIFY_RECOVER]->type = CKA_VERIFY_RECOVER;
	(*defaultTemplate)[CKA_VERIFY_RECOVER]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_VERIFY_RECOVER]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_VERIFY_RECOVER]->pValue, &b, (*defaultTemplate)[CKA_VERIFY_RECOVER]->ulValueLen);

	// CKA_WRAP - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_WRAP] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_WRAP]->type = CKA_WRAP;
	(*defaultTemplate)[CKA_WRAP]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_WRAP]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_WRAP]->pValue, &b, (*defaultTemplate)[CKA_WRAP]->ulValueLen);

	// CKA_TRUSTED - read only
	b = CK_FALSE;
	(*defaultTemplate)[CKA_TRUSTED] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_TRUSTED]->type = CKA_TRUSTED;
	(*defaultTemplate)[CKA_TRUSTED]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_TRUSTED]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_TRUSTED]->pValue, &b, (*defaultTemplate)[CKA_TRUSTED]->ulValueLen);

	// CKA_WRAP_TEMPLATE - default empty
	(*defaultTemplate)[CKA_WRAP_TEMPLATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_WRAP_TEMPLATE]->type = CKA_WRAP_TEMPLATE;
	(*defaultTemplate)[CKA_WRAP_TEMPLATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_WRAP_TEMPLATE]->pValue = NULL;

	// CKA_MODULUS - required
	(*defaultTemplate)[CKA_MODULUS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_MODULUS]->type = CKA_MODULUS;
	(*defaultTemplate)[CKA_MODULUS]->ulValueLen = 0;
	(*defaultTemplate)[CKA_MODULUS]->pValue = NULL;

	// CKA_MODULUS_BITS - read only
	(*defaultTemplate)[CKA_MODULUS_BITS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_MODULUS_BITS]->type = CKA_MODULUS_BITS;
	(*defaultTemplate)[CKA_MODULUS_BITS]->ulValueLen = sizeof (modLen);
	(*defaultTemplate)[CKA_MODULUS_BITS]->pValue = new unsigned char*[sizeof (modLen)];
	memcpy((*defaultTemplate)[CKA_MODULUS_BITS]->pValue, &modLen, (*defaultTemplate)[CKA_MODULUS_BITS]->ulValueLen);

	// CKA_PUBLIC_EXPONENT - required
	(*defaultTemplate)[CKA_PUBLIC_EXPONENT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_PUBLIC_EXPONENT]->type = CKA_PUBLIC_EXPONENT;
	(*defaultTemplate)[CKA_PUBLIC_EXPONENT]->ulValueLen = 0;
	(*defaultTemplate)[CKA_PUBLIC_EXPONENT]->pValue = NULL;
}

static void generateDefaultPrivKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate)
{
	/**
	 Attributes:
	
	 Private key is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_PRIVATE_KEY
	 [storage]
		CKA_TOKEN - Defaults to True
		CKA_PRIVATE - defaults to true
		CKA_MODIFIABLE - defaults to true
		CKA_LABEL - defaults to empty string
	 [Key]
		CKA_KEY_TYPE - required
		CKA_ID - default empty
		CKA_START_DATE - default empty
		CKA_END_DATE - default empty
		CKA_DERIVE - default FALSE
		CKA_LOCAL - read only
		CKA_KEY_GEN_MECHANISM - read only
		CKA_ALLOWED_MECHANISMS - default empty
	 [Private Key]
		CKA_SUBJECT - default empty
		CKA_SENSITIVE - default true
		CKA_DECRYPT - default true
		CKA_SIGN - default true
		CKA_SIGN_RECOVER - default true
		CKA_UNWRAP - default true
		CKA_EXTRACTABLE - default true
		CKA_ALWAYS_SENSITIVE - false, read only
		CKA_NEVER_EXTRACTABLE - false, read only
		CKA_WRAP_WITH_TRUSTED - default false
		CKA_UNWRAP_TEMPLATE - default empty
		CKA_ALWAYS_AUTHENTICATE - default false
	 [Other]
		CKA_MODULUS - read only
		CKA_PUBLIC_EXPONENT - read only
		CKA_PRIVATE_EXPONENT - read only
		CKA_PRIME_1 - read only
		CKA_PRIME_2 - read only
		CKA_EXPONENT_1 - read only
		CKA_EXPONENT_2 - read only
		CKA_COEFFICIENT - read only
	 */

	CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
	CK_BBOOL b = CK_TRUE;
	CK_KEY_TYPE keyType = CKK_RSA;

	// CKA_CLASS -> CKO_PRIVATE_KEY
	(*defaultTemplate)[CKA_CLASS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CLASS]->type = CKA_CLASS;
	(*defaultTemplate)[CKA_CLASS]->ulValueLen = sizeof (objClass);
	(*defaultTemplate)[CKA_CLASS]->pValue = new unsigned char*[sizeof (objClass)];
	memcpy((*defaultTemplate)[CKA_CLASS]->pValue, &objClass, (*defaultTemplate)[CKA_CLASS]->ulValueLen);

	// CKA_TOKEN -> true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_TOKEN] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_TOKEN]->type = CKA_TOKEN;
	(*defaultTemplate)[CKA_TOKEN]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_TOKEN]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_TOKEN]->pValue, &b, (*defaultTemplate)[CKA_TOKEN]->ulValueLen);

	// CKA_PRIVATE -> false
	b = CK_TRUE;
	(*defaultTemplate)[CKA_PRIVATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_PRIVATE]->type = CKA_PRIVATE;
	(*defaultTemplate)[CKA_PRIVATE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_PRIVATE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_PRIVATE]->pValue, &b, (*defaultTemplate)[CKA_PRIVATE]->ulValueLen);

	// CKA_MODIFIABLE -> true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_MODIFIABLE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_MODIFIABLE]->type = CKA_MODIFIABLE;
	(*defaultTemplate)[CKA_MODIFIABLE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_MODIFIABLE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_MODIFIABLE]->pValue, &b, (*defaultTemplate)[CKA_MODIFIABLE]->ulValueLen);

	// CKA_LABEL -> empty string
	(*defaultTemplate)[CKA_LABEL] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_LABEL]->type = CKA_LABEL;
	(*defaultTemplate)[CKA_LABEL]->ulValueLen = 0;
	(*defaultTemplate)[CKA_LABEL]->pValue = NULL;

	// CKA_KEY_TYPE - required
	(*defaultTemplate)[CKA_KEY_TYPE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_KEY_TYPE]->type = CKA_KEY_TYPE;
	(*defaultTemplate)[CKA_KEY_TYPE]->ulValueLen = sizeof (keyType);
	(*defaultTemplate)[CKA_KEY_TYPE]->pValue = new unsigned char*[sizeof (keyType)];
	memcpy((*defaultTemplate)[CKA_KEY_TYPE]->pValue, &keyType, (*defaultTemplate)[CKA_KEY_TYPE]->ulValueLen);

	// CKA_ID - default empty
	(*defaultTemplate)[CKA_ID] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ID]->type = CKA_ID;
	(*defaultTemplate)[CKA_ID]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ID]->pValue = NULL;

	// CKA_START_DATE - default empty
	(*defaultTemplate)[CKA_START_DATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_START_DATE]->type = CKA_START_DATE;
	(*defaultTemplate)[CKA_START_DATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_START_DATE]->pValue = NULL;

	// CKA_END_DATE - default empty
	(*defaultTemplate)[CKA_END_DATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_END_DATE]->type = CKA_END_DATE;
	(*defaultTemplate)[CKA_END_DATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_END_DATE]->pValue = NULL;

	// CKA_DERIVE - default FALSE
	b = CK_FALSE;
	(*defaultTemplate)[CKA_DERIVE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_DERIVE]->type = CKA_DERIVE;
	(*defaultTemplate)[CKA_DERIVE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_DERIVE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_DERIVE]->pValue, &b, (*defaultTemplate)[CKA_DERIVE]->ulValueLen);

	// CKA_LOCAL - read only
	b = CK_FALSE;
	(*defaultTemplate)[CKA_LOCAL] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_LOCAL]->type = CKA_LOCAL;
	(*defaultTemplate)[CKA_LOCAL]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_LOCAL]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_LOCAL]->pValue, &b, (*defaultTemplate)[CKA_LOCAL]->ulValueLen);

	// CKA_KEY_GEN_MECHANISM - read only
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->type = CKA_KEY_GEN_MECHANISM;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->ulValueLen = 0;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->pValue = NULL;

	// CKA_ALLOWED_MECHANISMS - default empty
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->type = CKA_ALLOWED_MECHANISMS;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->pValue = NULL;

	//CKA_SUBJECT - default empty
	(*defaultTemplate)[CKA_SUBJECT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SUBJECT]->type = CKA_SUBJECT;
	(*defaultTemplate)[CKA_SUBJECT]->ulValueLen = 0;
	(*defaultTemplate)[CKA_SUBJECT]->pValue = NULL;

	//CKA_SENSITIVE - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_SENSITIVE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SENSITIVE]->type = CKA_SENSITIVE;
	(*defaultTemplate)[CKA_SENSITIVE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_SENSITIVE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_SENSITIVE]->pValue, &b, (*defaultTemplate)[CKA_SENSITIVE]->ulValueLen);

	//CKA_DECRYPT - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_DECRYPT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_DECRYPT]->type = CKA_DECRYPT;
	(*defaultTemplate)[CKA_DECRYPT]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_DECRYPT]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_DECRYPT]->pValue, &b, (*defaultTemplate)[CKA_DECRYPT]->ulValueLen);

	//CKA_SIGN - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_SIGN] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SIGN]->type = CKA_SIGN;
	(*defaultTemplate)[CKA_SIGN]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_SIGN]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_SIGN]->pValue, &b, (*defaultTemplate)[CKA_SIGN]->ulValueLen);

	//CKA_SIGN_RECOVER - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_SIGN_RECOVER] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SIGN_RECOVER]->type = CKA_SIGN_RECOVER;
	(*defaultTemplate)[CKA_SIGN_RECOVER]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_SIGN_RECOVER]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_SIGN_RECOVER]->pValue, &b, (*defaultTemplate)[CKA_SIGN_RECOVER]->ulValueLen);

	//CKA_UNWRAP - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_UNWRAP] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_UNWRAP]->type = CKA_UNWRAP;
	(*defaultTemplate)[CKA_UNWRAP]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_UNWRAP]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_UNWRAP]->pValue, &b, (*defaultTemplate)[CKA_UNWRAP]->ulValueLen);

	//CKA_EXTRACTABLE - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_EXTRACTABLE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_EXTRACTABLE]->type = CKA_EXTRACTABLE;
	(*defaultTemplate)[CKA_EXTRACTABLE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_EXTRACTABLE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_EXTRACTABLE]->pValue, &b, (*defaultTemplate)[CKA_EXTRACTABLE]->ulValueLen);

	//CKA_ALWAYS_SENSITIVE - false, read only
	b = CK_FALSE;
	(*defaultTemplate)[CKA_ALWAYS_SENSITIVE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->type = CKA_ALWAYS_SENSITIVE;
	(*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->pValue, &b, (*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->ulValueLen);

	//CKA_NEVER_EXTRACTABLE - false, read only
	b = CK_FALSE;
	(*defaultTemplate)[CKA_NEVER_EXTRACTABLE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->type = CKA_NEVER_EXTRACTABLE;
	(*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->pValue, &b, (*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->ulValueLen);

	//CKA_WRAP_WITH_TRUSTED - default false
	b = CK_FALSE;
	(*defaultTemplate)[CKA_WRAP_WITH_TRUSTED] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->type = CKA_WRAP_WITH_TRUSTED;
	(*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->pValue, &b, (*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->ulValueLen);

	//CKA_UNWRAP_TEMPLATE - default empty
	(*defaultTemplate)[CKA_UNWRAP_TEMPLATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_UNWRAP_TEMPLATE]->type = CKA_UNWRAP_TEMPLATE;
	(*defaultTemplate)[CKA_UNWRAP_TEMPLATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_UNWRAP_TEMPLATE]->pValue = NULL;

	//CKA_ALWAYS_AUTHENTICATE - default false
	b = CK_FALSE;
	(*defaultTemplate)[CKA_ALWAYS_AUTHENTICATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ALWAYS_AUTHENTICATE]->type = CKA_ALWAYS_AUTHENTICATE;
	(*defaultTemplate)[CKA_ALWAYS_AUTHENTICATE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_ALWAYS_AUTHENTICATE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_ALWAYS_AUTHENTICATE]->pValue, &b, (*defaultTemplate)[CKA_ALWAYS_AUTHENTICATE]->ulValueLen);

	// CKA_MODULUS - required
	(*defaultTemplate)[CKA_MODULUS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_MODULUS]->type = CKA_MODULUS;
	(*defaultTemplate)[CKA_MODULUS]->ulValueLen = 0;
	(*defaultTemplate)[CKA_MODULUS]->pValue = NULL;

	// CKA_PUBLIC_EXPONENT - optional
	(*defaultTemplate)[CKA_PUBLIC_EXPONENT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_PUBLIC_EXPONENT]->type = CKA_PUBLIC_EXPONENT;
	(*defaultTemplate)[CKA_PUBLIC_EXPONENT]->ulValueLen = 0;
	(*defaultTemplate)[CKA_PUBLIC_EXPONENT]->pValue = NULL;

	// CKA_PRIVATE_EXPONENT - required
	(*defaultTemplate)[CKA_PRIVATE_EXPONENT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_PRIVATE_EXPONENT]->type = CKA_PRIVATE_EXPONENT;
	(*defaultTemplate)[CKA_PRIVATE_EXPONENT]->ulValueLen = 0;
	(*defaultTemplate)[CKA_PRIVATE_EXPONENT]->pValue = NULL;

	// CKA_PRIME_1 - optional
	(*defaultTemplate)[CKA_PRIME_1] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_PRIME_1]->type = CKA_PRIME_1;
	(*defaultTemplate)[CKA_PRIME_1]->ulValueLen = 0;
	(*defaultTemplate)[CKA_PRIME_1]->pValue = NULL;

	// CKA_PRIME_2 - optional
	(*defaultTemplate)[CKA_PRIME_2] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_PRIME_2]->type = CKA_PRIME_2;
	(*defaultTemplate)[CKA_PRIME_2]->ulValueLen = 0;
	(*defaultTemplate)[CKA_PRIME_2]->pValue = NULL;

	// CKA_EXPONENT_1 - optional
	(*defaultTemplate)[CKA_EXPONENT_1] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_EXPONENT_1]->type = CKA_EXPONENT_1;
	(*defaultTemplate)[CKA_EXPONENT_1]->ulValueLen = 0;
	(*defaultTemplate)[CKA_EXPONENT_1]->pValue = NULL;

	// CKA_EXPONENT_2 - optional
	(*defaultTemplate)[CKA_EXPONENT_2] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_EXPONENT_2]->type = CKA_EXPONENT_2;
	(*defaultTemplate)[CKA_EXPONENT_2]->ulValueLen = 0;
	(*defaultTemplate)[CKA_EXPONENT_2]->pValue = NULL;

	// CKA_COEFFICIENT - optional
	(*defaultTemplate)[CKA_COEFFICIENT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_COEFFICIENT]->type = CKA_COEFFICIENT;
	(*defaultTemplate)[CKA_COEFFICIENT]->ulValueLen = 0;
	(*defaultTemplate)[CKA_COEFFICIENT]->pValue = NULL;
}

static void generateDefaultSecKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate)
{
	/**
	 Attributes:
	
	 Private key is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_SECRET_KEY
	 [storage]
		CKA_TOKEN - Defaults to True
		CKA_PRIVATE - defaults to true
		CKA_MODIFIABLE - defaults to true
		CKA_LABEL - defaults to empty string
	 [Key]
		CKA_KEY_TYPE - required
		CKA_ID - default empty
		CKA_START_DATE - default empty
		CKA_END_DATE - default empty
		CKA_DERIVE - default FALSE
		CKA_LOCAL - read only
		CKA_KEY_GEN_MECHANISM - read only
		CKA_ALLOWED_MECHANISMS - default empty
	 [Secret Key]
		CKA_SENSITIVE - default false
		CKA_ENCRYPT - default true
		CKA_DECRYPT - default true
		CKA_SIGN - default false
		CKA_VERIFY - default false
		CKA_WRAP - default true
		CKA_UNWRAP - default true
		CKA_EXTRACTABLE - default true
		CKA_ALWAYS_SEINSITIVE - default false, read only
		CKA_NEVER_EXTRACTABLE - default false, read only
		CKA_CHECK_VALUE - default empty
		CKA_WRAP_WITH_TRUSTED - default false
		CKA_TRUSTED - default false
		CKA_WRAP_TEMPLATE - default empty
		CKA_UNWRAP_TEMPLATE - default empty
	 [Other]
		CKA_VALUE - read only
		CKA_VALUE_LEN - optional
	 */

	CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
	CK_BBOOL b = CK_TRUE;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ULONG length = 0;

	// CKA_CLASS -> CKO_SECRET_KEY
	(*defaultTemplate)[CKA_CLASS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CLASS]->type = CKA_CLASS;
	(*defaultTemplate)[CKA_CLASS]->ulValueLen = sizeof (objClass);
	(*defaultTemplate)[CKA_CLASS]->pValue = new unsigned char*[sizeof (objClass)];
	memcpy((*defaultTemplate)[CKA_CLASS]->pValue, &objClass, (*defaultTemplate)[CKA_CLASS]->ulValueLen);

	// CKA_TOKEN -> true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_TOKEN] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_TOKEN]->type = CKA_TOKEN;
	(*defaultTemplate)[CKA_TOKEN]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_TOKEN]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_TOKEN]->pValue, &b, (*defaultTemplate)[CKA_TOKEN]->ulValueLen);

	// CKA_PRIVATE -> false
	b = CK_TRUE;
	(*defaultTemplate)[CKA_PRIVATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_PRIVATE]->type = CKA_PRIVATE;
	(*defaultTemplate)[CKA_PRIVATE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_PRIVATE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_PRIVATE]->pValue, &b, (*defaultTemplate)[CKA_PRIVATE]->ulValueLen);

	// CKA_MODIFIABLE -> true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_MODIFIABLE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_MODIFIABLE]->type = CKA_MODIFIABLE;
	(*defaultTemplate)[CKA_MODIFIABLE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_MODIFIABLE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_MODIFIABLE]->pValue, &b, (*defaultTemplate)[CKA_MODIFIABLE]->ulValueLen);

	// CKA_LABEL -> empty string
	(*defaultTemplate)[CKA_LABEL] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_LABEL]->type = CKA_LABEL;
	(*defaultTemplate)[CKA_LABEL]->ulValueLen = 0;
	(*defaultTemplate)[CKA_LABEL]->pValue = NULL;

	// CKA_KEY_TYPE - required
	(*defaultTemplate)[CKA_KEY_TYPE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_KEY_TYPE]->type = CKA_KEY_TYPE;
	(*defaultTemplate)[CKA_KEY_TYPE]->ulValueLen = sizeof (keyType);
	(*defaultTemplate)[CKA_KEY_TYPE]->pValue = new unsigned char*[sizeof (keyType)];
	memcpy((*defaultTemplate)[CKA_KEY_TYPE]->pValue, &keyType, (*defaultTemplate)[CKA_KEY_TYPE]->ulValueLen);

	// CKA_ID - default empty
	(*defaultTemplate)[CKA_ID] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ID]->type = CKA_ID;
	(*defaultTemplate)[CKA_ID]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ID]->pValue = NULL;

	// CKA_START_DATE - default empty
	(*defaultTemplate)[CKA_START_DATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_START_DATE]->type = CKA_START_DATE;
	(*defaultTemplate)[CKA_START_DATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_START_DATE]->pValue = NULL;

	// CKA_END_DATE - default empty
	(*defaultTemplate)[CKA_END_DATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_END_DATE]->type = CKA_END_DATE;
	(*defaultTemplate)[CKA_END_DATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_END_DATE]->pValue = NULL;

	// CKA_DERIVE - default FALSE
	b = CK_FALSE;
	(*defaultTemplate)[CKA_DERIVE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_DERIVE]->type = CKA_DERIVE;
	(*defaultTemplate)[CKA_DERIVE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_DERIVE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_DERIVE]->pValue, &b, (*defaultTemplate)[CKA_DERIVE]->ulValueLen);

	// CKA_LOCAL - read only
	b = CK_FALSE;
	(*defaultTemplate)[CKA_LOCAL] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_LOCAL]->type = CKA_LOCAL;
	(*defaultTemplate)[CKA_LOCAL]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_LOCAL]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_LOCAL]->pValue, &b, (*defaultTemplate)[CKA_LOCAL]->ulValueLen);

	// CKA_KEY_GEN_MECHANISM - read only
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->type = CKA_KEY_GEN_MECHANISM;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->ulValueLen = 0;
	(*defaultTemplate)[CKA_KEY_GEN_MECHANISM]->pValue = NULL;

	// CKA_ALLOWED_MECHANISMS - default empty
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->type = CKA_ALLOWED_MECHANISMS;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ALLOWED_MECHANISMS]->pValue = NULL;

	//CKA_SENSITIVE - default false
	b = CK_FALSE;
	(*defaultTemplate)[CKA_SENSITIVE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SENSITIVE]->type = CKA_SENSITIVE;
	(*defaultTemplate)[CKA_SENSITIVE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_SENSITIVE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_SENSITIVE]->pValue, &b, (*defaultTemplate)[CKA_SENSITIVE]->ulValueLen);

	//CKA_ENCRYPT - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_ENCRYPT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ENCRYPT]->type = CKA_ENCRYPT;
	(*defaultTemplate)[CKA_ENCRYPT]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_ENCRYPT]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_ENCRYPT]->pValue, &b, (*defaultTemplate)[CKA_ENCRYPT]->ulValueLen);

	//CKA_DECRYPT - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_DECRYPT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_DECRYPT]->type = CKA_DECRYPT;
	(*defaultTemplate)[CKA_DECRYPT]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_DECRYPT]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_DECRYPT]->pValue, &b, (*defaultTemplate)[CKA_DECRYPT]->ulValueLen);

	//CKA_SIGN - default false
	b = CK_FALSE;
	(*defaultTemplate)[CKA_SIGN] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SIGN]->type = CKA_SIGN;
	(*defaultTemplate)[CKA_SIGN]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_SIGN]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_SIGN]->pValue, &b, (*defaultTemplate)[CKA_SIGN]->ulValueLen);

	//CKA_VERIFY - default false
	b = CK_FALSE;
	(*defaultTemplate)[CKA_VERIFY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VERIFY]->type = CKA_VERIFY;
	(*defaultTemplate)[CKA_VERIFY]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_VERIFY]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_VERIFY]->pValue, &b, (*defaultTemplate)[CKA_VERIFY]->ulValueLen);

	//CKA_WRAP - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_WRAP] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_WRAP]->type = CKA_WRAP;
	(*defaultTemplate)[CKA_WRAP]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_WRAP]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_WRAP]->pValue, &b, (*defaultTemplate)[CKA_WRAP]->ulValueLen);

	//CKA_UNWRAP - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_UNWRAP] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_UNWRAP]->type = CKA_UNWRAP;
	(*defaultTemplate)[CKA_UNWRAP]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_UNWRAP]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_UNWRAP]->pValue, &b, (*defaultTemplate)[CKA_UNWRAP]->ulValueLen);

	//CKA_EXTRACTABLE - default true
	b = CK_TRUE;
	(*defaultTemplate)[CKA_EXTRACTABLE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_EXTRACTABLE]->type = CKA_EXTRACTABLE;
	(*defaultTemplate)[CKA_EXTRACTABLE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_EXTRACTABLE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_EXTRACTABLE]->pValue, &b, (*defaultTemplate)[CKA_EXTRACTABLE]->ulValueLen);

	//CKA_ALWAYS_SENSITIVE - default false, read only
	b = CK_FALSE;
	(*defaultTemplate)[CKA_ALWAYS_SENSITIVE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->type = CKA_ALWAYS_SENSITIVE;
	(*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->pValue, &b, (*defaultTemplate)[CKA_ALWAYS_SENSITIVE]->ulValueLen);

	//CKA_NEVER_EXTRACTABLE - default false, read only
	b = CK_FALSE;
	(*defaultTemplate)[CKA_NEVER_EXTRACTABLE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->type = CKA_NEVER_EXTRACTABLE;
	(*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->pValue, &b, (*defaultTemplate)[CKA_NEVER_EXTRACTABLE]->ulValueLen);

	//CKA_CHECK_VALUE - default empty
	(*defaultTemplate)[CKA_CHECK_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CHECK_VALUE]->type = CKA_CHECK_VALUE;
	(*defaultTemplate)[CKA_CHECK_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_CHECK_VALUE]->pValue = NULL;

	//CKA_WRAP_WITH_TRUSTED - default false
	b = CK_FALSE;
	(*defaultTemplate)[CKA_WRAP_WITH_TRUSTED] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->type = CKA_WRAP_WITH_TRUSTED;
	(*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->pValue, &b, (*defaultTemplate)[CKA_WRAP_WITH_TRUSTED]->ulValueLen);

	//CKA_TRUSTED - default false
	b = CK_FALSE;
	(*defaultTemplate)[CKA_TRUSTED] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_TRUSTED]->type = CKA_TRUSTED;
	(*defaultTemplate)[CKA_TRUSTED]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_TRUSTED]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_TRUSTED]->pValue, &b, (*defaultTemplate)[CKA_TRUSTED]->ulValueLen);

	//CKA_WRAP_TEMPLATE - default empty
	(*defaultTemplate)[CKA_WRAP_TEMPLATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_WRAP_TEMPLATE]->type = CKA_WRAP_TEMPLATE;
	(*defaultTemplate)[CKA_WRAP_TEMPLATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_WRAP_TEMPLATE]->pValue = NULL;

	//CKA_UNWRAP_TEMPLATE - default empty
	(*defaultTemplate)[CKA_UNWRAP_TEMPLATE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_UNWRAP_TEMPLATE]->type = CKA_UNWRAP_TEMPLATE;
	(*defaultTemplate)[CKA_UNWRAP_TEMPLATE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_UNWRAP_TEMPLATE]->pValue = NULL;

	//CKA_VALUE - required
	(*defaultTemplate)[CKA_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VALUE]->type = CKA_VALUE;
	(*defaultTemplate)[CKA_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_VALUE]->pValue = NULL;

	//CKA_VALUE_LEN - read only
	(*defaultTemplate)[CKA_VALUE_LEN] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VALUE_LEN]->type = CKA_VALUE_LEN;
	(*defaultTemplate)[CKA_VALUE_LEN]->ulValueLen = sizeof (length);
	(*defaultTemplate)[CKA_VALUE_LEN]->pValue = new unsigned char*[sizeof (length)];
	memcpy((*defaultTemplate)[CKA_VALUE_LEN]->pValue, &length, (*defaultTemplate)[CKA_VALUE_LEN]->ulValueLen);
}

static CK_RV applyPubKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	int reqCount = 0;

	for (unsigned int i = 0; i < ulCount && !rv; i++)
	{
		switch (pTemplate[i].type)
		{
		case CKA_KEY_TYPE:
			reqCount++;
			// required attributes
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_MODULUS:
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_TRUSTED:
			rv = CKR_ATTRIBUTE_READ_ONLY;
			break;
		case CKA_CLASS:
			// We only end up in this function because this is set already.
		case CKA_MODULUS_BITS:
		case CKA_PUBLIC_EXPONENT:
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_LABEL:
		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:
		case CKA_DERIVE:
		case CKA_ALLOWED_MECHANISMS:
		case CKA_SUBJECT:
		case CKA_ENCRYPT:
		case CKA_VERIFY:
		case CKA_VERIFY_RECOVER:
		case CKA_WRAP:
		case CKA_WRAP_TEMPLATE:
			// optional attributes
			break;
		default:
			// extra invalid attributes
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
		}

		if (!rv)
		{
			if ((*defaultTemplate)[pTemplate[i].type]->pValue) delete [] (unsigned char*) (*defaultTemplate)[pTemplate[i].type]->pValue;
			(*defaultTemplate)[pTemplate[i].type]->ulValueLen = pTemplate[i].ulValueLen;
			(*defaultTemplate)[pTemplate[i].type]->pValue = new unsigned char[pTemplate[i].ulValueLen];
			memcpy((*defaultTemplate)[pTemplate[i].type]->pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);
		}
	}

	if (!rv && reqCount != 1)
		rv = CKR_TEMPLATE_INCOMPLETE;

	return rv;
}

static CK_RV applyPrivKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	int reqCount = 0;

	for (unsigned int i = 0; i < ulCount && !rv; i++)
	{
		switch (pTemplate[i].type)
		{
		case CKA_KEY_TYPE:
			// required attributes
			reqCount++;
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
		case CKA_MODULUS:
		case CKA_PUBLIC_EXPONENT:
		case CKA_PRIME_1:
		case CKA_PRIME_2:
		case CKA_EXPONENT_1:
		case CKA_EXPONENT_2:
		case CKA_COEFFICIENT:
			// read only attributes
			rv = CKR_ATTRIBUTE_READ_ONLY;
			break;
		case CKA_CLASS:
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_LABEL:
		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:
		case CKA_DERIVE:
		case CKA_ALLOWED_MECHANISMS:
		case CKA_SUBJECT:
		case CKA_SENSITIVE:
		case CKA_DECRYPT:
		case CKA_SIGN:
		case CKA_SIGN_RECOVER:
		case CKA_UNWRAP:
		case CKA_EXTRACTABLE:
		case CKA_WRAP_WITH_TRUSTED:
		case CKA_UNWRAP_TEMPLATE:
		case CKA_ALWAYS_AUTHENTICATE:
		case CKA_PRIVATE_EXPONENT:
			// optional attributes
			break;
		default:
			// extra invalid attributes
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
		}

		if (!rv)
		{
			if ((*defaultTemplate)[pTemplate[i].type]->pValue) delete [] (unsigned char*) (*defaultTemplate)[pTemplate[i].type]->pValue;
			(*defaultTemplate)[pTemplate[i].type]->ulValueLen = pTemplate[i].ulValueLen;
			(*defaultTemplate)[pTemplate[i].type]->pValue = new unsigned char[pTemplate[i].ulValueLen];
			memcpy((*defaultTemplate)[pTemplate[i].type]->pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);
		}
	}

	if (!rv && reqCount != 1) // check that magic number
		rv = CKR_TEMPLATE_INCOMPLETE;

	return rv;
}

static CK_RV applySecKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	int reqCount = 0;

	for (unsigned int i = 0; i < ulCount && !rv; i++)
	{
		switch (pTemplate[i].type)
		{
		case CKA_KEY_TYPE:
			reqCount++;
			// required attributes
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_VALUE:
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
			// read only attributes
			rv = CKR_ATTRIBUTE_READ_ONLY;
			break;
		case CKA_VALUE_LEN:
		case CKA_CLASS:
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_LABEL:
		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:
		case CKA_DERIVE:
		case CKA_ALLOWED_MECHANISMS:
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
		case CKA_TRUSTED:
		case CKA_WRAP_TEMPLATE:
		case CKA_UNWRAP_TEMPLATE:
			// optional attributes
			break;
		default:
			// extra invalid attributes
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
		}

		if (!rv)
		{
			if ((*defaultTemplate)[pTemplate[i].type]->pValue) delete [] (unsigned char*) (*defaultTemplate)[pTemplate[i].type]->pValue;
			(*defaultTemplate)[pTemplate[i].type]->ulValueLen = pTemplate[i].ulValueLen;
			(*defaultTemplate)[pTemplate[i].type]->pValue = new unsigned char[pTemplate[i].ulValueLen];
			memcpy((*defaultTemplate)[pTemplate[i].type]->pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);
		}
	}

	if (!rv && reqCount != 1)
		rv = CKR_TEMPLATE_INCOMPLETE;

	return rv;
}
