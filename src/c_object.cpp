/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo -at- goodvikings -dot- com> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day, and
 * you think this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include "log.h"
#include "p11.h"
#include "slot.h"
#include <map>
#include <string.h>
#include <vector>

extern bool cryptokiInitialized;
extern std::vector<slot*>* slots;

extern int getSlotBySession(CK_SESSION_HANDLE hSession);

static CK_OBJECT_HANDLE_PTR findResults = NULL;
static unsigned int nextResult = 0;
static unsigned int resultLen = 0;

static void generateDefaultDataTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static void generateDefaultX509Template(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static void generateDefaultX509AttrTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static void generateDefaultWTLSTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static void generateDefaultPubKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static void generateDefaultPrivKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static void generateDefaultSecKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate);
static CK_RV applyDataTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV applyX509Template(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV applyX509AttrTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV applyWTLSTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV applyPubKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV applyPrivKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
static CK_RV applySecKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate = NULL;
	CK_ATTRIBUTE_TYPE* attrType = NULL;
	CK_ATTRIBUTE_TYPE* certType = NULL;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && (state == CKS_RO_USER_FUNCTIONS || state == CKS_RO_PUBLIC_SESSION))
		rv = CKR_SESSION_READ_ONLY;
	if (!rv && !pTemplate)
		rv = CKR_ARGUMENTS_BAD;

	if (!rv)
	{
		for (unsigned int i = 0; i < ulCount; i++)
			if (pTemplate[i].type == CKA_CLASS)
			{
				attrType = (CK_ATTRIBUTE_TYPE*) pTemplate[i].pValue;
				break;
			}
		if (!attrType)
			rv = CKR_TEMPLATE_INCOMPLETE;
	}

	if (!rv)
	{
		defaultTemplate = new std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>;
		if (!defaultTemplate)
			rv = CKR_DEVICE_MEMORY;
	}

	if (!rv)
	{
		switch (*attrType)
		{
		case CKO_DATA:
			generateDefaultDataTemplate(defaultTemplate);
			rv = applyDataTemplate(defaultTemplate, pTemplate, ulCount);
			break;
		case CKO_PUBLIC_KEY:
			generateDefaultPubKeyTemplate(defaultTemplate);
			rv = applyPubKeyTemplate(defaultTemplate, pTemplate, ulCount);
			break;
		case CKO_SECRET_KEY:
			generateDefaultSecKeyTemplate(defaultTemplate);
			rv = applySecKeyTemplate(defaultTemplate, pTemplate, ulCount);
			break;
		case CKO_PRIVATE_KEY:
			generateDefaultPrivKeyTemplate(defaultTemplate);
			rv = applyPrivKeyTemplate(defaultTemplate, pTemplate, ulCount);
			break;
		case CKO_CERTIFICATE:
			for (unsigned int i = 0; i < ulCount; i++)
				if (pTemplate[i].type == CKA_CERTIFICATE_TYPE)
				{
					certType = (CK_ATTRIBUTE_TYPE*) pTemplate[i].pValue;
					break;
				}
			if (!certType)
			{
				rv = CKR_TEMPLATE_INCOMPLETE;
				break;
			}
			switch (*certType)
			{
			case CKC_X_509:
				generateDefaultX509Template(defaultTemplate);
				rv = applyX509Template(defaultTemplate, pTemplate, ulCount);
				break;
			case CKC_X_509_ATTR_CERT:
				generateDefaultX509AttrTemplate(defaultTemplate);
				rv = applyX509AttrTemplate(defaultTemplate, pTemplate, ulCount);
				break;
			case CKC_WTLS:
				generateDefaultWTLSTemplate(defaultTemplate);
				rv = applyWTLSTemplate(defaultTemplate, pTemplate, ulCount);
				break;
			}
			break;
		default:
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	if (!rv)
	{
		if (!(*slots)[slot]->createObject(hSession, defaultTemplate, phObject))
			rv = CKR_DEVICE_ERROR;
	}

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

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && (state == CKS_RO_USER_FUNCTIONS || state == CKS_RO_PUBLIC_SESSION))
		rv = CKR_SESSION_READ_ONLY;
	if (!rv && ((!pTemplate && ulCount > 0) || !phNewObject))
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && !(*slots)[slot]->tokenHasObjectByHandle(hObject))
		rv = CKR_OBJECT_HANDLE_INVALID;

	if (!rv)
		rv = (*slots)[slot]->copyObject(hSession, hObject, pTemplate, ulCount, phNewObject);

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && (state == CKS_RO_USER_FUNCTIONS || state == CKS_RO_PUBLIC_SESSION))
		rv = CKR_SESSION_READ_ONLY;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && !(*slots)[slot]->tokenHasObjectByHandle(hObject))
		rv = CKR_OBJECT_HANDLE_INVALID;
	if (!rv)
		if (!(*slots)[slot]->destroyObject(hObject))
			rv = CKR_DEVICE_ERROR;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pulSize)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && !(*slots)[slot]->tokenHasObjectByHandle(hObject))
		rv = CKR_OBJECT_HANDLE_INVALID;

	if (!rv)
		if (!(*slots)[slot]->getObjectSize(hObject, pulSize))
			rv = CKR_DEVICE_ERROR;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !pTemplate)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && !(*slots)[slot]->tokenHasObjectByHandle(hObject))
		rv = CKR_OBJECT_HANDLE_INVALID;

	if (!rv)
		rv = (*slots)[slot]->getAttributeValues(hObject, pTemplate, ulCount);

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;

	int slot = getSlotBySession(hSession);
	CK_STATE state = (*slots)[slot]->getTokenState();
	unsigned char* modifiable = NULL;
	unsigned int buffLen = 0;

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !(state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS))
		rv = CKR_USER_NOT_LOGGED_IN;
	if (!rv && (state == CKS_RO_USER_FUNCTIONS || state == CKS_RO_PUBLIC_SESSION))
		rv = CKR_SESSION_READ_ONLY;
	if (!rv && !pTemplate && ulCount > 0)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && !(*slots)[slot]->tokenHasObjectByHandle(hObject))
		rv = CKR_OBJECT_HANDLE_INVALID;
	if (!rv && (*slots)[slot]->getObjectAttributeData(hObject, CKA_MODIFIABLE, (void**) &modifiable, &buffLen) && *(CK_BBOOL*) modifiable == false)
		rv = CKR_ATTRIBUTE_READ_ONLY;
	if (!rv)
		rv = (*slots)[slot]->setAttributeValues(hObject, pTemplate, ulCount, false);

	if (modifiable) delete [] modifiable;

	LOG_RETURNCODE(rv);

	return rv;
}

// <editor-fold defaultstate="collapsed" desc="Find Objects">

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && findResults)
		rv = CKR_OPERATION_ACTIVE;
	if (!rv && ulCount > 0 && !pTemplate)
		rv = CKR_ARGUMENTS_BAD;

	if (!rv)
		if (!(*slots)[slot]->findObjects(pTemplate, ulCount, &findResults, &resultLen))
			rv = CKR_DEVICE_ERROR;

	if (!rv)
		nextResult = 0;
	else
		if (findResults) delete findResults;

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !findResults)
		rv = CKR_OPERATION_NOT_INITIALIZED;
	if (!rv && !phObject)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && !ulMaxObjectCount)
		rv = CKR_ARGUMENTS_BAD;
	if (!rv && !pulObjectCount)
		rv = CKR_ARGUMENTS_BAD;

	if (!rv)
	{
		*pulObjectCount = ulMaxObjectCount;

		if (resultLen - nextResult < *pulObjectCount)
			*pulObjectCount = resultLen - nextResult;

		memcpy(phObject, &findResults[nextResult], *pulObjectCount * sizeof (CK_OBJECT_HANDLE));

		nextResult += *pulObjectCount;
	}

	LOG_RETURNCODE(rv);

	return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	LOG_INSTANCE(NULL);
	LOG_FUNCTIONCALL();

	CK_RV rv = CKR_OK;
	int slot = getSlotBySession(hSession);

	if (!rv && !cryptokiInitialized)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!rv && slot == -1)
		rv = CKR_SESSION_HANDLE_INVALID;
	if (!rv && !findResults)
		rv = CKR_OPERATION_NOT_INITIALIZED;

	if (!rv)
	{
		if (findResults) delete [] findResults;
		findResults = NULL;
		nextResult = 0;
		resultLen = 0;
	}

	LOG_RETURNCODE(rv);

	return rv;
}
// </editor-fold>

// <editor-fold defaultstate="collapsed" desc="Templating">

static void generateDefaultDataTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate)
{
	/**
	 Attributes:
	
	 Data is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_DATA
	 [storage]
		CKA_TOKEN - Defaults to True
		CKA_PRIVATE - defaults to false
		CKA_MODIFIABLE - defaults to true
		CKA_LABEL - defaults to empty string
	 [Data]
		CKA_APPLICATION - default empty
		CKA_OBJECT_ID - default empty
		CKA_VALUE - default empty
	 */

	CK_OBJECT_CLASS objClass = CKO_DATA;
	CK_BBOOL b = CK_TRUE;

	// CKA_CLASS -> CKO_DATA
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

	// CKA_APPLICATION -> empty string
	(*defaultTemplate)[CKA_APPLICATION] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_APPLICATION]->type = CKA_APPLICATION;
	(*defaultTemplate)[CKA_APPLICATION]->ulValueLen = 0;
	(*defaultTemplate)[CKA_APPLICATION]->pValue = NULL;

	// CKA_LABEL -> empty string
	(*defaultTemplate)[CKA_OBJECT_ID] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_OBJECT_ID]->type = CKA_OBJECT_ID;
	(*defaultTemplate)[CKA_OBJECT_ID]->ulValueLen = 0;
	(*defaultTemplate)[CKA_OBJECT_ID]->pValue = NULL;

	// CKA_APPLICATION -> empty string
	(*defaultTemplate)[CKA_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VALUE]->type = CKA_VALUE;
	(*defaultTemplate)[CKA_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_VALUE]->pValue = NULL;
}

static void generateDefaultX509Template(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate)
{
	/**
	 Attributes:
	
	 X509 Cert is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_CERTIFICATE
	 [storage]
		CKA_TOKEN - Defaults to True
		CKA_PRIVATE - defaults to false
		CKA_MODIFIABLE - defaults to true
		CKA_LABEL - defaults to empty string
	 [Cert]
		CKA_CERTIFICATE_TYPE - required, no default
		CKA_TRUSTED - set only by SO user (read only)
		CKA_CERTIFICATE_CATEGORY - default 0
		CKA_CHECK_VALUE - first three bytes of sha1 of cert
		CKA_START_DATE - default empty
		CKA_END_DATE - default empty
	 [X509]
		CKA_SUBJECT - Required
		CKA_ID - default empty
		CKA_ISSUER - default empty
		CKA_SERIAL_NUMBER - defautl empty
		CKA_VALUE - required
		CKA_URL - default empty
		CKA_HASH_OF_SUBJECT_PUBLIC_KEY - default empty
		CKA_HASH_OF_ISSUER_PUBLIC_KEY - default empty
		CKA_JAVA_MIDP_SECURITY_DOMAIN - default 0
	 */

	CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
	CK_BBOOL b = CK_TRUE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ULONG ul = 0;

	// CKA_CLASS -> CKO_DATA
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

	// CKA_CERTIFICATE_TYPE - required, no default
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->type = CKA_CERTIFICATE_TYPE;
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->ulValueLen = sizeof (certType);
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->pValue = new unsigned char*[sizeof (certType)];
	memcpy((*defaultTemplate)[CKA_CERTIFICATE_TYPE]->pValue, &certType, (*defaultTemplate)[CKA_CERTIFICATE_TYPE]->ulValueLen);

	// CKA_TRUSTED - set only by SO user (read only)
	b = CK_FALSE;
	(*defaultTemplate)[CKA_TRUSTED] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_TRUSTED]->type = CKA_TRUSTED;
	(*defaultTemplate)[CKA_TRUSTED]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_TRUSTED]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_TRUSTED]->pValue, &b, (*defaultTemplate)[CKA_TRUSTED]->ulValueLen);

	// CKA_CERTIFICATE_CATEGORY - default 0
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->type = CKA_CERTIFICATE_CATEGORY;
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->ulValueLen = sizeof (ul);
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->pValue = new unsigned char*[sizeof (ul)];
	memcpy((*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->pValue, &ul, (*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->ulValueLen);

	// CKA_CHECK_VALUE - first three bytes of sha1 of cert
	(*defaultTemplate)[CKA_CHECK_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CHECK_VALUE]->type = CKA_CHECK_VALUE;
	(*defaultTemplate)[CKA_CHECK_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_CHECK_VALUE]->pValue = NULL;

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

	// CKA_SUBJECT - Required
	(*defaultTemplate)[CKA_SUBJECT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SUBJECT]->type = CKA_SUBJECT;
	(*defaultTemplate)[CKA_SUBJECT]->ulValueLen = 0;
	(*defaultTemplate)[CKA_SUBJECT]->pValue = NULL;

	// CKA_ID - default empty
	(*defaultTemplate)[CKA_ID] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ID]->type = CKA_ID;
	(*defaultTemplate)[CKA_ID]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ID]->pValue = NULL;

	// CKA_ISSUER - default empty
	(*defaultTemplate)[CKA_ISSUER] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ISSUER]->type = CKA_ISSUER;
	(*defaultTemplate)[CKA_ISSUER]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ISSUER]->pValue = NULL;

	// CKA_SERIAL_NUMBER - defautl empty
	(*defaultTemplate)[CKA_SERIAL_NUMBER] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SERIAL_NUMBER]->type = CKA_SERIAL_NUMBER;
	(*defaultTemplate)[CKA_SERIAL_NUMBER]->ulValueLen = 0;
	(*defaultTemplate)[CKA_SERIAL_NUMBER]->pValue = NULL;

	// CKA_VALUE - required
	(*defaultTemplate)[CKA_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VALUE]->type = CKA_VALUE;
	(*defaultTemplate)[CKA_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_VALUE]->pValue = NULL;

	// CKA_URL - default empty
	(*defaultTemplate)[CKA_URL] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_URL]->type = CKA_URL;
	(*defaultTemplate)[CKA_URL]->ulValueLen = 0;
	(*defaultTemplate)[CKA_URL]->pValue = NULL;

	// CKA_HASH_OF_SUBJECT_PUBLIC_KEY - default empty
	(*defaultTemplate)[CKA_HASH_OF_SUBJECT_PUBLIC_KEY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_HASH_OF_SUBJECT_PUBLIC_KEY]->type = CKA_HASH_OF_SUBJECT_PUBLIC_KEY;
	(*defaultTemplate)[CKA_HASH_OF_SUBJECT_PUBLIC_KEY]->ulValueLen = 0;
	(*defaultTemplate)[CKA_HASH_OF_SUBJECT_PUBLIC_KEY]->pValue = NULL;

	// CKA_HASH_OF_ISSUER_PUBLIC_KEY - default empty
	(*defaultTemplate)[CKA_HASH_OF_ISSUER_PUBLIC_KEY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_HASH_OF_ISSUER_PUBLIC_KEY]->type = CKA_HASH_OF_ISSUER_PUBLIC_KEY;
	(*defaultTemplate)[CKA_HASH_OF_ISSUER_PUBLIC_KEY]->ulValueLen = 0;
	(*defaultTemplate)[CKA_HASH_OF_ISSUER_PUBLIC_KEY]->pValue = NULL;

	// CKA_JAVA_MIDP_SECURITY_DOMAIN - default 0
	(*defaultTemplate)[CKA_JAVA_MIDP_SECURITY_DOMAIN] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_JAVA_MIDP_SECURITY_DOMAIN]->type = CKA_JAVA_MIDP_SECURITY_DOMAIN;
	(*defaultTemplate)[CKA_JAVA_MIDP_SECURITY_DOMAIN]->ulValueLen = sizeof (ul);
	(*defaultTemplate)[CKA_JAVA_MIDP_SECURITY_DOMAIN]->pValue = new unsigned char*[sizeof (ul)];
	memcpy((*defaultTemplate)[CKA_JAVA_MIDP_SECURITY_DOMAIN]->pValue, &ul, (*defaultTemplate)[CKA_JAVA_MIDP_SECURITY_DOMAIN]->ulValueLen);
}

static void generateDefaultX509AttrTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate)
{
	/**
	 Attributes:
	
	 X509 Cert attr is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_CERTIFICATE
	 [storage]
		CKA_TOKEN - Defaults to True
		CKA_PRIVATE - defaults to false
		CKA_MODIFIABLE - defaults to true
		CKA_LABEL - defaults to empty string
	 [Cert]
		CKA_CERTIFICATE_TYPE - required, no default
		CKA_TRUSTED - set only by SO user (read only)
		CKA_CERTIFICATE_CATEGORY - default 0
		CKA_CHECK_VALUE - first three bytes of sha1 of cert
		CKA_START_DATE - default empty
		CKA_END_DATE - default empty
	 [X509 Attr]
		CKA_OWNER - required
		CKA_AC_ISSUER - default empty
		CKA_SERIAL_NUMBER - default empty
		CKA_ATTR_TYPES - default empty
		CKA_VALUE - required
	 */

	CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
	CK_BBOOL b = CK_TRUE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509_ATTR_CERT;
	CK_ULONG ul = 0;

	// CKA_CLASS -> CKO_DATA
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

	// CKA_CERTIFICATE_TYPE - required, no default
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->type = CKA_CERTIFICATE_TYPE;
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->ulValueLen = sizeof (certType);
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->pValue = new unsigned char*[sizeof (certType)];
	memcpy((*defaultTemplate)[CKA_CERTIFICATE_TYPE]->pValue, &certType, (*defaultTemplate)[CKA_CERTIFICATE_TYPE]->ulValueLen);

	// CKA_TRUSTED - set only by SO user (read only)
	b = CK_FALSE;
	(*defaultTemplate)[CKA_TRUSTED] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_TRUSTED]->type = CKA_TRUSTED;
	(*defaultTemplate)[CKA_TRUSTED]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_TRUSTED]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_TRUSTED]->pValue, &b, (*defaultTemplate)[CKA_TRUSTED]->ulValueLen);

	// CKA_CERTIFICATE_CATEGORY - default 0
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->type = CKA_CERTIFICATE_CATEGORY;
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->ulValueLen = sizeof (ul);
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->pValue = new unsigned char*[sizeof (ul)];
	memcpy((*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->pValue, &ul, (*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->ulValueLen);

	// CKA_CHECK_VALUE - first three bytes of sha1 of cert
	(*defaultTemplate)[CKA_CHECK_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CHECK_VALUE]->type = CKA_CHECK_VALUE;
	(*defaultTemplate)[CKA_CHECK_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_CHECK_VALUE]->pValue = NULL;

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

	// CKA_OWNER - required
	(*defaultTemplate)[CKA_OWNER] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_OWNER]->type = CKA_OWNER;
	(*defaultTemplate)[CKA_OWNER]->ulValueLen = 0;
	(*defaultTemplate)[CKA_OWNER]->pValue = NULL;

	// CKA_AC_ISSUER - default empty
	(*defaultTemplate)[CKA_AC_ISSUER] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_AC_ISSUER]->type = CKA_AC_ISSUER;
	(*defaultTemplate)[CKA_AC_ISSUER]->ulValueLen = 0;
	(*defaultTemplate)[CKA_AC_ISSUER]->pValue = NULL;

	// CKA_SERIAL_NUMBER - default empty
	(*defaultTemplate)[CKA_SERIAL_NUMBER] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SERIAL_NUMBER]->type = CKA_SERIAL_NUMBER;
	(*defaultTemplate)[CKA_SERIAL_NUMBER]->ulValueLen = 0;
	(*defaultTemplate)[CKA_SERIAL_NUMBER]->pValue = NULL;

	// CKA_ATTR_TYPES - default empty
	(*defaultTemplate)[CKA_ATTR_TYPES] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ATTR_TYPES]->type = CKA_ATTR_TYPES;
	(*defaultTemplate)[CKA_ATTR_TYPES]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ATTR_TYPES]->pValue = NULL;

	// CKA_VALUE - required
	(*defaultTemplate)[CKA_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VALUE]->type = CKA_VALUE;
	(*defaultTemplate)[CKA_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_VALUE]->pValue = NULL;
}

static void generateDefaultWTLSTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate)
{
	/**
	 Attributes:
	
	 WTLS cert is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_CERTIFICATE
	 [storage]
		CKA_TOKEN - Defaults to True
		CKA_PRIVATE - defaults to false
		CKA_MODIFIABLE - defaults to true
		CKA_LABEL - defaults to empty string
	 [Cert]
		CKA_CERTIFICATE_TYPE - required, no default
		CKA_TRUSTED - set only by SO user (read only)
		CKA_CERTIFICATE_CATEGORY - default 0
		CKA_CHECK_VALUE - first three bytes of sha1 of cert
		CKA_START_DATE - default empty
		CKA_END_DATE - default empty
	 [WTLS]
		CKA_SUBJECT - required
		CKA_ISSUER - default empty
		CKA_VALUE - required
		CKA_URL - default empty
		CKA_HASH_OF_SUBJECT_PUBLIC_KEY - default empty
		CKA_HASH_OF_ISSUER_PUBLIC_KEY - default empty
	 */

	CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
	CK_BBOOL b = CK_TRUE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509_ATTR_CERT;
	CK_ULONG ul = 0;

	// CKA_CLASS -> CKO_DATA
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

	// CKA_CERTIFICATE_TYPE - required, no default
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->type = CKA_CERTIFICATE_TYPE;
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->ulValueLen = sizeof (certType);
	(*defaultTemplate)[CKA_CERTIFICATE_TYPE]->pValue = new unsigned char*[sizeof (certType)];
	memcpy((*defaultTemplate)[CKA_CERTIFICATE_TYPE]->pValue, &certType, (*defaultTemplate)[CKA_CERTIFICATE_TYPE]->ulValueLen);

	// CKA_TRUSTED - set only by SO user (read only)
	b = CK_FALSE;
	(*defaultTemplate)[CKA_TRUSTED] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_TRUSTED]->type = CKA_TRUSTED;
	(*defaultTemplate)[CKA_TRUSTED]->ulValueLen = sizeof (b);
	(*defaultTemplate)[CKA_TRUSTED]->pValue = new unsigned char*[sizeof (b)];
	memcpy((*defaultTemplate)[CKA_TRUSTED]->pValue, &b, (*defaultTemplate)[CKA_TRUSTED]->ulValueLen);

	// CKA_CERTIFICATE_CATEGORY - default 0
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->type = CKA_CERTIFICATE_CATEGORY;
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->ulValueLen = sizeof (ul);
	(*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->pValue = new unsigned char*[sizeof (ul)];
	memcpy((*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->pValue, &ul, (*defaultTemplate)[CKA_CERTIFICATE_CATEGORY]->ulValueLen);

	// CKA_CHECK_VALUE - first three bytes of sha1 of cert
	(*defaultTemplate)[CKA_CHECK_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_CHECK_VALUE]->type = CKA_CHECK_VALUE;
	(*defaultTemplate)[CKA_CHECK_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_CHECK_VALUE]->pValue = NULL;

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

	// CKA_SUBJECT - Required
	(*defaultTemplate)[CKA_SUBJECT] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_SUBJECT]->type = CKA_SUBJECT;
	(*defaultTemplate)[CKA_SUBJECT]->ulValueLen = 0;
	(*defaultTemplate)[CKA_SUBJECT]->pValue = NULL;

	// CKA_ISSUER - default empty
	(*defaultTemplate)[CKA_ISSUER] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_ISSUER]->type = CKA_ISSUER;
	(*defaultTemplate)[CKA_ISSUER]->ulValueLen = 0;
	(*defaultTemplate)[CKA_ISSUER]->pValue = NULL;

	// CKA_VALUE - required
	(*defaultTemplate)[CKA_VALUE] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_VALUE]->type = CKA_VALUE;
	(*defaultTemplate)[CKA_VALUE]->ulValueLen = 0;
	(*defaultTemplate)[CKA_VALUE]->pValue = NULL;

	// CKA_URL - default empty
	(*defaultTemplate)[CKA_URL] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_URL]->type = CKA_URL;
	(*defaultTemplate)[CKA_URL]->ulValueLen = 0;
	(*defaultTemplate)[CKA_URL]->pValue = NULL;

	// CKA_HASH_OF_SUBJECT_PUBLIC_KEY - default empty
	(*defaultTemplate)[CKA_HASH_OF_SUBJECT_PUBLIC_KEY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_HASH_OF_SUBJECT_PUBLIC_KEY]->type = CKA_HASH_OF_SUBJECT_PUBLIC_KEY;
	(*defaultTemplate)[CKA_HASH_OF_SUBJECT_PUBLIC_KEY]->ulValueLen = 0;
	(*defaultTemplate)[CKA_HASH_OF_SUBJECT_PUBLIC_KEY]->pValue = NULL;

	// CKA_HASH_OF_ISSUER_PUBLIC_KEY - default empty
	(*defaultTemplate)[CKA_HASH_OF_ISSUER_PUBLIC_KEY] = new CK_ATTRIBUTE;
	(*defaultTemplate)[CKA_HASH_OF_ISSUER_PUBLIC_KEY]->type = CKA_HASH_OF_ISSUER_PUBLIC_KEY;
	(*defaultTemplate)[CKA_HASH_OF_ISSUER_PUBLIC_KEY]->ulValueLen = 0;
	(*defaultTemplate)[CKA_HASH_OF_ISSUER_PUBLIC_KEY]->pValue = NULL;
}

static void generateDefaultPubKeyTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate)
{
	/**
	 Attributes:
	
	 public key is allowed attributes of:
	 [object]
		CKA_CLASS - defaults to CKO_PUBLIC_KEY
	 [storage]
		CKA_TOKEN - Defaults to True
		CKA_PRIVATE - defaults to false
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
	 [Public Key]
		CKA_SUBJECT - default empty
		CKA_ENCRYPT - default true
		CKA_VERIFY - default true
		CKA_VERIFY_RECOVER - default true
		CKA_WRAP - default true
		CKA_TRUSTED - read only
		CKA_WRAP_TEMPLATE - default empty
	 [Other]
		CKA_MODULUS - required
		CKA_MODULUS_BITS - read only
		CKA_PUBLIC_EXPONENT - required
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
	b = CK_TRUE;
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
		CKA_MODULUS - required
		CKA_PUBLIC_EXPONENT - optional
		CKA_PRIVATE_EXPONENT - required
		CKA_PRIME_1 - optional
		CKA_PRIME_2 - optional
		CKA_EXPONENT_1 - optional
		CKA_EXPONENT_2 - optional
		CKA_COEFFICIENT - optional
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
		CKA_VALUE - required
		CKA_VALUE_LEN - read only
	 */

	CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
	CK_BBOOL b = CK_TRUE;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ULONG len = 0;

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
	(*defaultTemplate)[CKA_VALUE_LEN]->ulValueLen = sizeof (len);
	(*defaultTemplate)[CKA_VALUE_LEN]->pValue = new unsigned char*[sizeof (len)];
	memcpy((*defaultTemplate)[CKA_VALUE_LEN]->pValue, &len, (*defaultTemplate)[CKA_VALUE_LEN]->ulValueLen);
}

static CK_RV applyDataTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	int reqCount = 0;

	for (unsigned int i = 0; i < ulCount && !rv; i++)
	{
		switch (pTemplate[i].type)
		{
		case CKA_VALUE:
			reqCount++;
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_CLASS:
			// We only end up in this function because this is set already.
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_LABEL:
		case CKA_APPLICATION:
		case CKA_OBJECT_ID:
			break;
		default:
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

static CK_RV applyX509Template(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	int reqCount = 0;

	for (unsigned int i = 0; i < ulCount && !rv; i++)
	{
		switch (pTemplate[i].type)
		{
		case CKA_VALUE:
		case CKA_CERTIFICATE_TYPE:
		case CKA_SUBJECT:
			// required attributes
			reqCount++;
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_TRUSTED:
			// read only attributes
			rv = CKR_ATTRIBUTE_READ_ONLY;
			break;
		case CKA_CLASS:
			// We only end up in this function because this is set already.
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_LABEL:
		case CKA_CERTIFICATE_CATEGORY:
		case CKA_CHECK_VALUE:
		case CKA_START_DATE:
		case CKA_END_DATE:
		case CKA_ID:
		case CKA_ISSUER:
		case CKA_SERIAL_NUMBER:
		case CKA_URL:
		case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		case CKA_JAVA_MIDP_SECURITY_DOMAIN:
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

	if (!rv && reqCount != 3)
		rv = CKR_TEMPLATE_INCOMPLETE;

	return rv;
}

static CK_RV applyX509AttrTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	int reqCount = 0;

	for (unsigned int i = 0; i < ulCount && !rv; i++)
	{
		switch (pTemplate[i].type)
		{
		case CKA_VALUE:
		case CKA_CERTIFICATE_TYPE:
		case CKA_OWNER:
			// required attributes
			reqCount++;
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_TRUSTED:
			// read only attributes
			rv = CKR_ATTRIBUTE_READ_ONLY;
			break;
		case CKA_CLASS:
			// We only end up in this function because this is set already.
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_LABEL:
		case CKA_CERTIFICATE_CATEGORY:
		case CKA_CHECK_VALUE:
		case CKA_START_DATE:
		case CKA_END_DATE:
		case CKA_AC_ISSUER:
		case CKA_SERIAL_NUMBER:
		case CKA_ATTR_TYPES:
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

	if (!rv && reqCount != 3)
		rv = CKR_TEMPLATE_INCOMPLETE;

	return rv;
}

static CK_RV applyWTLSTemplate(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>* defaultTemplate, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	int reqCount = 0;

	for (unsigned int i = 0; i < ulCount && !rv; i++)
	{
		switch (pTemplate[i].type)
		{
		case CKA_VALUE:
		case CKA_CERTIFICATE_TYPE:
		case CKA_SUBJECT:
			reqCount++;
			// required attributes
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_TRUSTED:
			// read only attributes
			rv = CKR_ATTRIBUTE_READ_ONLY;
			break;
		case CKA_CLASS:
			// We only end up in this function because this is set already.
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_LABEL:
		case CKA_CERTIFICATE_CATEGORY:
		case CKA_CHECK_VALUE:
		case CKA_START_DATE:
		case CKA_END_DATE:
		case CKA_ISSUER:
		case CKA_URL:
		case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
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

	if (!rv && reqCount != 3)
		rv = CKR_TEMPLATE_INCOMPLETE;

	return rv;
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
		case CKA_MODULUS:
		case CKA_PUBLIC_EXPONENT:
			reqCount++;
			// required attributes
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_TRUSTED:
		case CKA_MODULUS_BITS:
			rv = CKR_ATTRIBUTE_READ_ONLY;
			break;
		case CKA_CLASS:
			// We only end up in this function because this is set already.
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

	if (!rv && reqCount != 3)
		rv = CKR_TEMPLATE_INCOMPLETE;

	// apply read only values that do not have suitable defaults
	if (!rv)
	{
		*(CK_ULONG*) (*defaultTemplate)[CKA_MODULUS_BITS]->pValue = (*defaultTemplate)[CKA_MODULUS]->ulValueLen * 8;
	}

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
		case CKA_MODULUS:
		case CKA_PRIVATE_EXPONENT:
			// required attributes
			reqCount++;
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
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
		case CKA_PUBLIC_EXPONENT:
		case CKA_PRIME_1:
		case CKA_PRIME_2:
		case CKA_EXPONENT_1:
		case CKA_EXPONENT_2:
		case CKA_COEFFICIENT:
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

	if (!rv && reqCount != 3) // check that magic number
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
		case CKA_VALUE:
			reqCount++;
			// required attributes
			if (!pTemplate[i].pValue)
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			break;
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
		case CKA_VALUE_LEN:
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

	if (!rv && reqCount != 3)
		rv = CKR_TEMPLATE_INCOMPLETE;

	// apply read only values that do not have suitable defaults
	if (!rv)
	{
		*(CK_ULONG*) (*defaultTemplate)[CKA_VALUE_LEN]->pValue = (*defaultTemplate)[CKA_VALUE]->ulValueLen;
	}

	return rv;
}
// </editor-fold>
