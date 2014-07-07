/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <iomanip>
#include <pthread.h>
#include <fstream>
#include <sys/time.h>
#include "log.h"
#include "p11.h"
using namespace std;

logger* logger::instance = NULL;

logger* logger::getInstance(const char* filename)
{
	if (!instance)
	{
		instance = new logger;
		instance->fout->open(filename);
	}

	return instance;
}

void logger::destroy()
{
	if (instance)
	{
		delete instance;
	}
}

logger::logger()
{
	lock = new pthread_mutex_t;
	fout = new ofstream;
	pthread_mutex_init(lock, NULL);
}

logger::~logger()
{
	pthread_mutex_lock(lock);
	pthread_mutex_unlock(lock);
	pthread_mutex_destroy(lock);

	if (fout)
	{
		fout->close();
	}

	delete lock;
	delete fout;
}

void logger::log_event(const char* eventText, const char* func, const char* file, const long lineNo) const
{
	pthread_mutex_lock(lock);

	struct timeval *tp = new struct timeval;
	gettimeofday(tp, NULL);

	*fout << tp->tv_sec << setw(3) << setfill('0') << tp->tv_usec / 1000 << " Thread: " << pthread_self() << " " << file << ":" << func << "():" << lineNo << " - " << eventText << endl;

	delete tp;

	pthread_mutex_unlock(lock);
}

void logger::log_functionCall(const char* function, const char* file, const long lineNo) const
{
	pthread_mutex_lock(lock);

	struct timeval *tp = new struct timeval;
	gettimeofday(tp, NULL);

	*fout << tp->tv_sec << setw(3) << setfill('0') << tp->tv_usec / 1000 << " Thread: " << pthread_self() << " " << file << ":" << function << "():" << lineNo << " - " << function << " entered" << endl;

	delete tp;

	pthread_mutex_unlock(lock);
}

void logger::log_returnCode(const CK_RV rc, const char* func, const char* file, const long lineNo) const
{
	pthread_mutex_lock(lock);

	struct timeval *tp = new struct timeval;
	gettimeofday(tp, NULL);

	*fout << tp->tv_sec << setw(3) << setfill('0') << tp->tv_usec / 1000 << " Thread: " << pthread_self() << " " << file << ":" << func << "():" << lineNo << " - " << func << " returned " << convertReturnVode(rc) << endl;

	delete tp;

	pthread_mutex_unlock(lock);
}

const char* logger::convertReturnVode(const CK_RV rv) const
{
	const char* rc = NULL;

	switch (rv)
	{
	case CKR_OK:
		rc = "CKR_OK";
		break;
	case CKR_CANCEL:
		rc = "CKR_CANCEL";
		break;
	case CKR_HOST_MEMORY:
		rc = "CKR_HOST_MEMORY";
		break;
	case CKR_SLOT_ID_INVALID:
		rc = "CKR_SLOT_ID_INVALID";
		break;
	case CKR_GENERAL_ERROR:
		rc = "CKR_GENERAL_ERROR";
		break;
	case CKR_FUNCTION_FAILED:
		rc = "CKR_FUNCTION_FAILED";
		break;
	case CKR_ARGUMENTS_BAD:
		rc = "CKR_ARGUMENTS_BAD";
		break;
	case CKR_NO_EVENT:
		rc = "CKR_NO_EVENT";
		break;
	case CKR_NEED_TO_CREATE_THREADS:
		rc = "CKR_NEED_TO_CREATE_THREADS";
		break;
	case CKR_CANT_LOCK:
		rc = "CKR_CANT_LOCK";
		break;
	case CKR_ATTRIBUTE_READ_ONLY:
		rc = "CKR_ATTRIBUTE_READ_ONLY";
		break;
	case CKR_ATTRIBUTE_SENSITIVE:
		rc = "CKR_ATTRIBUTE_SENSITIVE";
		break;
	case CKR_ATTRIBUTE_TYPE_INVALID:
		rc = "CKR_ATTRIBUTE_TYPE_INVALID";
		break;
	case CKR_ATTRIBUTE_VALUE_INVALID:
		rc = "CKR_ATTRIBUTE_VALUE_INVALID";
		break;
	case CKR_DATA_INVALID:
		rc = "CKR_DATA_INVALID";
		break;
	case CKR_DATA_LEN_RANGE:
		rc = "CKR_DATA_LEN_RANGE";
		break;
	case CKR_DEVICE_ERROR:
		rc = "CKR_DEVICE_ERROR";
		break;
	case CKR_DEVICE_MEMORY:
		rc = "CKR_DEVICE_MEMORY";
		break;
	case CKR_DEVICE_REMOVED:
		rc = "CKR_DEVICE_REMOVED";
		break;
	case CKR_ENCRYPTED_DATA_INVALID:
		rc = "CKR_ENCRYPTED_DATA_INVALID";
		break;
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
		rc = "CKR_ENCRYPTED_DATA_LEN_RANGE";
		break;
	case CKR_FUNCTION_CANCELED:
		rc = "CKR_FUNCTION_CANCELED";
		break;
	case CKR_FUNCTION_NOT_PARALLEL:
		rc = "CKR_FUNCTION_NOT_PARALLEL";
		break;
	case CKR_FUNCTION_NOT_SUPPORTED:
		rc = "CKR_FUNCTION_NOT_SUPPORTED";
		break;
	case CKR_KEY_HANDLE_INVALID:
		rc = "CKR_KEY_HANDLE_INVALID";
		break;
	case CKR_KEY_SIZE_RANGE:
		rc = "CKR_KEY_SIZE_RANGE";
		break;
	case CKR_KEY_TYPE_INCONSISTENT:
		rc = "CKR_KEY_TYPE_INCONSISTENT";
		break;
	case CKR_KEY_NOT_NEEDED:
		rc = "CKR_KEY_NOT_NEEDED";
		break;
	case CKR_KEY_CHANGED:
		rc = "CKR_KEY_CHANGED";
		break;
	case CKR_KEY_NEEDED:
		rc = "CKR_KEY_NEEDED";
		break;
	case CKR_KEY_INDIGESTIBLE:
		rc = "CKR_KEY_INDIGESTIBLE";
		break;
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
		rc = "CKR_KEY_FUNCTION_NOT_PERMITTED";
		break;
	case CKR_KEY_NOT_WRAPPABLE:
		rc = "CKR_KEY_NOT_WRAPPABLE";
		break;
	case CKR_KEY_UNEXTRACTABLE:
		rc = "CKR_KEY_UNEXTRACTABLE";
		break;
	case CKR_MECHANISM_INVALID:
		rc = "CKR_MECHANISM_INVALID";
		break;
	case CKR_MECHANISM_PARAM_INVALID:
		rc = "CKR_MECHANISM_PARAM_INVALID";
		break;
	case CKR_OBJECT_HANDLE_INVALID:
		rc = "CKR_OBJECT_HANDLE_INVALID";
		break;
	case CKR_OPERATION_ACTIVE:
		rc = "CKR_OPERATION_ACTIVE";
		break;
	case CKR_OPERATION_NOT_INITIALIZED:
		rc = "CKR_OPERATION_NOT_INITIALIZED";
		break;
	case CKR_PIN_INCORRECT:
		rc = "CKR_PIN_INCORRECT";
		break;
	case CKR_PIN_INVALID:
		rc = "CKR_PIN_INVALID";
		break;
	case CKR_PIN_LEN_RANGE:
		rc = "CKR_PIN_LEN_RANGE";
		break;
	case CKR_PIN_EXPIRED:
		rc = "CKR_PIN_EXPIRED";
		break;
	case CKR_PIN_LOCKED:
		rc = "CKR_PIN_LOCKED";
		break;
	case CKR_SESSION_CLOSED:
		rc = "CKR_SESSION_CLOSED";
		break;
	case CKR_SESSION_COUNT:
		rc = "CKR_SESSION_COUNT";
		break;
	case CKR_SESSION_HANDLE_INVALID:
		rc = "CKR_SESSION_HANDLE_INVALID";
		break;
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		rc = "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		break;
	case CKR_SESSION_READ_ONLY:
		rc = "CKR_SESSION_READ_ONLY";
		break;
	case CKR_SESSION_EXISTS:
		rc = "CKR_SESSION_EXISTS";
		break;
	case CKR_SESSION_READ_ONLY_EXISTS:
		rc = "CKR_SESSION_READ_ONLY_EXISTS";
		break;
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
		rc = "CKR_SESSION_READ_WRITE_SO_EXISTS";
		break;
	case CKR_SIGNATURE_INVALID:
		rc = "CKR_SIGNATURE_INVALID";
		break;
	case CKR_SIGNATURE_LEN_RANGE:
		rc = "CKR_SIGNATURE_LEN_RANGE";
		break;
	case CKR_TEMPLATE_INCOMPLETE:
		rc = "CKR_TEMPLATE_INCOMPLETE";
		break;
	case CKR_TEMPLATE_INCONSISTENT:
		rc = "CKR_TEMPLATE_INCONSISTENT";
		break;
	case CKR_TOKEN_NOT_PRESENT:
		rc = "CKR_TOKEN_NOT_PRESENT";
		break;
	case CKR_TOKEN_NOT_RECOGNIZED:
		rc = "CKR_TOKEN_NOT_RECOGNIZED";
		break;
	case CKR_TOKEN_WRITE_PROTECTED:
		rc = "CKR_TOKEN_WRITE_PROTECTED";
		break;
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
		rc = "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		break;
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		rc = "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		break;
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		rc = "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		break;
	case CKR_USER_ALREADY_LOGGED_IN:
		rc = "CKR_USER_ALREADY_LOGGED_IN";
		break;
	case CKR_USER_NOT_LOGGED_IN:
		rc = "CKR_USER_NOT_LOGGED_IN";
		break;
	case CKR_USER_PIN_NOT_INITIALIZED:
		rc = "CKR_USER_PIN_NOT_INITIALIZED";
		break;
	case CKR_USER_TYPE_INVALID:
		rc = "CKR_USER_TYPE_INVALID";
		break;
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		rc = "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		break;
	case CKR_USER_TOO_MANY_TYPES:
		rc = "CKR_USER_TOO_MANY_TYPES";
		break;
	case CKR_WRAPPED_KEY_INVALID:
		rc = "CKR_WRAPPED_KEY_INVALID";
		break;
	case CKR_WRAPPED_KEY_LEN_RANGE:
		rc = "CKR_WRAPPED_KEY_LEN_RANGE";
		break;
	case CKR_WRAPPING_KEY_HANDLE_INVALID:
		rc = "CKR_WRAPPING_KEY_HANDLE_INVALID";
		break;
	case CKR_WRAPPING_KEY_SIZE_RANGE:
		rc = "CKR_WRAPPING_KEY_SIZE_RANGE";
		break;
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
		rc = "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		break;
	case CKR_RANDOM_SEED_NOT_SUPPORTED:
		rc = "CKR_RANDOM_SEED_NOT_SUPPORTED";
		break;
	case CKR_RANDOM_NO_RNG:
		rc = "CKR_RANDOM_NO_RNG";
		break;
	case CKR_DOMAIN_PARAMS_INVALID:
		rc = "CKR_DOMAIN_PARAMS_INVALID";
		break;
	case CKR_BUFFER_TOO_SMALL:
		rc = "CKR_BUFFER_TOO_SMALL";
		break;
	case CKR_SAVED_STATE_INVALID:
		rc = "CKR_SAVED_STATE_INVALID";
		break;
	case CKR_INFORMATION_SENSITIVE:
		rc = "CKR_INFORMATION_SENSITIVE";
		break;
	case CKR_STATE_UNSAVEABLE:
		rc = "CKR_STATE_UNSAVEABLE";
		break;
	case CKR_CRYPTOKI_NOT_INITIALIZED:
		rc = "CKR_CRYPTOKI_NOT_INITIALIZED";
		break;
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		rc = "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		break;
	case CKR_MUTEX_BAD:
		rc = "CKR_MUTEX_BAD";
		break;
	case CKR_MUTEX_NOT_LOCKED:
		rc = "CKR_MUTEX_NOT_LOCKED";
		break;
	case CKR_NEW_PIN_MODE:
		rc = "CKR_NEW_PIN_MODE";
		break;
	case CKR_NEXT_OTP:
		rc = "CKR_NEXT_OTP";
		break;
	case CKR_FUNCTION_REJECTED:
		rc = "CKR_FUNCTION_REJECTED";
		break;
	case CKR_VENDOR_DEFINED:
		rc = "CKR_VENDOR_DEFINED";
		break;
	default:
		rc = "INVLAID RETURN CODE";
	}

	return rc;
}
