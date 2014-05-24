/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <stddef.h>
#include <pthread.h>
#include "p11.h"
#include "mutex.h"

CK_CREATEMUTEX createMutex;
CK_DESTROYMUTEX destroyMutex;
CK_LOCKMUTEX lockMutex;
CK_UNLOCKMUTEX unlockMutex;

CK_RV mutex_create(void **mutex)
{
	pthread_mutex_t *m = new pthread_mutex_t;
	if (m == NULL)
		return CKR_GENERAL_ERROR;
	pthread_mutex_init(m, NULL);
	*mutex = m;
	return CKR_OK;
}

CK_RV mutex_lock(void *p)
{
	if (pthread_mutex_lock((pthread_mutex_t *) p) == 0)
		return CKR_OK;
	else
		return CKR_GENERAL_ERROR;
}

CK_RV mutex_unlock(void *p)
{
	if (pthread_mutex_unlock((pthread_mutex_t *) p) == 0)
		return CKR_OK;
	else
		return CKR_GENERAL_ERROR;
}

CK_RV mutex_destroy(void *p)
{
	pthread_mutex_destroy((pthread_mutex_t *) p);
	delete (pthread_mutex_t*) p;
	return CKR_OK;
}
