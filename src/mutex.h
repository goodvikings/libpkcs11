/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#ifndef MUTEX_H
#define MUTEX_H

#include "p11.h"

/*
 * These get assigned as function pointers to the CK_XXMUTEX functions, call
 * those as such:
 *	pthread_mutex_t** mutex = new pthread_mutex_t*;
 *	createMutex((void**)mutex);
 *	lockMutex(*mutex);
 *	unlockMutex(*mutex);
 *	destroyMutex(*mutex);
 */

CK_RV mutex_create(void **mutex);
CK_RV mutex_lock(void *p);
CK_RV mutex_unlock(void *p);
CK_RV mutex_destroy(void *p);

extern CK_CREATEMUTEX createMutex;
extern CK_DESTROYMUTEX destroyMutex;
extern CK_LOCKMUTEX lockMutex;
extern CK_UNLOCKMUTEX unlockMutex;

#endif
