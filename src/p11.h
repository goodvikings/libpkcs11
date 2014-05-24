/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#ifndef P11_H
#define P11_H

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#define LIBVERSIONMAJOR	0
#define LIBVERSIONMINOR	1
#define LIBMANIDLEN 32
#define LIBLIBRARYDESCLEN 32
#define LIBMANID	"Ramo                            "
#define LIBLIBRARYDESC	"Ramo's PKCS11 Debugging Library "

#define PKCS11SLOTLISTENV "RAMOPKCS11SLOTFILE"
#define PKCS11LOGFILEENV "RAMOPKCS11LOGFILE"

#endif
