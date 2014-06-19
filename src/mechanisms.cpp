/*
 * ------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <ramo@goodvikings.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return - Ramo
 * ------------------------------------------------------------------------------
 */

#include <map>
#include <string.h>
#include "mechanisms.h"
#include "p11.h"

#define RSAMAXKEYSIZE 8192
#define RSAMINKEYSIZE 512
#define RC4MAXKEYSIZE 2048
#define RC4MINKEYSIZE 40
#define DESMAXKEYSIZE 56
#define DESMINKEYSIZE DESMAXKEYSIZE
#define DES3MAXKEYSIZE 168
#define DES3MINKEYSIZE DESMAXKEYSIZE
#define AESMAXKEYSIZE 256
#define AESMINKEYSIZE 128

// <editor-fold defaultstate="collapsed" desc="mechanisms::~mechanisms()">

mechanisms::mechanisms()
{
	secKeyTypes = new CK_KEY_TYPE[4];
	secKeyTypes[0] = CKK_RC4;
	secKeyTypes[1] = CKK_DES;
	secKeyTypes[2] = CKK_DES3;
	secKeyTypes[3] = CKK_AES;
	secKeyTypeCount = 4;

	asymKeyTypes = new CK_KEY_TYPE[1];
	asymKeyTypes[0] = CKK_RSA;
	asymKeyTypeCount = 1;

	m = new std::map<CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR > ();

	//#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000
	(*m)[CKM_RSA_PKCS_KEY_PAIR_GEN] = new CK_MECHANISM_INFO;
	(*m)[CKM_RSA_PKCS_KEY_PAIR_GEN]->ulMaxKeySize = RSAMAXKEYSIZE;
	(*m)[CKM_RSA_PKCS_KEY_PAIR_GEN]->ulMinKeySize = RSAMINKEYSIZE;
	(*m)[CKM_RSA_PKCS_KEY_PAIR_GEN]->flags = CKF_GENERATE_KEY_PAIR;

	//#define CKM_RSA_PKCS                   0x00000001
	(*m)[CKM_RSA_PKCS] = new CK_MECHANISM_INFO;
	(*m)[CKM_RSA_PKCS]->ulMaxKeySize = RSAMAXKEYSIZE;
	(*m)[CKM_RSA_PKCS]->ulMinKeySize = RSAMINKEYSIZE;
	(*m)[CKM_RSA_PKCS]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_RSA_9796                   0x00000002

	//#define CKM_RSA_X_509                  0x00000003

	//#define CKM_MD2_RSA_PKCS               0x00000004

	//#define CKM_MD5_RSA_PKCS               0x00000005
	(*m)[CKM_MD5_RSA_PKCS] = new CK_MECHANISM_INFO;
	(*m)[CKM_MD5_RSA_PKCS]->ulMaxKeySize = RSAMAXKEYSIZE;
	(*m)[CKM_MD5_RSA_PKCS]->ulMinKeySize = RSAMINKEYSIZE;
	(*m)[CKM_MD5_RSA_PKCS]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_SHA1_RSA_PKCS              0x00000006
	(*m)[CKM_SHA1_RSA_PKCS] = new CK_MECHANISM_INFO;
	(*m)[CKM_SHA1_RSA_PKCS]->ulMaxKeySize = RSAMAXKEYSIZE;
	(*m)[CKM_SHA1_RSA_PKCS]->ulMinKeySize = RSAMINKEYSIZE;
	(*m)[CKM_SHA1_RSA_PKCS]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_RIPEMD128_RSA_PKCS         0x00000007

	//#define CKM_RIPEMD160_RSA_PKCS         0x00000008

	//#define CKM_RSA_PKCS_OAEP              0x00000009
	(*m)[CKM_RSA_PKCS_OAEP] = new CK_MECHANISM_INFO;
	(*m)[CKM_RSA_PKCS_OAEP]->ulMaxKeySize = RSAMAXKEYSIZE;
	(*m)[CKM_RSA_PKCS_OAEP]->ulMinKeySize = RSAMINKEYSIZE;
	(*m)[CKM_RSA_PKCS_OAEP]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;

	//#define CKM_RSA_X9_31_KEY_PAIR_GEN     0x0000000A

	//#define CKM_SHA1_RSA_X9_31             0x0000000C

	//#define CKM_RSA_PKCS_PSS               0x0000000D

	//#define CKM_SHA1_RSA_PKCS_PSS          0x0000000E

	//#define CKM_DSA_KEY_PAIR_GEN           0x00000010

	//#define CKM_DSA                        0x00000011

	//#define CKM_DSA_SHA1                   0x00000012

	//#define CKM_DH_PKCS_KEY_PAIR_GEN       0x00000020

	//#define CKM_DH_PKCS_DERIVE             0x00000021

	//#define CKM_X9_42_DH_KEY_PAIR_GEN      0x00000030

	//#define CKM_X9_42_DH_DERIVE            0x00000031

	//#define CKM_X9_42_DH_HYBRID_DERIVE     0x00000032

	//#define CKM_X9_42_MQV_DERIVE           0x00000033

	//#define CKM_SHA256_RSA_PKCS            0x00000040
	(*m)[CKM_SHA256_RSA_PKCS] = new CK_MECHANISM_INFO;
	(*m)[CKM_SHA256_RSA_PKCS]->ulMaxKeySize = RSAMAXKEYSIZE;
	(*m)[CKM_SHA256_RSA_PKCS]->ulMinKeySize = RSAMINKEYSIZE;
	(*m)[CKM_SHA256_RSA_PKCS]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_SHA384_RSA_PKCS            0x00000041
	(*m)[CKM_SHA384_RSA_PKCS] = new CK_MECHANISM_INFO;
	(*m)[CKM_SHA384_RSA_PKCS]->ulMaxKeySize = RSAMAXKEYSIZE;
	(*m)[CKM_SHA384_RSA_PKCS]->ulMinKeySize = RSAMINKEYSIZE;
	(*m)[CKM_SHA384_RSA_PKCS]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_SHA512_RSA_PKCS            0x00000042
	(*m)[CKM_SHA512_RSA_PKCS] = new CK_MECHANISM_INFO;
	(*m)[CKM_SHA512_RSA_PKCS]->ulMaxKeySize = RSAMAXKEYSIZE;
	(*m)[CKM_SHA512_RSA_PKCS]->ulMinKeySize = RSAMINKEYSIZE;
	(*m)[CKM_SHA512_RSA_PKCS]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_SHA256_RSA_PKCS_PSS        0x00000043

	//#define CKM_SHA384_RSA_PKCS_PSS        0x00000044

	//#define CKM_SHA512_RSA_PKCS_PSS        0x00000045

	//#define CKM_SHA224_RSA_PKCS            0x00000046

	//#define CKM_SHA224_RSA_PKCS_PSS        0x00000047

	//#define CKM_RC2_KEY_GEN                0x00000100

	//#define CKM_RC2_ECB                    0x00000101

	//#define CKM_RC2_CBC                    0x00000102

	//#define CKM_RC2_MAC                    0x00000103

	//#define CKM_RC2_MAC_GENERAL            0x00000104

	//#define CKM_RC2_CBC_PAD                0x00000105

	//#define CKM_RC4_KEY_GEN                0x00000110
	(*m)[CKM_RC4_KEY_GEN] = new CK_MECHANISM_INFO;
	(*m)[CKM_RC4_KEY_GEN]->ulMaxKeySize = RC4MAXKEYSIZE;
	(*m)[CKM_RC4_KEY_GEN]->ulMinKeySize = RC4MINKEYSIZE;
	(*m)[CKM_RC4_KEY_GEN]->flags = CKF_GENERATE;

	//#define CKM_RC4                        0x00000111
	(*m)[CKM_RC4] = new CK_MECHANISM_INFO;
	(*m)[CKM_RC4]->ulMaxKeySize = RC4MAXKEYSIZE;
	(*m)[CKM_RC4]->ulMinKeySize = RC4MINKEYSIZE;
	(*m)[CKM_RC4]->flags = CKF_ENCRYPT | CKF_DECRYPT;

	//#define CKM_DES_KEY_GEN                0x00000120
	(*m)[CKM_DES_KEY_GEN] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES_KEY_GEN]->ulMaxKeySize = DESMAXKEYSIZE;
	(*m)[CKM_DES_KEY_GEN]->ulMinKeySize = DESMINKEYSIZE;
	(*m)[CKM_DES_KEY_GEN]->flags = CKF_GENERATE;

	//#define CKM_DES_ECB                    0x00000121
	(*m)[CKM_DES_ECB] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES_ECB]->ulMaxKeySize = DESMAXKEYSIZE;
	(*m)[CKM_DES_ECB]->ulMinKeySize = DESMINKEYSIZE;
	(*m)[CKM_DES_ECB]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_DES_CBC                    0x00000122
	(*m)[CKM_DES_CBC] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES_CBC]->ulMaxKeySize = DESMAXKEYSIZE;
	(*m)[CKM_DES_CBC]->ulMinKeySize = DESMINKEYSIZE;
	(*m)[CKM_DES_CBC]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_DES_MAC                    0x00000123
	(*m)[CKM_DES_MAC] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES_MAC]->ulMaxKeySize = DESMAXKEYSIZE;
	(*m)[CKM_DES_MAC]->ulMinKeySize = DESMINKEYSIZE;
	(*m)[CKM_DES_MAC]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_DES_MAC_GENERAL            0x00000124
	(*m)[CKM_DES_MAC_GENERAL] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES_MAC_GENERAL]->ulMaxKeySize = DESMAXKEYSIZE;
	(*m)[CKM_DES_MAC_GENERAL]->ulMinKeySize = DESMINKEYSIZE;
	(*m)[CKM_DES_MAC_GENERAL]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_DES_CBC_PAD                0x00000125
	(*m)[CKM_DES_CBC_PAD] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES_CBC_PAD]->ulMaxKeySize = DESMAXKEYSIZE;
	(*m)[CKM_DES_CBC_PAD]->ulMinKeySize = DESMINKEYSIZE;
	(*m)[CKM_DES_CBC_PAD]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_DES2_KEY_GEN               0x00000130

	//#define CKM_DES3_KEY_GEN               0x00000131
	(*m)[CKM_DES3_KEY_GEN] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES3_KEY_GEN]->ulMaxKeySize = DES3MAXKEYSIZE;
	(*m)[CKM_DES3_KEY_GEN]->ulMinKeySize = DES3MINKEYSIZE;
	(*m)[CKM_DES3_KEY_GEN]->flags = CKF_GENERATE;

	//#define CKM_DES3_ECB                   0x00000132
	(*m)[CKM_DES3_ECB] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES3_ECB]->ulMaxKeySize = DES3MAXKEYSIZE;
	(*m)[CKM_DES3_ECB]->ulMinKeySize = DES3MINKEYSIZE;
	(*m)[CKM_DES3_ECB]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_DES3_CBC                   0x00000133
	(*m)[CKM_DES3_CBC] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES3_CBC]->ulMaxKeySize = DES3MAXKEYSIZE;
	(*m)[CKM_DES3_CBC]->ulMinKeySize = DES3MINKEYSIZE;
	(*m)[CKM_DES3_CBC]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_DES3_MAC                   0x00000134
	(*m)[CKM_DES3_MAC] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES3_MAC]->ulMaxKeySize = DES3MAXKEYSIZE;
	(*m)[CKM_DES3_MAC]->ulMinKeySize = DES3MAXKEYSIZE;
	(*m)[CKM_DES3_MAC]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_DES3_MAC_GENERAL           0x00000135
	(*m)[CKM_DES3_MAC_GENERAL] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES3_MAC_GENERAL]->ulMaxKeySize = DES3MAXKEYSIZE;
	(*m)[CKM_DES3_MAC_GENERAL]->ulMinKeySize = DES3MAXKEYSIZE;
	(*m)[CKM_DES3_MAC_GENERAL]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_DES3_CBC_PAD               0x00000136
	(*m)[CKM_DES3_CBC_PAD] = new CK_MECHANISM_INFO;
	(*m)[CKM_DES3_CBC_PAD]->ulMaxKeySize = DES3MAXKEYSIZE;
	(*m)[CKM_DES3_CBC_PAD]->ulMinKeySize = DES3MINKEYSIZE;
	(*m)[CKM_DES3_CBC_PAD]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_CDMF_KEY_GEN               0x00000140

	//#define CKM_CDMF_ECB                   0x00000141

	//#define CKM_CDMF_CBC                   0x00000142

	//#define CKM_CDMF_MAC                   0x00000143

	//#define CKM_CDMF_MAC_GENERAL           0x00000144

	//#define CKM_CDMF_CBC_PAD               0x00000145

	//#define CKM_DES_OFB64                  0x00000150

	//#define CKM_DES_OFB8                   0x00000151

	//#define CKM_DES_CFB64                  0x00000152

	//#define CKM_DES_CFB8                   0x00000153

	//#define CKM_MD2                        0x00000200

	//#define CKM_MD2_HMAC                   0x00000201

	//#define CKM_MD2_HMAC_GENERAL           0x00000202

	//#define CKM_MD5                        0x00000210
	(*m)[CKM_MD5] = new CK_MECHANISM_INFO;
	(*m)[CKM_MD5]->flags = CKF_DIGEST;

	//#define CKM_MD5_HMAC                   0x00000211

	//#define CKM_MD5_HMAC_GENERAL           0x00000212

	//#define CKM_SHA_1                      0x00000220
	(*m)[CKM_SHA_1] = new CK_MECHANISM_INFO;
	(*m)[CKM_SHA_1]->flags = CKF_DIGEST;

	//#define CKM_SHA_1_HMAC                 0x00000221

	//#define CKM_SHA_1_HMAC_GENERAL         0x00000222

	//#define CKM_RIPEMD128                  0x00000230

	//#define CKM_RIPEMD128_HMAC             0x00000231

	//#define CKM_RIPEMD128_HMAC_GENERAL     0x00000232

	//#define CKM_RIPEMD160                  0x00000240
	(*m)[CKM_RIPEMD160] = new CK_MECHANISM_INFO;
	(*m)[CKM_RIPEMD160]->flags = CKF_DIGEST;

	//#define CKM_RIPEMD160_HMAC             0x00000241

	//#define CKM_RIPEMD160_HMAC_GENERAL     0x00000242

	//#define CKM_SHA256                     0x00000250
	(*m)[CKM_SHA256] = new CK_MECHANISM_INFO;
	(*m)[CKM_SHA256]->flags = CKF_DIGEST;

	//#define CKM_SHA256_HMAC                0x00000251

	//#define CKM_SHA256_HMAC_GENERAL        0x00000252

	//#define CKM_SHA224                     0x00000255

	//#define CKM_SHA224_HMAC                0x00000256

	//#define CKM_SHA224_HMAC_GENERAL        0x00000257

	//#define CKM_SHA384                     0x00000260
	(*m)[CKM_SHA384] = new CK_MECHANISM_INFO;
	(*m)[CKM_SHA384]->flags = CKF_DIGEST;

	//#define CKM_SHA384_HMAC                0x00000261

	//#define CKM_SHA384_HMAC_GENERAL        0x00000262

	//#define CKM_SHA512                     0x00000270
	(*m)[CKM_SHA512] = new CK_MECHANISM_INFO;
	(*m)[CKM_SHA512]->flags = CKF_DIGEST;

	//#define CKM_SHA512_HMAC                0x00000271

	//#define CKM_SHA512_HMAC_GENERAL        0x00000272

	//#define CKM_SECURID_KEY_GEN            0x00000280

	//#define CKM_SECURID                    0x00000282

	//#define CKM_HOTP_KEY_GEN    0x00000290

	//#define CKM_HOTP            0x00000291

	//#define CKM_ACTI            0x000002A0

	//#define CKM_ACTI_KEY_GEN    0x000002A1

	//#define CKM_CAST_KEY_GEN               0x00000300

	//#define CKM_CAST_ECB                   0x00000301

	//#define CKM_CAST_CBC                   0x00000302

	//#define CKM_CAST_MAC                   0x00000303

	//#define CKM_CAST_MAC_GENERAL           0x00000304

	//#define CKM_CAST_CBC_PAD               0x00000305

	//#define CKM_CAST3_KEY_GEN              0x00000310

	//#define CKM_CAST3_ECB                  0x00000311

	//#define CKM_CAST3_CBC                  0x00000312

	//#define CKM_CAST3_MAC                  0x00000313

	//#define CKM_CAST3_MAC_GENERAL          0x00000314

	//#define CKM_CAST3_CBC_PAD              0x00000315

	//#define CKM_CAST5_KEY_GEN              0x00000320

	//#define CKM_CAST128_KEY_GEN            0x00000320

	//#define CKM_CAST5_ECB                  0x00000321

	//#define CKM_CAST128_ECB                0x00000321

	//#define CKM_CAST5_CBC                  0x00000322

	//#define CKM_CAST128_CBC                0x00000322

	//#define CKM_CAST5_MAC                  0x00000323

	//#define CKM_CAST128_MAC                0x00000323

	//#define CKM_CAST5_MAC_GENERAL          0x00000324

	//#define CKM_CAST128_MAC_GENERAL        0x00000324

	//#define CKM_CAST5_CBC_PAD              0x00000325

	//#define CKM_CAST128_CBC_PAD            0x00000325

	//#define CKM_RC5_KEY_GEN                0x00000330

	//#define CKM_RC5_ECB                    0x00000331

	//#define CKM_RC5_CBC                    0x00000332

	//#define CKM_RC5_MAC                    0x00000333

	//#define CKM_RC5_MAC_GENERAL            0x00000334

	//#define CKM_RC5_CBC_PAD                0x00000335

	//#define CKM_IDEA_KEY_GEN               0x00000340

	//#define CKM_IDEA_ECB                   0x00000341

	//#define CKM_IDEA_CBC                   0x00000342

	//#define CKM_IDEA_MAC                   0x00000343

	//#define CKM_IDEA_MAC_GENERAL           0x00000344

	//#define CKM_IDEA_CBC_PAD               0x00000345

	//#define CKM_GENERIC_SECRET_KEY_GEN     0x00000350

	//#define CKM_CONCATENATE_BASE_AND_KEY   0x00000360

	//#define CKM_CONCATENATE_BASE_AND_DATA  0x00000362

	//#define CKM_CONCATENATE_DATA_AND_BASE  0x00000363

	//#define CKM_XOR_BASE_AND_DATA          0x00000364

	//#define CKM_EXTRACT_KEY_FROM_KEY       0x00000365

	//#define CKM_SSL3_PRE_MASTER_KEY_GEN    0x00000370

	//#define CKM_SSL3_MASTER_KEY_DERIVE     0x00000371

	//#define CKM_SSL3_KEY_AND_MAC_DERIVE    0x00000372

	//#define CKM_SSL3_MASTER_KEY_DERIVE_DH  0x00000373

	//#define CKM_TLS_PRE_MASTER_KEY_GEN     0x00000374

	//#define CKM_TLS_MASTER_KEY_DERIVE      0x00000375

	//#define CKM_TLS_KEY_AND_MAC_DERIVE     0x00000376

	//#define CKM_TLS_MASTER_KEY_DERIVE_DH   0x00000377

	//#define CKM_TLS_PRF                    0x00000378

	//#define CKM_SSL3_MD5_MAC               0x00000380

	//#define CKM_SSL3_SHA1_MAC              0x00000381

	//#define CKM_MD5_KEY_DERIVATION         0x00000390

	//#define CKM_MD2_KEY_DERIVATION         0x00000391

	//#define CKM_SHA1_KEY_DERIVATION        0x00000392

	//#define CKM_SHA256_KEY_DERIVATION      0x00000393

	//#define CKM_SHA384_KEY_DERIVATION      0x00000394

	//#define CKM_SHA512_KEY_DERIVATION      0x00000395

	//#define CKM_SHA224_KEY_DERIVATION      0x00000396

	//#define CKM_PBE_MD2_DES_CBC            0x000003A0

	//#define CKM_PBE_MD5_DES_CBC            0x000003A1

	//#define CKM_PBE_MD5_CAST_CBC           0x000003A2

	//#define CKM_PBE_MD5_CAST3_CBC          0x000003A3

	//#define CKM_PBE_MD5_CAST5_CBC          0x000003A4

	//#define CKM_PBE_MD5_CAST128_CBC        0x000003A4

	//#define CKM_PBE_SHA1_CAST5_CBC         0x000003A5

	//#define CKM_PBE_SHA1_CAST128_CBC       0x000003A5

	//#define CKM_PBE_SHA1_RC4_128           0x000003A6

	//#define CKM_PBE_SHA1_RC4_40            0x000003A7

	//#define CKM_PBE_SHA1_DES3_EDE_CBC      0x000003A8

	//#define CKM_PBE_SHA1_DES2_EDE_CBC      0x000003A9

	//#define CKM_PBE_SHA1_RC2_128_CBC       0x000003AA

	//#define CKM_PBE_SHA1_RC2_40_CBC        0x000003AB

	//#define CKM_PKCS5_PBKD2                0x000003B0

	//#define CKM_PBA_SHA1_WITH_SHA1_HMAC    0x000003C0

	//#define CKM_WTLS_PRE_MASTER_KEY_GEN         0x000003D0

	//#define CKM_WTLS_MASTER_KEY_DERIVE          0x000003D1

	//#define CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   0x000003D2

	//#define CKM_WTLS_PRF                        0x000003D3

	//#define CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  0x000003D4

	//#define CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  0x000003D5

	//#define CKM_KEY_WRAP_LYNKS             0x00000400

	//#define CKM_KEY_WRAP_SET_OAEP          0x00000401

	//#define CKM_CMS_SIG                    0x00000500

	//#define CKM_KIP_DERIVE	               0x00000510

	//#define CKM_KIP_WRAP	               0x00000511

	//#define CKM_KIP_MAC	               0x00000512

	//#define CKM_CAMELLIA_KEY_GEN           0x00000550

	//#define CKM_CAMELLIA_ECB               0x00000551

	//#define CKM_CAMELLIA_CBC               0x00000552

	//#define CKM_CAMELLIA_MAC               0x00000553

	//#define CKM_CAMELLIA_MAC_GENERAL       0x00000554

	//#define CKM_CAMELLIA_CBC_PAD           0x00000555

	//#define CKM_CAMELLIA_ECB_ENCRYPT_DATA  0x00000556

	//#define CKM_CAMELLIA_CBC_ENCRYPT_DATA  0x00000557

	//#define CKM_CAMELLIA_CTR               0x00000558

	//#define CKM_ARIA_KEY_GEN               0x00000560

	//#define CKM_ARIA_ECB                   0x00000561

	//#define CKM_ARIA_CBC                   0x00000562

	//#define CKM_ARIA_MAC                   0x00000563

	//#define CKM_ARIA_MAC_GENERAL           0x00000564

	//#define CKM_ARIA_CBC_PAD               0x00000565

	//#define CKM_ARIA_ECB_ENCRYPT_DATA      0x00000566

	//#define CKM_ARIA_CBC_ENCRYPT_DATA      0x00000567

	//#define CKM_SKIPJACK_KEY_GEN           0x00001000

	//#define CKM_SKIPJACK_ECB64             0x00001001

	//#define CKM_SKIPJACK_CBC64             0x00001002

	//#define CKM_SKIPJACK_OFB64             0x00001003

	//#define CKM_SKIPJACK_CFB64             0x00001004

	//#define CKM_SKIPJACK_CFB32             0x00001005

	//#define CKM_SKIPJACK_CFB16             0x00001006

	//#define CKM_SKIPJACK_CFB8              0x00001007

	//#define CKM_SKIPJACK_WRAP              0x00001008

	//#define CKM_SKIPJACK_PRIVATE_WRAP      0x00001009

	//#define CKM_SKIPJACK_RELAYX            0x0000100a

	//#define CKM_KEA_KEY_PAIR_GEN           0x00001010

	//#define CKM_KEA_KEY_DERIVE             0x00001011

	//#define CKM_FORTEZZA_TIMESTAMP         0x00001020

	//#define CKM_BATON_KEY_GEN              0x00001030

	//#define CKM_BATON_ECB128               0x00001031

	//#define CKM_BATON_ECB96                0x00001032

	//#define CKM_BATON_CBC128               0x00001033

	//#define CKM_BATON_COUNTER              0x00001034

	//#define CKM_BATON_SHUFFLE              0x00001035

	//#define CKM_BATON_WRAP                 0x00001036

	//#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040

	//#define CKM_EC_KEY_PAIR_GEN            0x00001040

	//#define CKM_ECDSA                      0x00001041

	//#define CKM_ECDSA_SHA1                 0x00001042

	//#define CKM_ECDH1_DERIVE               0x00001050

	//#define CKM_ECDH1_COFACTOR_DERIVE      0x00001051

	//#define CKM_ECMQV_DERIVE               0x00001052

	//#define CKM_JUNIPER_KEY_GEN            0x00001060

	//#define CKM_JUNIPER_ECB128             0x00001061

	//#define CKM_JUNIPER_CBC128             0x00001062

	//#define CKM_JUNIPER_COUNTER            0x00001063

	//#define CKM_JUNIPER_SHUFFLE            0x00001064

	//#define CKM_JUNIPER_WRAP               0x00001065

	//#define CKM_FASTHASH                   0x00001070

	//#define CKM_AES_KEY_GEN                0x00001080
	(*m)[CKM_AES_KEY_GEN] = new CK_MECHANISM_INFO;
	(*m)[CKM_AES_KEY_GEN]->ulMaxKeySize = AESMAXKEYSIZE;
	(*m)[CKM_AES_KEY_GEN]->ulMinKeySize = AESMINKEYSIZE;
	(*m)[CKM_AES_KEY_GEN]->flags = CKF_GENERATE;

	//#define CKM_AES_ECB                    0x00001081
	(*m)[CKM_AES_ECB] = new CK_MECHANISM_INFO;
	(*m)[CKM_AES_ECB]->ulMaxKeySize = AESMAXKEYSIZE;
	(*m)[CKM_AES_ECB]->ulMinKeySize = AESMINKEYSIZE;
	(*m)[CKM_AES_ECB]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_AES_CBC                    0x00001082
	(*m)[CKM_AES_CBC] = new CK_MECHANISM_INFO;
	(*m)[CKM_AES_CBC]->ulMaxKeySize = AESMAXKEYSIZE;
	(*m)[CKM_AES_CBC]->ulMinKeySize = AESMINKEYSIZE;
	(*m)[CKM_AES_CBC]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_AES_MAC                    0x00001083
	(*m)[CKM_AES_MAC] = new CK_MECHANISM_INFO;
	(*m)[CKM_AES_MAC]->ulMaxKeySize = AESMAXKEYSIZE;
	(*m)[CKM_AES_MAC]->ulMinKeySize = AESMINKEYSIZE;
	(*m)[CKM_AES_MAC]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_AES_MAC_GENERAL            0x00001084
	(*m)[CKM_AES_MAC_GENERAL] = new CK_MECHANISM_INFO;
	(*m)[CKM_AES_MAC_GENERAL]->ulMaxKeySize = AESMAXKEYSIZE;
	(*m)[CKM_AES_MAC_GENERAL]->ulMinKeySize = AESMINKEYSIZE;
	(*m)[CKM_AES_MAC_GENERAL]->flags = CKF_SIGN | CKF_VERIFY;

	//#define CKM_AES_CBC_PAD                0x00001085
	(*m)[CKM_AES_CBC_PAD] = new CK_MECHANISM_INFO;
	(*m)[CKM_AES_CBC_PAD]->ulMaxKeySize = AESMAXKEYSIZE;
	(*m)[CKM_AES_CBC_PAD]->ulMinKeySize = AESMINKEYSIZE;
	(*m)[CKM_AES_CBC_PAD]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_AES_CTR                    0x00001086
	(*m)[CKM_AES_CTR] = new CK_MECHANISM_INFO;
	(*m)[CKM_AES_CTR]->ulMaxKeySize = AESMAXKEYSIZE;
	(*m)[CKM_AES_CTR]->ulMinKeySize = AESMINKEYSIZE;
	(*m)[CKM_AES_CTR]->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;

	//#define CKM_BLOWFISH_KEY_GEN           0x00001090

	//#define CKM_BLOWFISH_CBC               0x00001091

	//#define CKM_TWOFISH_KEY_GEN            0x00001092

	//#define CKM_TWOFISH_CBC                0x00001093

	//#define CKM_DES_ECB_ENCRYPT_DATA       0x00001100

	//#define CKM_DES_CBC_ENCRYPT_DATA       0x00001101

	//#define CKM_DES3_ECB_ENCRYPT_DATA      0x00001102

	//#define CKM_DES3_CBC_ENCRYPT_DATA      0x00001103

	//#define CKM_AES_ECB_ENCRYPT_DATA       0x00001104

	//#define CKM_AES_CBC_ENCRYPT_DATA       0x00001105

	//#define CKM_DSA_PARAMETER_GEN          0x00002000

	//#define CKM_DH_PKCS_PARAMETER_GEN      0x00002001

	//#define CKM_X9_42_DH_PARAMETER_GEN     0x00002002

	//#define CKM_VENDOR_DEFINED             0x80000000
}
// </editor-fold>

mechanisms::~mechanisms()
{
	for (std::map<CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR>::iterator i = m->begin(); i != m->end(); i++)
	{
		delete i->second;
	}

	delete m;
	delete [] secKeyTypes;
	delete [] asymKeyTypes;
}

CK_ULONG mechanisms::getSize()
{
	return m->size();
}

CK_RV mechanisms::getMachanismList(CK_MECHANISM_TYPE_PTR pType, CK_ULONG_PTR pCount)
{
	if (m->size() > *pCount)
		return CKR_BUFFER_TOO_SMALL;

	int j = 0;
	for (std::map<CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR>::iterator i = m->begin(); i != m->end(); i++, j++)
	{
		pType[j] = i->first;
	}

	return CKR_OK;
}

CK_RV mechanisms::getMechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	if (!m->count(type))
		rv = CKR_MECHANISM_INVALID;

	if (!rv)
		memcpy(pInfo, (*m)[type], sizeof (CK_MECHANISM_INFO));

	return rv;
}

bool mechanisms::isSupportedSecretKeyType(CK_KEY_TYPE keyType)
{
	for (int i = 0; i < secKeyTypeCount; i++)
		if (keyType == secKeyTypes[i])
			return true;

	return false;
}

bool mechanisms::isSupportedAsymKeyType(CK_KEY_TYPE keyType)
{
	for (int i = 0; i < asymKeyTypeCount; i++)
		if (keyType == asymKeyTypes[i])
			return true;

	return false;
}

bool mechanisms::getMechanismsByKeyType(CK_KEY_TYPE keyType, CK_MECHANISM_TYPE_PTR* mechs, int* len)
{
	switch (keyType) {
	case CKK_DES:
		*len = 5;
		*mechs = new CK_MECHANISM_TYPE[*len];
		(*mechs)[0] = CKM_DES_ECB;
		(*mechs)[1] = CKM_DES_CBC;
		(*mechs)[2] = CKM_DES_MAC;
		(*mechs)[3] = CKM_DES_MAC_GENERAL;
		(*mechs)[4] = CKM_DES_CBC_PAD;
		break;
	case CKK_RC4:
		*len = 1;
		*mechs = new CK_MECHANISM_TYPE[*len];
		(*mechs)[0] = CKM_RC4;
		break;
	case CKK_DES3:
		*len = 5;
		*mechs = new CK_MECHANISM_TYPE[*len];
		(*mechs)[0] = CKM_DES3_ECB;
		(*mechs)[1] = CKM_DES3_CBC;
		(*mechs)[2] = CKM_DES3_MAC;
		(*mechs)[3] = CKM_DES3_MAC_GENERAL;
		(*mechs)[4] = CKM_DES3_CBC_PAD;
		break;
	case CKK_AES:
		*len = 7;
		*mechs = new CK_MECHANISM_TYPE[*len];
		(*mechs)[0] = CKM_AES_KEY_GEN;
		(*mechs)[1] = CKM_AES_ECB;
		(*mechs)[2] = CKM_AES_CBC;
		(*mechs)[3] = CKM_AES_MAC;
		(*mechs)[4] = CKM_AES_MAC_GENERAL;
		(*mechs)[5] = CKM_AES_CBC_PAD;
		(*mechs)[6] = CKM_AES_CTR;
		break;
	case CKK_RSA:
		*len = 8;
		*mechs = new CK_MECHANISM_TYPE[*len];
		(*mechs)[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
		(*mechs)[1] = CKM_RSA_PKCS;
		(*mechs)[2] = CKM_MD5_RSA_PKCS;
		(*mechs)[3] = CKM_SHA1_RSA_PKCS;
		(*mechs)[4] = CKM_RSA_PKCS_OAEP;
		(*mechs)[5] = CKM_SHA256_RSA_PKCS;
		(*mechs)[6] = CKM_SHA384_RSA_PKCS;
		(*mechs)[7] = CKM_SHA512_RSA_PKCS;
		break;
	default:
		return false;
	}
	return true;
}
