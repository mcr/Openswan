#ifndef __seam_gi_sha256_group14_c__
#define __seam_gi_sha256_group14_c__
#include "seam_secrets.h"
#include "seam_gi_sha1.c"
/*
 * these files are created by running a full pluto, and observing the
 * debug lines, and transforming them to C data files
 */

/* test case 4 - DH operation, SHA256 + AES */
u_int16_t     __tc14B_oakleygroup  = OAKLEY_GROUP_MODP2048;
oakley_auth_t __tc14B_auth         = AUTH_ALGORITHM_HMAC_SHA2_256;
enum oakley_hash_t __tc14B_hash         = OAKLEY_SHA2_256;
enum phase1_role __tc14B_init      = INITIATOR;

/* secret value */
unsigned char __tc14B_secret[] = {
  0x87, 0x5a, 0x1b, 0x5e, 0xb4, 0x7f, 0x40, 0xbd,
  0x2b, 0x4d, 0x38, 0x79, 0x06, 0x71, 0x25, 0xca,
  0xab, 0x3e, 0x8d, 0x19, 0x19, 0xd1, 0x8f, 0xd0,
  0x53, 0x78, 0x09, 0xd9, 0x4e, 0x8f, 0xd4, 0xb2
};

unsigned int __tc14B_secret_len = sizeof(__tc14B_secret);

/* secret value */
unsigned char __tc14B_secretr[] = {
  0x36, 0x19, 0x54, 0xfb,  0x99, 0x37, 0x8b, 0x75,
  0x10, 0xb8, 0x30, 0x3b,  0xde, 0x69, 0xa6, 0x08,
  0x86, 0xc0, 0xfa, 0x0f,  0x42, 0x5f, 0x00, 0x04,
  0xf8, 0x77, 0x28, 0x76,  0x52, 0x91, 0xb9, 0x47
};
unsigned int __tc14B_secretr_len = sizeof(__tc14B_secretr);


unsigned char __tc14B_gi[] = {
  0x3d, 0xa6, 0x6a, 0x81, 0xe2, 0x92, 0x09, 0xbe,
  0x18, 0x4f, 0xa0, 0x1e, 0x5c, 0xed, 0xea, 0x7c,
  0x7d, 0x7b, 0x3a, 0x21, 0x3e, 0x15, 0x0d, 0x53,
  0x5d, 0x17, 0x6a, 0xbe, 0x1b, 0xc5, 0x70, 0xab,
  0x34, 0x47, 0xbc, 0x09, 0x14, 0x7c, 0xaa, 0x91,
  0x9c, 0x8f, 0x81, 0xdc, 0x1e, 0xf9, 0x87, 0xcd,
  0x6a, 0xec, 0xfa, 0xf3, 0xa5, 0x9e, 0x37, 0xbc,
  0xac, 0x3d, 0xfd, 0xe1, 0x32, 0x8e, 0xe8, 0xb3,
  0xfe, 0xd3, 0x8b, 0xf4, 0x7b, 0x50, 0x34, 0x13,
  0x33, 0x7a, 0x93, 0xea, 0xe9, 0x3c, 0x0e, 0x8b,
  0xbd, 0x48, 0x18, 0x9c, 0x9e, 0x03, 0x70, 0xf2, 0x55, 0xce, 0x45, 0x22, 0x9f, 0xc7, 0xc9, 0x48,
  0x43, 0xa3, 0xe2, 0x64, 0xb5, 0x5d, 0x43, 0x38, 0xc8, 0xfe, 0xf1, 0xd3, 0x06, 0x43, 0xf0, 0x0a,
  0xe8, 0x6d, 0x61, 0x8c, 0x60, 0x78, 0xd9, 0x98, 0xd3, 0x1b, 0x3b, 0x5e, 0xf5, 0xa6, 0xe8, 0x2f,
  0xef, 0x56, 0xac, 0xb4, 0x33, 0xbd, 0x1e, 0x62, 0xb2, 0x3e, 0x0b, 0x17, 0xaf, 0x6c, 0xb8, 0x31,
  0x08, 0xd7, 0x19, 0x5a, 0x7b, 0xc4, 0x54, 0xc2, 0x13, 0x47, 0x98, 0xc2, 0xcc, 0xd2, 0x16, 0x29,
  0x75, 0x6c, 0x03, 0xfb, 0x1e, 0x9c, 0x9d, 0x21, 0x0c, 0xa1, 0xe6, 0xc2, 0xf3, 0xf2, 0x49, 0x2c,
  0xf6, 0x06, 0x73, 0xc1, 0x96, 0x1e, 0xce, 0x58, 0x81, 0x01, 0x1c, 0xcb, 0x16, 0xdc, 0xf9, 0xfc,
  0xc7, 0x93, 0x08, 0x75, 0x58, 0x16, 0x57, 0x71, 0x69, 0x96, 0x66, 0xb7, 0xa9, 0x81, 0x7f, 0xf7,
  0x37, 0x4d, 0x7c, 0x41, 0x38, 0x62, 0xa6, 0x39, 0x00, 0x81, 0xca, 0x3d, 0x1d, 0xfc, 0xf7, 0xb5,
  0x08, 0x38, 0xd4, 0x34, 0x70, 0x22, 0x6c, 0x21, 0xd2, 0x5b, 0x20, 0xa1, 0xd2, 0xba, 0x2a, 0xd1,
  0x89, 0xf3, 0x20, 0x79, 0xce, 0xac, 0x1e, 0xc2, 0xec, 0x7d, 0xae, 0x76, 0x94, 0x40, 0x39, 0xa0
};
unsigned int __tc14B_gi_len = sizeof(__tc14B_gi);

unsigned char __tc14B_ni[] = {
  0x20, 0x98, 0x9d, 0x37,  0xa8, 0x14, 0xa6, 0x4d,
  0x8f, 0xf0, 0x7c, 0x08,  0xd3, 0x20, 0xe9, 0xe3
};
unsigned int __tc14B_ni_len = sizeof(__tc14B_ni);

unsigned char __tc14B_gr[] = {
  0xbd, 0x48, 0x18, 0x9c, 0x9e, 0x03, 0x70, 0xf2,
  0x55, 0xce, 0x45, 0x22, 0x9f, 0xc7, 0xc9, 0x48,
  0x43, 0xa3, 0xe2, 0x64, 0xb5, 0x5d, 0x43, 0x38,
  0xc8, 0xfe, 0xf1, 0xd3, 0x06, 0x43, 0xf0, 0x0a,
  0xe8, 0x6d, 0x61, 0x8c, 0x60, 0x78, 0xd9, 0x98,
  0xd3, 0x1b, 0x3b, 0x5e, 0xf5, 0xa6, 0xe8, 0x2f,
  0xef, 0x56, 0xac, 0xb4, 0x33, 0xbd, 0x1e, 0x62,
  0xb2, 0x3e, 0x0b, 0x17, 0xaf, 0x6c, 0xb8, 0x31,
  0x08, 0xd7, 0x19, 0x5a, 0x7b, 0xc4, 0x54, 0xc2,
  0x13, 0x47, 0x98, 0xc2, 0xcc, 0xd2, 0x16, 0x29,
  0x75, 0x6c, 0x03, 0xfb, 0x1e, 0x9c, 0x9d, 0x21,
  0x0c, 0xa1, 0xe6, 0xc2, 0xf3, 0xf2, 0x49, 0x2c,
  0xf6, 0x06, 0x73, 0xc1, 0x96, 0x1e, 0xce, 0x58,
  0x81, 0x01, 0x1c, 0xcb, 0x16, 0xdc, 0xf9, 0xfc,
  0xc7, 0x93, 0x08, 0x75, 0x58, 0x16, 0x57, 0x71,
  0x69, 0x96, 0x66, 0xb7, 0xa9, 0x81, 0x7f, 0xf7,
  0x37, 0x4d, 0x7c, 0x41, 0x38, 0x62, 0xa6, 0x39,
  0x00, 0x81, 0xca, 0x3d, 0x1d, 0xfc, 0xf7, 0xb5,
  0x08, 0x38, 0xd4, 0x34, 0x70, 0x22, 0x6c, 0x21,
  0xd2, 0x5b, 0x20, 0xa1, 0xd2, 0xba, 0x2a, 0xd1,
  0x89, 0xf3, 0x20, 0x79, 0xce, 0xac, 0x1e, 0xc2,
  0xec, 0x7d, 0xae, 0x76, 0x94, 0x40, 0x39, 0xa0,
  0x3d, 0xa6, 0x6a, 0x81, 0xe2, 0x92, 0x09, 0xbe,
  0x18, 0x4f, 0xa0, 0x1e, 0x5c, 0xed, 0xea, 0x7c,
  0x7d, 0x7b, 0x3a, 0x21, 0x3e, 0x15, 0x0d, 0x53,
  0x5d, 0x17, 0x6a, 0xbe, 0x1b, 0xc5, 0x70, 0xab,
  0x34, 0x47, 0xbc, 0x09, 0x14, 0x7c, 0xaa, 0x91,
  0x9c, 0x8f, 0x81, 0xdc, 0x1e, 0xf9, 0x87, 0xcd,
  0x6a, 0xec, 0xfa, 0xf3, 0xa5, 0x9e, 0x37, 0xbc,
  0xac, 0x3d, 0xfd, 0xe1, 0x32, 0x8e, 0xe8, 0xb3,
  0xfe, 0xd3, 0x8b, 0xf4, 0x7b, 0x50, 0x34, 0x13,
  0x33, 0x7a, 0x93, 0xea, 0xe9, 0x3c, 0x0e, 0x8b,
};
unsigned int __tc14B_gr_len = sizeof(__tc14B_gr);

unsigned char __tc14B_nr[] = {
  0x20, 0x98, 0x9d, 0x37,  0xa8, 0x14, 0xa6, 0x4d,
  0x8f, 0xf0, 0x7c, 0x08,  0xd3, 0x20, 0xe9, 0xe3
};
unsigned int __tc14B_nr_len = sizeof(__tc14B_nr);


/* some of this one comes from tc3_ for now */
#define  __tc14B_icookie           __tc3_icookie
#define  __tc14B_rcookie           __tc3_rcookie
#define  __tc14B_results_shared    __tc3_results_shared
#define  __tc14B_results_skeyseed  __tc3_results_skeyseed

unsigned char __tc14B_results_skey_d[]= {
	0xac, 0x97, 0xeb, 0x39,  0x07, 0x53, 0xa4, 0x5d,
	0x61, 0xc1, 0x64, 0xff,  0xca, 0x25, 0x99, 0xb0,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
};

unsigned char __tc14B_results_skey_ai[]= {
	0x4e, 0xa8, 0xe6, 0x62,  0xb0, 0x7c, 0xdd, 0x43,
	0x0f, 0x69, 0x44, 0xc6,  0x72, 0x3e, 0x4b, 0x82,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
};

unsigned char __tc14B_results_skey_ar[]= {
	0x51, 0x5b, 0x0b, 0xd2,  0x2e, 0x6d, 0x76, 0xb3,
	0x4f, 0xdb, 0x76, 0x0a,  0xa7, 0xbf, 0xad, 0x80,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
};

unsigned char __tc14B_results_skey_ei[]= {
	0x3f, 0x44, 0xbf, 0x47,  0xca, 0xfd, 0x81, 0x50,
	0x59, 0x1d, 0xeb, 0x08,  0x81, 0x99, 0xfc, 0xbf,
};

unsigned char __tc14B_results_skey_er[]= {
	0xbe, 0xdb, 0x67, 0xec,  0x7d, 0xc3, 0xd0, 0x0c,
	0xcc, 0xac, 0x42, 0xe7,  0x0c, 0xd6, 0x3b, 0xde,
};

unsigned char __tc14B_results_skey_pi[]= {
	0xcc, 0x07, 0x97, 0x44,  0xb4, 0xa3, 0x4e, 0x8a,
	0x0d, 0x2f, 0x27, 0x8b,  0xee, 0x06, 0x6d, 0x07,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
};

unsigned char __tc14B_results_skey_pr[]= {
	0xe9, 0x00, 0x11, 0x7e,  0x41, 0xd4, 0x31, 0x62,
	0x40, 0xb8, 0x63, 0x22,  0xbf, 0x06, 0x9f, 0xbc,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
	0x2e, 0x05, 0x3c, 0x7e,  0x12, 0x87, 0x12, 0x99,
};

unsigned char __tc14B_results_new_iv[] = {
  0xbc, 0xd5, 0x89, 0x68, 0x0c, 0x42, 0x2e, 0xcd,
  0x14, 0x72, 0xae, 0xa3, 0x97, 0x42, 0x67, 0x41
};

unsigned char __tc14B_results_enc_key[] = {
  0x56, 0x4c, 0x62, 0xb3, 0x52, 0xd9, 0x33, 0x45,
  0x0a, 0xd1, 0xdf, 0x32, 0x4e, 0xa5, 0x7d, 0x69
};



SEAM_SECRETS_DECLARE_USING_PREFIX_ARRAYS(tc14B_secrets,
					 OAKLEY_GROUP_MODP2048,
					 AUTH_ALGORITHM_HMAC_SHA2_256,
					 OAKLEY_SHA2_256,
					 INITIATOR,
					 __tc14B);
#undef SECRETS
#define SECRETS (&tc14B_secrets)

#endif
