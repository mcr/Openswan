#ifndef __seam_gi_md5_c__
#define __seam_gi_md5_c__
#include "seam_secrets.h"
/*
 * these files are created by running a full pluto, and observing the
 * debug lines, and transforming them to C data files
 */

/*
 * conn alttunnel
 *     also=mytunnel
 *     ike=3des-md5;modp2048
 *     phase2alg=aes128-sha1;modp1536
 */

/* test case 3 - DH operation, SHA1 + AES */
u_int16_t     __tc71_oakleygroup  = OAKLEY_GROUP_MODP2048;
oakley_auth_t __tc71_auth         = AUTH_ALGORITHM_HMAC_MD5;
oakley_hash_t __tc71_hash         = OAKLEY_MD5;
enum phase1_role __tc71_init      = INITIATOR;

unsigned char __tc71_gi[] = {
0xbf, 0xda, 0xea, 0xa0,  0x86, 0x55, 0x9f, 0xdf,  0xbf, 0xbb, 0x5e, 0x42,  0xb9, 0xa6, 0x18, 0x18,
0xab, 0xca, 0x13, 0xb4,  0xcf, 0x6a, 0x92, 0x77,  0x44, 0x6c, 0x57, 0x46,  0x1c, 0x07, 0xa0, 0x86,
0x44, 0xe0, 0x9c, 0x5f,  0x98, 0x41, 0x7c, 0x4a,  0x3b, 0xab, 0x6c, 0x35,  0x56, 0x5a, 0x63, 0xcc,
0x0b, 0x2e, 0x40, 0x97,  0x16, 0x18, 0xbf, 0xc0,  0x83, 0x55, 0x57, 0xcc,  0x94, 0x04, 0xcd, 0x6b,
0xa2, 0xf2, 0xb9, 0xa6,  0x3b, 0x9b, 0x0d, 0xfd,  0x73, 0x7f, 0x91, 0x04,  0x06, 0x28, 0x86, 0xf9,
0xcb, 0x0b, 0x8a, 0x65,  0x14, 0xa0, 0xf5, 0xb2,  0xed, 0x6b, 0x23, 0x1f,  0x7d, 0xdf, 0x90, 0x28,
0xb8, 0x0f, 0x28, 0x95,  0xfb, 0x00, 0x22, 0xc9,  0xe3, 0x8f, 0xb9, 0xdf,  0xb8, 0x7c, 0x66, 0xbc,
0x75, 0x1b, 0xc8, 0x61,  0xba, 0xb5, 0x93, 0x17,  0xd6, 0xdf, 0x87, 0x26,  0xd3, 0x4d, 0x2d, 0x0a,
0xa4, 0x80, 0xe4, 0x51,  0xfd, 0x38, 0xfa, 0x42,  0xca, 0xb5, 0xf5, 0x2d,  0x90, 0x80, 0xbe, 0xa4,
0x9c, 0x08, 0x17, 0xb6,  0xab, 0xa9, 0x49, 0x4c,  0xf7, 0x45, 0x53, 0x50,  0xcb, 0x49, 0xf8, 0xb4,
0x44, 0x50, 0x86, 0x91,  0x37, 0xf7, 0x5c, 0xb0,  0x4a, 0xce, 0x96, 0x1f,  0xfc, 0x2a, 0xa5, 0x16,
0xe9, 0x45, 0xe4, 0xf2,  0xe5, 0xf0, 0xc9, 0x81,  0xc1, 0x66, 0x68, 0x55,  0xed, 0xc9, 0x3b, 0x62,
0x27, 0xa9, 0x34, 0x0e,  0x01, 0xa8, 0x54, 0x63,  0x7f, 0x99, 0x2f, 0xea,  0x6d, 0x3a, 0x21, 0x4c,
0x32, 0x72, 0xbf, 0xbb,  0x85, 0xdf, 0x2b, 0x8e,  0xcc, 0xa0, 0x40, 0x3e,  0x96, 0x16, 0xfa, 0x03,
0x96, 0x7f, 0xcd, 0xd7,  0xd0, 0x11, 0xd0, 0x17,  0x89, 0x96, 0xcd, 0x01,  0x25, 0xd3, 0x3d, 0xdd,
0xd2, 0x5e, 0x2c, 0xbd,  0x2e, 0x3a, 0xe4, 0x97,  0xb6, 0x33, 0xa3, 0x5c,  0x41, 0x01, 0xed, 0x8e,
};
unsigned int __tc71_gi_len = sizeof(__tc71_gi);

unsigned char __tc71_gr[] = {
0x25, 0x9a, 0x4e, 0x99,  0x8d, 0xac, 0xd9, 0x7b,  0x7d, 0xad, 0x9b, 0x2a,  0xbd, 0x38, 0x04, 0x00,
0xf7, 0x71, 0x32, 0x4c,  0xb0, 0x95, 0x5e, 0x5c,  0xc1, 0x0b, 0xe2, 0x92,  0x80, 0xc3, 0x9f, 0xb5,
0x30, 0x9b, 0xf3, 0x89,  0x51, 0x96, 0x5b, 0x75,  0xc6, 0x5b, 0x85, 0x1a,  0x8f, 0xf3, 0x2d, 0x6a,
0xb1, 0xb9, 0x66, 0xfe,  0xc5, 0x2e, 0xa9, 0xf4,  0x9e, 0xe2, 0x34, 0xc3,  0xd9, 0xdd, 0x47, 0x17,
0x18, 0x90, 0xfd, 0xce,  0x66, 0xbd, 0x6c, 0xe4,  0x43, 0x8a, 0x74, 0x49,  0x1c, 0x72, 0x97, 0x9f,
0xd7, 0x74, 0x86, 0xb1,  0x82, 0x7e, 0x9f, 0x17,  0x82, 0x5e, 0x06, 0xba,  0xd2, 0xfd, 0x71, 0x7e,
0x73, 0x10, 0x4b, 0x8b,  0x52, 0x14, 0x00, 0x26,  0x48, 0xd2, 0x59, 0x2e,  0x1c, 0x89, 0x3c, 0xbb,
0xe7, 0xe0, 0x12, 0x4a,  0xcb, 0x9b, 0xb4, 0x06,  0x45, 0xca, 0xdf, 0x18,  0xca, 0x11, 0xf3, 0x28,
0x68, 0x35, 0x09, 0x9f,  0x16, 0xe5, 0x14, 0x33,  0xff, 0xa8, 0x5c, 0x28,  0xab, 0x17, 0x4b, 0x29,
0x3b, 0x56, 0x32, 0xc7,  0x53, 0xad, 0x99, 0x61,  0x9c, 0x56, 0xf8, 0x50,  0x25, 0x21, 0x34, 0xab,
0x2d, 0xb8, 0xf0, 0xec,  0xf9, 0x23, 0xae, 0x8c,  0xb5, 0x24, 0x4d, 0xe0,  0xe6, 0x3e, 0x29, 0xd4,
0x2e, 0xda, 0xb1, 0x9c,  0x6c, 0x3b, 0x1f, 0x0b,  0xbf, 0xae, 0xbe, 0x6d,  0x0f, 0x58, 0xc3, 0x7a,
0x95, 0xbe, 0x9b, 0x9f,  0x8a, 0xe7, 0x07, 0x38,  0xa6, 0x54, 0xe9, 0x32,  0x80, 0x63, 0x8c, 0x60,
0xb3, 0xed, 0x8b, 0x59,  0x27, 0xd3, 0x03, 0x7d,  0x46, 0x04, 0x05, 0x4c,  0x6d, 0xd1, 0x26, 0x3c,
0x4e, 0x09, 0xea, 0x63,  0xe0, 0x7a, 0x6a, 0x7a,  0xa6, 0x3d, 0xed, 0xac,  0x39, 0x8c, 0xbf, 0x1f,
0xde, 0x9c, 0xd9, 0x09,  0xd2, 0xa1, 0x63, 0xe1,  0x28, 0x12, 0x5a, 0x18,  0x31, 0xfb, 0x82, 0xee,
};
unsigned int __tc71_gr_len = sizeof(__tc71_gr);

unsigned char __tc71_ni[] = {
0x3c, 0xd5, 0x15, 0x14,  0x50, 0xab, 0x73, 0x9a,  0xc8, 0xac, 0x54, 0x1c,  0x0d, 0xe6, 0xbc, 0x04,
};
unsigned int __tc71_ni_len = sizeof(__tc71_ni);

unsigned char __tc71_nr[] = {
0x00, 0x84, 0xb6, 0x7e,  0xd1, 0xb6, 0xd1, 0x52,  0x89, 0x0e, 0xd7, 0x1c,  0x74, 0xb9, 0x26, 0xe4,
};
unsigned int __tc71_nr_len = sizeof(__tc71_nr);

unsigned char __tc71_icookie[] = {
0x8a, 0x44, 0x87, 0x03,  0xba, 0x72, 0x90, 0x75,
};
unsigned int __tc71_icookie_len = sizeof(__tc71_icookie);

unsigned char __tc71_rcookie[] = {
0x55, 0x68, 0x7f, 0x55,  0x86, 0xc2, 0x97, 0x2a,
};
unsigned int __tc71_rcookie_len = sizeof(__tc71_rcookie);

unsigned char __tc71_secret[] = {
0xe7, 0xa6, 0x91, 0x6a,  0x99, 0xf7, 0x2a, 0x24,  0x24, 0xac, 0xba, 0xda,  0x5c, 0xcd, 0x57, 0x3e,
0xae, 0x01, 0xcd, 0x21,  0x49, 0x8d, 0x16, 0x24,  0xfb, 0xa7, 0x41, 0x72,  0xa0, 0x77, 0xbf, 0xa3,
};
unsigned int __tc71_secret_len = sizeof(__tc71_secret);

unsigned char __tc71_secretr[] = {
0xe7, 0xa6, 0x91, 0x6a,  0x99, 0xf7, 0x2a, 0x24,  0x24, 0xac, 0xba, 0xda,  0x5c, 0xcd, 0x57, 0x3e,
0xae, 0x01, 0xcd, 0x21,  0x49, 0x8d, 0x16, 0x24,  0xfb, 0xa7, 0x41, 0x72,  0xa0, 0x77, 0xbf, 0xa3,
};
unsigned int __tc71_secretr_len = sizeof(__tc71_secretr);

unsigned char __tc71_results_shared[]= {
0x1d, 0x64, 0xa9, 0xc9,  0x8b, 0x7f, 0x70, 0xf4,  0x0a, 0x9f, 0x8d, 0x2d,  0x2a, 0xa3, 0x6c, 0xf4,
0x58, 0xad, 0xcb, 0x71,  0x8a, 0x64, 0x41, 0x29,  0x92, 0x09, 0x7b, 0x56,  0xf6, 0x6a, 0x7b, 0xf1,
0x57, 0xc0, 0x45, 0x35,  0xa6, 0xd3, 0xda, 0x9b,  0x8e, 0xf1, 0x20, 0xad,  0x11, 0xca, 0x04, 0x3a,
0x56, 0xe2, 0xf0, 0x60,  0x75, 0x39, 0x16, 0xb4,  0x18, 0x36, 0xef, 0x58,  0xc2, 0x2f, 0x06, 0xc8,
0x4e, 0x18, 0x12, 0x3a,  0x15, 0x06, 0xe5, 0xf3,  0xe6, 0x32, 0x02, 0xf7,  0x8d, 0xd7, 0xf4, 0xee,
0x42, 0xc9, 0xaa, 0xd0,  0x34, 0x44, 0xb6, 0x9c,  0xf9, 0x8d, 0x7e, 0xf7,  0x91, 0x2b, 0xc3, 0xa7,
0xbd, 0x77, 0xe6, 0x1f,  0x56, 0xa8, 0x90, 0xfb,  0xbf, 0xff, 0x36, 0x86,  0xc4, 0xa1, 0xb3, 0x7d,
0xb9, 0xd6, 0x08, 0xdb,  0x02, 0xb0, 0xac, 0x5e,  0xed, 0xde, 0xb3, 0xb6,  0xd3, 0x17, 0x72, 0x81,
0x0d, 0xad, 0x8d, 0xc7,  0x81, 0x1d, 0xfa, 0x4c,  0xc9, 0x25, 0x9f, 0x5d,  0x1e, 0x09, 0x2d, 0x49,
0xd6, 0xfe, 0x9d, 0x87,  0xcd, 0xaf, 0x17, 0x4d,  0x44, 0x28, 0xcf, 0xa9,  0x53, 0xbe, 0xb7, 0x69,
0xb4, 0xa7, 0xed, 0xb1,  0xc7, 0x56, 0x48, 0xe4,  0xc5, 0x42, 0x64, 0x93,  0x54, 0xa7, 0x42, 0xd3,
0x59, 0x90, 0xa2, 0xc8,  0xb8, 0x76, 0x09, 0xed,  0xa8, 0xb2, 0x84, 0x62,  0xbf, 0x82, 0x9e, 0x27,
0x20, 0xbc, 0x09, 0x0f,  0x20, 0xfa, 0x3d, 0x37,  0x0b, 0xf8, 0x53, 0x17,  0xb9, 0xcb, 0x93, 0xae,
0x02, 0xdf, 0xe0, 0xe0,  0x94, 0x77, 0xa6, 0x85,  0xdb, 0x18, 0xac, 0xef,  0x82, 0x94, 0xc5, 0x3a,
0xf3, 0x29, 0xe9, 0x45,  0x01, 0xa6, 0x76, 0xf0,  0x75, 0x46, 0xf3, 0x69,  0x43, 0x75, 0x28, 0x9e,
0x2b, 0x5d, 0x58, 0x5a,  0xf0, 0x41, 0x1a, 0x08,  0xf2, 0x75, 0xad, 0xc5,  0x4b, 0x6c, 0x91, 0x0a,
};

/* NOTE: some calculations below are known to be wrong */
unsigned char __tc71_results_skeyseed[]= {
};

unsigned char __tc71_results_skey_d[]= {
0x48, 0x88, 0x03, 0x79,  0xb2, 0x23, 0xce, 0xab,  0x6f, 0xfc, 0x0e, 0xc6,  0xca, 0x8a, 0x49, 0x74,
};

unsigned char __tc71_results_skey_ai[]= {
0xf4, 0xc1, 0x01, 0xc7,  0x21, 0x18, 0xcf, 0x31,  0xd4, 0x68, 0x2f, 0x68,  0xb9, 0xa2, 0x9c, 0x07,
};

unsigned char __tc71_results_skey_ar[]= {
0xe7, 0x35, 0x43, 0x51,  0xe9, 0xa0, 0x81, 0xc3,  0x65, 0xb2, 0x76, 0x1a,  0xc5, 0xf8, 0x15, 0xea,
};

unsigned char __tc71_results_skey_ei[]= {
0x0d, 0x08, 0x5c, 0xb0,  0xdb, 0x3e, 0x85, 0x6c,  0x4d, 0x47, 0x45, 0xcc,  0x1f, 0xf5, 0xc9, 0x27,
0x4f, 0x58, 0x08, 0x27,  0xf0, 0x3c, 0x1a, 0xad,
};

unsigned char __tc71_results_skey_er[]= {
0x8f, 0x01, 0x46, 0x4a,  0x6b, 0x1a, 0x7a, 0xaf,  0x8b, 0x8a, 0x96, 0x9c,  0x88, 0xf3, 0xcc, 0x8e,
0xf8, 0x2a, 0x96, 0xcd,  0x72, 0x18, 0xfc, 0x11,
};

unsigned char __tc71_results_skey_pi[]= {
0xd8, 0x53, 0x01, 0xed,  0x30, 0x8e, 0x94, 0xde,  0x83, 0xd2, 0x32, 0x45,  0x9b, 0x66, 0x1c, 0x96,
};

unsigned char __tc71_results_skey_pr[]= {
0x96, 0x40, 0x1b, 0x7f,  0x2a, 0x94, 0x02, 0xfc,  0x64, 0xb0, 0xbe, 0xfc,  0xde, 0xd6, 0xd6, 0x8e,
};


SEAM_SECRETS_DECLARE_USING_PREFIX_ARRAYS(tc71_secrets,
					 OAKLEY_GROUP_MODP2048,
					 AUTH_ALGORITHM_HMAC_MD5,
					 OAKLEY_MD5,
					 INITIATOR,
					 __tc71);
#undef SECRETS
#define SECRETS (&tc71_secrets)

#endif
