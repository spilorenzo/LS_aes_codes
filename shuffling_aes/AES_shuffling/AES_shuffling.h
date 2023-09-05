//
//  AES_shuffling.h
//  AES_shuffling
//
//  Created by Lorenzo SPIGNOLI on 20/02/21.
//

#ifndef AES_shuffling_h
#define AES_shuffling_h

#include "AES_rp.h"
#include "sparse.h"

typedef sparse_shares state_ss[BLOCKLEN];

void encoding_block_stsec(byte *plaintext, state_ss input_s);
byte *decoding_block_stsec(state_ss output_s);

void print_state_stsec(state_ss input_s);
void print_expandedkey_stsec();

void key_expansion_stsec(state_ss mtx_key);

void subbyte_stsec(state_ss mtx_state);
void inv_subbyte_stsec(state_ss mtx_state);

void shiftrows_stsec(state_ss mtx_state);
void inv_shiftrows_stsec(state_ss mtx_state);

void mixcolumns_stsec(state_ss mtx_state);
void preprocessing_step_stsec(state_ss mtx_state);
void inv_mixcolumns_stsec(state_ss mtx_state);

void addroundkey_stsec(state_ss mtx_state, state_ss mtx_key);

void AES_encrypting_cs(state_ss mtx_state, state_ss mtx_key);
void AES_decrypting_cs(state_ss mtx_state, state_ss mtx_key);

#endif /* AES_shuffling_h */
