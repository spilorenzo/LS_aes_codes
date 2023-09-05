//
//  AES_rp.h
//  AES_shuffling
//
//  Created by Lorenzo SPIGNOLI on 20/02/21.
//

#ifndef AES_rp_h
#define AES_rp_h

#include "AES.h"
#include "shares.h"

// define struct for the shares of the state:
// the shares of the state are represented by a vector of state where row represents a share of the state
typedef state state_shares[m+1];

void encoding_block(byte *input, state_shares input_s);
byte *decoding_block(state_shares output_s);

void encoding_key(byte *input, state_shares input_s);
byte *decoding_key(state_shares output_s);

void print_state_shares(state_shares mtx_state);

void key_expansion_shares(state_shares mtx_key);

void subbyte_shares(state_shares mtx_state);
void inv_subbyte_shares(state_shares mtx_state);

void shiftrows_shares(state_shares mtx_state);
void inv_shiftrows_shares(state_shares mtx_state);

void mixcolumns_shares(state_shares mtx_state);
void inv_mixcolumns_shares(state_shares mtx_state);

void addroundkey_shares(state_shares mtx_state, byte round);

void AES_encrypting_rp(state_shares mtx_state, state_shares mtx_key);
void AES_decrypting_rp(state_shares mtx_state, state_shares mtx_key);

#endif /* AES_rp_h */
