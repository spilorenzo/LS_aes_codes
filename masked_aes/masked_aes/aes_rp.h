//
//  aes_rp.h
//  masked_aes
//
//  Created by Lorenzo SPIGNOLI on 04/05/23.
//

#ifndef aes_rp_h
#define aes_rp_h

#include "aes.h"
#include "shares.h"


// define struct for the shares:
// the shares are represented by a vector of n+1 elements of type 'state', which xored will return a 'state'
typedef state masked_state[n+1];

void copy_maskedstate(masked_state inp, masked_state outp);

void refresh_maskedstate_rp(masked_state inp, masked_state outp);
void refresh_maskedstate_bbd(masked_state inp);

void encoding(state aes_state, masked_state aes_shares);
void decoding(masked_state aes_shares, state aes_state);

void key_expansion_masked(masked_state aes_key_shares);

void secmult_rp_masked(masked_state a_shares, masked_state b_shares, masked_state ab_shares);
void secmult_table_masked(masked_state a_shares, masked_state b_shares, masked_state ab_shares);
void square_masked(masked_state a_shares);

void secexp254_masked(masked_state a_shares);

void subbyte_masked(masked_state aes_state);
void inv_subbyte_masked(masked_state aes_state);

void shiftrows_masked(masked_state aes_state_shares);
void inv_shiftrows_masked(masked_state aes_state_shares);

void mixcolumns_masked(masked_state aes_state_shares);
void inv_mixcolumns_masked(masked_state aes_state_shares);

void addroundkey_masked(masked_state aes_state_shares, byte round);

void aes_encryption_masked(masked_state aes_state_shares, masked_state aes_key_shares);
void aes_decryption_masked(masked_state aes_state_shares, masked_state aes_key_shares);


#endif /* aes_rp_h */

