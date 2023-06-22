//
//  lookuptable_sbox.h
//  masked+prg_aes
//
//  Created by Lorenzo SPIGNOLI on 25/05/2023.
//

#ifndef lookuptable_sbox_h
#define lookuptable_sbox_h

#include "aes_rp.h"

void refresh_locality_table(shares Tinp, shares Tout);

void masked_sbox_table(masked_state input);
void masked_rsbox_table(masked_state input);

void subbyte_masked_table(masked_state aes_state_shares);
void inv_subbyte_masked_table(masked_state aes_state);

void aes_encryption_masked_table(masked_state aes_state_shares, masked_state aes_key_shares);
void aes_decryption_masked_table(masked_state aes_state_shares, masked_state aes_key_shares);

#endif /* lookuptable_sbox_h */
