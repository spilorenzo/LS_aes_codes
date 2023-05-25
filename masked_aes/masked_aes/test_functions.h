//
//  test_functions.h
//  masked_aes
//
//  Created by Lorenzo SPIGNOLI on 25/05/2023.
//

#ifndef test_functions_h
#define test_functions_h

#include "lookuptable_sbox.h"

void printstate(state aes_state);
void printstate_matrix(state aes_state);

void printmaskedstate(masked_state inp);

void print_expandedkey(byte W[AES_KEY_SIZE*(Nr+1)]);
void check_keys(byte W[AES_KEY_SIZE*(Nr+1)]);

void print_expandedkey_masked(byte Wp[n+1][AES_KEY_SIZE*(Nr+1)]);

void printtable(shares T[256]);



#endif /* test_functions_h */
