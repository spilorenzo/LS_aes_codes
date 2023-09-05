//
//  AES.h
//  AES_implementation
//
//  Created by Lorenzo Spignoli on 07/01/2021.
//  Copyright © 2021 Lorenzo Spignoli. All rights reserved.
//

#ifndef AES_h
#define AES_h

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef unsigned char byte;

// lenght of the block
#define BLOCKLEN_bit 128
// number of column of the state in matrix form
#define Nb BLOCKLEN_bit/32
// number of element in vector representation of the block
#define BLOCKLEN BLOCKLEN_bit/8

// lenght of the key
#define KEYLEN_bit 128
// number of column of the key in matrix form
#define Nk KEYLEN_bit/32
// number of element in vector representation of the key
#define KEYLEN KEYLEN_bit/8

// number of rounds
#define Nr 10

// define struct for the states:
// the state is represented by a vector where each element represnt 8bit of information
typedef byte state[BLOCKLEN];

void initial_state(state output, byte *input);
void final_output(state vct_state, byte *output);

void print_state(state vct_state);

void key_expansion(state vct_key);

byte get_sbox_value(byte index);
byte get_rsbox_value(byte index);
byte get_rcon_value(byte index);

void subbyte(state vct_state);
void inv_subbyte(state vct_state);

void shiftrows(state vct_state);
void inv_shiftrows(state vct_state);

byte xtime(byte x);
byte multiply(byte x, byte y);
void preprocessing_step(state vct_state);

void mixcolumns(state vct_state);
void mixcolumns_slow(state vct_state);
void inv_mixcolumns(state vct_state);
void inv_mixcolumns_slow(state vct_state);

void addroundkey(state vct_state, byte round);

byte *AES_encrypting(byte *plaintext, byte *key);
byte *AES_decrypting(byte *chiphertext, byte *key);

#endif /* AES_h */
