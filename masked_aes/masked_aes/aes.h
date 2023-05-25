//
//  aes.h
//  masked_aes
//
//  Created by Lorenzo SPIGNOLI on 18/04/2023.
//

#ifndef aes_h
#define aes_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// define a byte of information as unsigned char
typedef unsigned char byte;

// lenght of the block in bytes
#define AES_BLOCK_SIZE 16

// lenght of the key in bytes
#define AES_KEY_SIZE 16

// lenght of the key in column
#define Nk (AES_KEY_SIZE/4)

// number of rounds
#define Nr 10

typedef byte state[AES_BLOCK_SIZE];
typedef byte key[AES_KEY_SIZE];

byte get_sbox_value(byte index);
byte get_rsbox_value(byte index);
byte get_rcon_value(byte i);

void key_expansion(key aes_key);

void subbyte(state aes_state);
void inv_subbyte(state aes_state);

void shiftrows(state aes_state);
void inv_shiftrows(state aes_state);

byte xtime(byte x);
byte multiply(byte x, byte y);
void preprocessing_step(state aes_state);

void mixcolumns(state aes_state);
void inv_mixcolumns(state aes_state);

void addroundkey(state aes_state, byte round);

void aes_encryption(state aes_state, state aes_key);
void aes_decryption(state ase_state, state aes_key);

#endif /* aes_h */
