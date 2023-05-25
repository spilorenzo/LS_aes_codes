//
//  shares.h
//  masked+prg_aes
//
//  Created by Lorenzo SPIGNOLI on 25/05/2023.
//

#ifndef shares_h
#define shares_h

#include <stdio.h>
#include <stdlib.h>

// define the masking order (recall the number of shares is n+1)
#define n 15

// define a byte of information as unsigned char
typedef unsigned char byte;

// define struct for the general shares:
// the general shares are represented by a vector of n+1 byte, which xored will return a sensitive byte
typedef byte shares[n+1];

void copy_shares(shares input, shares output);

void refreshmasks(shares input);

byte get_square(byte x);
byte get_affine(byte x);
byte get_inv_affine(byte x);

void square_shares(shares input);

byte multtable(byte x,byte y);
void sec_mult(shares input_a, shares input_b, shares output);

void sec_exp254(shares input);

void sec_sbox(shares input);
void sec_rsbox(shares input);

#endif /* shares_h */


