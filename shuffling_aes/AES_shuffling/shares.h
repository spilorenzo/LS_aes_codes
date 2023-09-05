//
//  shares.h
//  AES_shuffling
//
//  Created by Lorenzo SPIGNOLI on 20/02/21.
//

#ifndef shares_h
#define shares_h

#include "AES.h"
#include <math.h>

// number of shares
#define m 668

// define struct for the shares:
// the shares are represented by a vector of m+1 elements, which xored will return 8bit of information
typedef byte shares[m+1];

void copy_shares(shares vct_x, shares vct_y);

byte square(byte x);
byte affine(byte x);
byte inv_affine(byte x);

void square_shares(shares vct_state);

byte mult(byte x,byte y);
byte multtable(byte x,byte y);
void sec_mult(shares vct_a, shares vct_b, shares vct_c);

void refresh_masks(shares vct_x);

byte exp254(byte x);
void sec_exp254(shares vct_x);

void sec_sbox(shares vct_x);
void sec_rsbox(shares vct_x);

#endif /* shares_h */
