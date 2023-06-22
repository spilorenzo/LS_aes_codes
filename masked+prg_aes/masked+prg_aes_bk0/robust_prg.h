//
//  robust_prg.h
//  masked+prg_aes
//
//  Created by Lorenzo SPIGNOLI on 25/05/2023.
//

#ifndef robust_prg_h
#define robust_prg_h

#include "lookuptable_sbox.h"

// define struct for the element in GF(2^16):
// 2-degree extention of GF(2^8) to rapresent the field GF(2^16), i.e. GF(2^8)[x]/(x^2+x+t^5) or GF(2)(t)[x]/(x^2+x+t^5)
// so an element of GF(2^16) is stored as a vector of two element in GF(2^8)
typedef byte poly16[2];

// degree of the polynomial
#define deg 2
#define degsize (deg+1)


typedef struct{
    int nextx;
    poly16 coeff[degsize];
    int flag;
    poly16 value;
} tprg;

typedef struct{
    tprg prg[n];
} trobprg;

void multiply_gf16(poly16 a, poly16 b, poly16 c);
void poly_evaluation(poly16 coefficients[], poly16 x, poly16 result);

void init_prg(tprg *prg);
byte get_prg_value(tprg *prg);

void init_robprg(trobprg *robprg);
byte get_robprg_value(trobprg *robprg);

void locality_refreshing(masked_state input);

void secmult_flr(masked_state a_shares, masked_state b_shares, masked_state ab_shares);

void secmult_ilr(masked_state a_shares, masked_state b_shares, masked_state ab_shares);
void secmult_ilr2(masked_state a_shares, masked_state b_shares, masked_state ab_shares);

#endif /* robust_prg_h */
