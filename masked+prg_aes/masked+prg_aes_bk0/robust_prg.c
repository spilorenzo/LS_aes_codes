//
//  robust_prg.c
//  masked+prg_aes
//
//  Created by Lorenzo SPIGNOLI on 25/05/2023.
//

#include "robust_prg.h"

void multiply_gf16(poly16 a, poly16 b, poly16 c){
    
    // compute the moltiplication over GF(2^16) mod x^2+x+t^5
    byte a1b1=multtable(a[1],b[1]);
    c[0] = multtable(a[0],b[0]) ^ multtable(32,a1b1);
    c[1] = multtable(a[1],b[0]) ^ multtable(a[0],b[1]) ^ a1b1;
    
}

void poly_evaluation(poly16 coefficients[], poly16 x, poly16 result) {
        
    result[0] = 0x00;
    result[1] = 0x00;

    // Evaluate the polynomial using Horner's method
    for (int i = deg; i >= 0; i--) {
        
        poly16 aux;
        multiply_gf16(result, x, aux);
        result[0] = aux[0] ^ coefficients[i][0];
        result[1] = aux[1] ^ coefficients[i][1];
    }
    
};

void init_prg(tprg *prg){
    
    // inizialize the prg:
    // x=0
    prg->nextx = 0;
    // the flag=0 (i.e. consider the first byte representing the element in GF(2^16))
    prg->flag = 0;
    // generate the coefficients for the evaliuations
    for (int i=0; i<degsize; i++) {
        prg->coeff[i][0] = rand()%256;
        prg->coeff[i][1] = rand()%256;
    }
    
};

byte get_prg_value(tprg *prg){
    
    // check if the value has been already generated and in case use the second byte representing the element in GF(2^16) (i.e. poly16[1])
    if(prg->flag==1){
        // update the flag for the next call and return the pseudorandom value
        prg->flag = 0;
        return prg->value[1];
    } else{
        // in case the value has not been generated already evaluate the polynomial and use the first byte representing the element in GF(2^16) (i.e. poly16[0])
        // transform the nextx in an element in GF(2^16)
        poly16 aux;
        aux[0] = prg->nextx & 255;
        aux[1] = prg->nextx >> 8;
        // eveluate the polynomial at point nextx
        poly_evaluation(prg->coeff, aux, prg->value);
        // update info for the next call
        prg->flag = 1;
        prg->nextx = prg->nextx+1;
        return prg->value[0];
    }
};

void init_robprg(trobprg *robprg){
    // the robust prg consist in n different normal prg
    for (int i=0; i<n+1; i++) {
        init_prg(&robprg->prg[i]);
    }
};

byte get_robprg_value(trobprg *robprg){
    // compute the xor of resulting values from the n normal prgs
    byte r = 0x00;
    for (int i=0; i<n+1; i++) {
        r = r ^ get_prg_value(&robprg->prg[i]);
    }
    return r;
};

void locality_refreshing(masked_state input){
    
    // define auxiliary variable
    byte s;
    
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        // for each element of the state compute the refreshing of the mask to minimize the randomness locality
        for (int i=0; i<n; i++) {
            
            input[n][j] = input[n][j] ^ input[i][j];
            s = rand()%256;
            input[i][j] = s;
            input[n][j] = input[n][j] ^ s;
            
        }
    }
    
};

void secmult_flr(masked_state a_shares, masked_state b_shares, masked_state ab_shares){
    
    // compute the classica RP SecMult and apply the locality refreshing
    secmult_rp_masked(a_shares, b_shares, ab_shares);
    locality_refreshing(ab_shares);
    
};

void secmult_ilr(masked_state a_shares, masked_state b_shares, masked_state ab_shares){
    
    // define auxiliary variables
    byte rij, rji, aibj, ajbi, s;
    
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        // for every element of the state compute the a_ib_i products
        for (int i=0; i<n+1; i++) {
            ab_shares[i][j] = multtable(a_shares[i][j], b_shares[i][j]);
        }
        //
        for (int k=1; k<n+1; k++) {
            for (int i=0; i<k; i++) {
                rij = rand()%256;
                aibj = multtable(a_shares[i][j], b_shares[k][j]);
                ajbi = multtable(a_shares[k][j], b_shares[i][j]);
                rji = rij ^ aibj;
                rji = rji ^ ajbi;
                
                ab_shares[i][j] = ab_shares[i][j] ^ rij;
                ab_shares[k][j] = ab_shares[k][j] ^ rji;
            }
            //
            for (int i=0; i<k; i++) {
                s = rand()%256;
                ab_shares[k][j] = ab_shares[k][j] ^ ab_shares[i][j] ^ s;
                ab_shares[i][j] = s;
            }
        }
    }
    
};

void secmult_ilr2(masked_state a_shares, masked_state b_shares, masked_state ab_shares){
    
    // define auxiliary variables
    byte rij, rji, aibj, ajbi, s;
    
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        // for every element of the state compute the a_ib_i products
        for (int i=0; i<n+1; i++) {
            ab_shares[i][j] = multtable(a_shares[i][j], b_shares[i][j]);
        }
        //
        for (int k=1; k<n+1; k++) {
            for (int i=0; i<k; i++) {
                rij = rand()%256;
                aibj = multtable(a_shares[i][j], b_shares[k][j]);
                ajbi = multtable(a_shares[k][j], b_shares[i][j]);
                rji = rij ^ aibj;
                rji = rji ^ ajbi;
                
                ab_shares[k][j] = ab_shares[k][j] ^ ab_shares[i][j] ^ rij;
                ab_shares[i][j] = rji;
            }
        }
        //
        for (int i=0; i<n; i++) {
            s = rand()%256;
            ab_shares[n][j] = ab_shares[n][j] ^ ab_shares[i][j] ^ s;
            ab_shares[i][j] = s;
        }
    }
    
};


