//
//  aes_rp.c
//  masked+prg_aes
//
//  Created by Lorenzo SPIGNOLI on 25/05/2023.
//

#include "aes_rp.h"

// declare vector for the ExpandedKey
byte Wp[n+1][AES_KEY_SIZE*(Nr+1)];

void copy_maskedstate(masked_state inp, masked_state outp){
    
    // copy each share of input in output
    for (int i=0; i<n+1; i++) {
        for (int j=0; j<AES_BLOCK_SIZE; j++) {
            outp[i][j] = inp[i][j];
        }
    }
};

void refresh_maskedstate_rp(masked_state inp, masked_state outp){
    
    // define auxiliary variable
    byte aux;
    
    // compute the refresh from RP10 (i.e. unsecure)
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        // put each element of the last share of the input in each element of the last share of the output
        outp[0][j] = inp[0][j];
        for (int i=0; i<n; i++) {
            // refresh element by element and update the last share
            aux = rand()%256;
            outp[i][j] = inp[i][j] ^ aux;
            outp[0][j] = outp[0][j] ^ aux;
        }
    }
};

void refresh_maskedstate_bbd(masked_state inp){
    
    // define auxiliary variable
    byte aux;
    
    // compute the refresh from BBD+16 (i.e SNI)
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        for (int i=0; i<n+1; i++) {
            for (int k=i+1; k<n+1; k++) {
                // refresh element by element and update the last share
                aux = rand()%256;
                inp[i][j] = inp[i][j] ^ aux;
                inp[k][j] = inp[k][j] ^ aux;
            }
        }
    }
};

void encoding(state aes_state, masked_state aes_shares){
    
    // for each element of the state it generates n-1 ranodm element and the nth accordingly
    //(i.e x_n = x_0 ^ ... ^ x_n-1 ^ x)
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        // the type shares is allocated statically and it needs to be inizialized to 0
        aes_shares[n][j] = 0;
        for (int i=0; i<n; i++) {
            aes_shares[i][j] = rand()%256;
            aes_shares[n][j] = aes_shares[n][j] ^ aes_shares[i][j];
        }
        aes_shares[n][j] = aes_shares[n][j] ^ aes_state[j];
    }
};

void decoding(masked_state aes_shares, state aes_state){
    
    // each ith element of the n shares is xored to result in the ith element of the state
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        aes_state[j] = aes_shares[n][j];
        for (int i=0; i<n; i++) {
            aes_state[j] = aes_state[j] ^ aes_shares[i][j];
        }
    }
    
};

void key_expansion_masked(masked_state aes_key_shares){
    
    // define auxiliary vector for column of W
    shares temp[4];
    byte t;
    
    // the shares of the first KeyRound is equals to the shares of the key itself
    for (int j=0; j<Nk; j++) {
        for (int i=0; i<n+1; i++){
            Wp[i][4*j] = aes_key_shares[i][4*j];
            Wp[i][(4*j)+1] = aes_key_shares[i][(4*j)+1];
            Wp[i][(4*j)+2] = aes_key_shares[i][(4*j)+2];
            Wp[i][(4*j)+3] = aes_key_shares[i][(4*j)+3];
        }
    }
    
    // compute the shares of RoundKey for the remaining rounds
    for (int r=Nk; r<4*(Nr+1); r++) {
        
        // recover the shares of the previous column
        for (int i=0; i<n+1; i++) {
            temp[0][i] = Wp[i][(4*(r-1))];
            temp[1][i] = Wp[i][(4*(r-1))+1];
            temp[2][i] = Wp[i][(4*(r-1))+2];
            temp[3][i] = Wp[i][(4*(r-1))+3];
        }
        
        if(r%4==0){
            // for each value of the column collect each share for that value and compute sec_sbox (i.e. shares.h)
            sec_sbox(temp[0]);
            sec_sbox(temp[1]);
            sec_sbox(temp[2]);
            sec_sbox(temp[3]);
            
            for (int i=0; i<n+1; i++) {
                // for each share compute the rotation of the column
                t = temp[0][i];
                temp[0][i] = temp[1][i];
                temp[1][i] = temp[2][i];
                temp[2][i] = temp[3][i];
                temp[3][i] = t;
            }
            
            // only for the first share xor it with Rcon[j/Nk] (!!Error in the paper!!)
            temp[0][0] = temp[0][0] ^ get_rcon_value(r/4);
        }
        
        // compute the remaining value of the column
        for (int i=0; i<n+1; i++) {
            Wp[i][(4*r)] = Wp[i][4*(r-Nk)] ^ temp[0][i];
            Wp[i][(4*r)+1] = Wp[i][(4*(r-Nk))+1] ^ temp[1][i];
            Wp[i][(4*r)+2] = Wp[i][(4*(r-Nk))+2] ^ temp[2][i];
            Wp[i][(4*r)+3] = Wp[i][(4*(r-Nk))+3] ^ temp[3][i];
        }
        
    }
    
};

void secmult_rp_masked(masked_state a_shares, masked_state b_shares, masked_state ab_shares){
    
    // define auxiliary variables
    byte rij, rji, aibj, ajbi;
    
    // compute masked multiplication from RP10
    // first c_i = a_ib_i
    for (int k=0; k<AES_BLOCK_SIZE; k++) {
        for (int i=0; i<n+1; i++) {
            ab_shares[i][k] = multiply_gf8(a_shares[i][k], b_shares[i][k]);
        }
    }
    
    // then r_ij and r_ji and update c_i and c_j accordingly
    for (int k=0; k<AES_BLOCK_SIZE; k++) {
        for (int i=0; i<n+1; i++) {
            for (int j=i+1; j<n+1; j++) {
                rij = rand()%256;
                aibj = multiply_gf8(a_shares[i][k], b_shares[j][k]);
                ajbi = multiply_gf8(a_shares[j][k], b_shares[i][k]);
                rji = rij ^ aibj;
                rji = rji ^ ajbi;
                
                ab_shares[i][k] = ab_shares[i][k] ^ rij;
                ab_shares[j][k] = ab_shares[j][k] ^ rji;
            }
        }
    }
    
};

void secmult_table_masked(masked_state a_shares, masked_state b_shares, masked_state ab_shares){
    
    // define auxiliary variables
    byte rij, rji, aibj, ajbi;
    
    // compute masked multiplication using lookup-table tsmult
    // first c_i = a_ib_i
    for (int k=0; k<AES_BLOCK_SIZE; k++) {
        for (int i=0; i<n+1; i++) {
            ab_shares[i][k] = multtable(a_shares[i][k], b_shares[i][k]);
        }
    }
    
    // then r_ij and r_ji and update c_i and c_j accordingly
    for (int k=0; k<AES_BLOCK_SIZE; k++) {
        for (int i=0; i<n+1; i++) {
            for (int j=i+1; j<n+1; j++) {
                rij = rand()%256;
                aibj = multtable(a_shares[i][k], b_shares[j][k]);
                ajbi = multtable(a_shares[j][k], b_shares[i][k]);
                rji = rij ^ aibj;
                rji = rji ^ ajbi;
                
                ab_shares[i][k] = ab_shares[i][k] ^ rij;
                ab_shares[j][k] = ab_shares[j][k] ^ rji;
            }
        }
    }
    
};

void square_masked(masked_state aes_state_shares){
    
    // compute the squarings share by share using lookup-table sq[]
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        for (int i=0; i<n+1; i++) {
            byte aux = aes_state_shares[i][j];
            aes_state_shares[i][j] = get_square(aux);
        }
    }
    
};

void secexp254_masked(masked_state x_shares){
    
    // define auxiliary variable
    masked_state z_shares,y_shares,y2_shares,w_shares;
    
    // compute the exponentiation to the power of 254 from RP10
    // z=x^2
    copy_maskedstate(x_shares, z_shares);
    square_masked(z_shares);
    // refresh z
    refresh_maskedstate_bbd(z_shares);
    // y=x*z
    secmult_table_masked(x_shares, z_shares, y_shares);
    // w=y^4
    copy_maskedstate(y_shares, w_shares);
    square_masked(w_shares);
    square_masked(w_shares);
    // refresh w
    refresh_maskedstate_bbd(w_shares);
    // y=y*w
    secmult_table_masked(y_shares, w_shares, y2_shares);
    // y=y^16
    square_masked(y2_shares);
    square_masked(y2_shares);
    square_masked(y2_shares);
    square_masked(y2_shares);
    // y=y*w
    secmult_table_masked(y2_shares, w_shares, y_shares);
    // y=y*z
    secmult_table_masked(y_shares, z_shares, x_shares);
};

void subbyte_masked(masked_state aes_state_shares){
    
    // apply the exponantiation followed by the affine transformation (using lookup-table A)
    secexp254_masked(aes_state_shares);
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        for (int i=0; i<n+1; i++) {
            aes_state_shares[i][j] = get_affine(aes_state_shares[i][j]);
        }
    }
    if(n%2==1){
        for (int j=0; j<AES_BLOCK_SIZE; j++) {
            aes_state_shares[0][j] ^= 0x63;
        }
    }
};

void inv_subbyte_masked(masked_state aes_state_shares){
    
    // apply the inverse affine transformation (using lookup-table invA) followed by the exponentiation
    if(n%2==1){
        for (int j=0; j<AES_BLOCK_SIZE; j++) {
            aes_state_shares[0][j] ^= 0x63;
        }
    }
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        for (int i=0; i<n+1; i++) {
            aes_state_shares[i][j] = get_inv_affine(aes_state_shares[i][j]);
        }
    }
    secexp254_masked(aes_state_shares);
    
};

void shiftrows_masked(masked_state aes_state_shares){
    
    // compute the classical ShiftRows share by share
    for (int i=0; i<n+1; i++) {
        shiftrows(aes_state_shares[i]);
    }
};

void inv_shiftrows_masked(masked_state aes_state_shares){
    
    // compute the classical Inverse of ShiftRows share by share
    for (int i=0; i<n+1; i++) {
        inv_shiftrows(aes_state_shares[i]);
    }
};

void mixcolumns_masked(masked_state aes_state_shares){
    
    // compute the classical MixColumn share by share
    for (int i=0; i<n+1; i++) {
        mixcolumns(aes_state_shares[i]);
    }
    
};

void inv_mixcolumns_masked(masked_state aes_state_shares){
    
    // compute the classical Inverse of MixColumn share by share
    for (int i=0; i<n+1; i++) {
        inv_mixcolumns(aes_state_shares[i]);
    }
    
};

void addroundkey_masked(masked_state aes_state_shares, byte round){
    
    // compute share by share and, in turn, element by element the xor between the state and the round key
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        for (int i=0; i<n+1; i++) {
            aes_state_shares[i][j] = aes_state_shares[i][j] ^ Wp[i][(AES_BLOCK_SIZE*round)+j];
        }
    }
    
};

void aes_encryption_masked(masked_state aes_state_shares, masked_state aes_key_shares){
    
    // expand the aes_key
    key_expansion_masked(aes_key_shares);
    
    // AddRoundKey[0]
    addroundkey_masked(aes_state_shares, 0);
    
    // first Nr-1 rounds
    for (int r=1; r<Nr; r++) {
        
        // SubByte
        subbyte_masked(aes_state_shares);
        // ShiftRows
        shiftrows_masked(aes_state_shares);
        // MixColumn
        mixcolumns_masked(aes_state_shares);
        // AddRoundKey[i]
        addroundkey_masked(aes_state_shares, r);
    }
    
    // final round
    // SubByte
    subbyte_masked(aes_state_shares);
    // ShiftRows
    shiftrows_masked(aes_state_shares);
    // AddRoundKey[Nr]
    addroundkey_masked(aes_state_shares, Nr);
    
};

void aes_decryption_masked(masked_state aes_state_shares, masked_state aes_key_shares){
    
    // expand the aes_key
    //key_expansion(aes_key);
    
    // AddRoundKey[0]
    addroundkey_masked(aes_state_shares, Nr);
    
    // first Nr-1 rounds
    for (int r=Nr-1; r>0; r--) {
        
        // Inverse of ShiftRows
        inv_shiftrows_masked(aes_state_shares);
        // inverse of SubByte
        inv_subbyte_masked(aes_state_shares);
        // AddRoundKey[i]
        addroundkey_masked(aes_state_shares, r);
        // Inverse of MixColumn
        inv_mixcolumns_masked(aes_state_shares);
    }
    
    // final round
    // Inverse of ShiftRows
    inv_shiftrows_masked(aes_state_shares);
    // Inverse of SubByte
    inv_subbyte_masked(aes_state_shares);
    // AddRoundKey[Nr]
    addroundkey_masked(aes_state_shares, 0);
    
};


