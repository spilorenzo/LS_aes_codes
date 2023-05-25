//
//  lookuptable_sbox.c
//  masked_aes
//
//  Created by Lorenzo SPIGNOLI on 11/04/2023.
//

#include "lookuptable_sbox.h"

void refresh_table_line(shares Tinp, shares Tout){
    
    // define auxiliary variable
    byte aux;
    
    for (int i=0; i<n+1; i++) {
        Tout[i] = Tinp[i];
    }

    // compute the refresh
    for (int i=0; i<n+1; i++) {
        for (int j=i+1; j<n+1; j++) {
            aux = rand()%256;
            Tout[i] = Tout[i] ^ aux;
            Tout[j] = Tout[j] ^ aux;
        }
    }
    
};

void masked_sbox_table(masked_state input){
    
    // perform the masked lookup table sbox for each element of the state
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        // define table T and T'
        shares T[256];
        shares Tp[256];
        // for every string u compute T(u)=(S(u),0,0,0,...,0)
        for (int u=0; u<256; u++) {
            for (int i=0; i<n+1; i++) {
                if(i==0){
                    T[u][i] = get_sbox_value(u);
                } else{
                    T[u][i] = 0;
                }
            }
        }
        
        // compute the shiftings of the table for each share input[j][i] (i.e. every share of the jth element of the state)
        for (int i=0; i<n; i++) {
            for (int u=0; u<256; u++) {
                for (int ip=0; ip<n+1; ip++) {
                    Tp[u][ip] = T[(u^input[i][j])][ip];
                }
            }
            
            for (int u=0; u<256; u++) {
                refresh_table_line(Tp[u], T[u]);
            }
        }
        
        // refresh the T table at the input[n][j] point (i.e. the last shares of the jth element of the state)
        refresh_table_line(T[input[n][j]],Tp[input[n][j]]);
        
        for (int i=0; i<n+1; i++) {
            input[i][j] = Tp[input[n][j]][i];
        }
    }
    
};

void masked_rsbox_table(masked_state input){
    
    // perform the masked lookup table sbox for each element of the state
    for (int j=0; j<AES_BLOCK_SIZE; j++) {
        // define table T and T'
        shares T[256];
        shares Tp[256];
        // for every string u compute T(u)=(S(u),0,0,0,...,0)
        for (int u=0; u<256; u++) {
            for (int i=0; i<n+1; i++) {
                if(i==0){
                    T[u][i] = get_rsbox_value(u);
                } else{
                    T[u][i] = 0;
                }
            }
        }
        
        // compute the shiftings of the table for each share input[j][i] (i.e. every share of the jth element of the state)
        for (int i=0; i<n; i++) {
            for (int u=0; u<256; u++) {
                for (int ip=0; ip<n+1; ip++) {
                    Tp[u][ip] = T[(u^input[i][j])][ip];
                }
            }
            
            for (int u=0; u<256; u++) {
                refresh_table_line(Tp[u], T[u]);
            }
        }
        
        // refresh the T table at the input[n][j] point (i.e. the last shares of the jth element of the state)
        refresh_table_line(T[input[n][j]],Tp[input[n][j]]);
        
        for (int i=0; i<n+1; i++) {
            input[i][j] = Tp[input[n][j]][i];
        }
    }
    
};

void subbyte_masked_table(masked_state aes_state_shares){
    
    // call the masked sbox table
    masked_sbox_table(aes_state_shares);
    
};

void inv_subbyte_masked_table(masked_state aes_state_shares){
    
    // call the inverse of the masked sbox table
    masked_rsbox_table(aes_state_shares);
    
};

void aes_encryption_masked_table(masked_state aes_state_shares, masked_state aes_key_shares){
    
    // expand the aes_key
    key_expansion_masked(aes_key_shares);
    
    // AddRoundKey[0]
    addroundkey_masked(aes_state_shares, 0);
    
    // first Nr-1 rounds
    for (int r=1; r<Nr; r++) {
        
        // SubByte
        subbyte_masked_table(aes_state_shares);
        // ShiftRows
        shiftrows_masked(aes_state_shares);
        // MixColumn
        mixcolumns_masked(aes_state_shares);
        // AddRoundKey[i]
        addroundkey_masked(aes_state_shares, r);
    }
    
    // final round
    // SubByte
    subbyte_masked_table(aes_state_shares);
    // ShiftRows
    shiftrows_masked(aes_state_shares);
    // AddRoundKey[Nr]
    addroundkey_masked(aes_state_shares, Nr);
    
};

void aes_decryption_masked_table(masked_state aes_state_shares, masked_state aes_key_shares){
    
    // expand the aes_key
    //key_expansion(aes_key);
    
    // AddRoundKey[0]
    addroundkey_masked(aes_state_shares, Nr);
    
    // first Nr-1 rounds
    for (int r=Nr-1; r>0; r--) {
        
        // Inverse of ShiftRows
        inv_shiftrows_masked(aes_state_shares);
        // inverse of SubByte
        inv_subbyte_masked_table(aes_state_shares);
        // AddRoundKey[i]
        addroundkey_masked(aes_state_shares, r);
        // Inverse of MixColumn
        inv_mixcolumns_masked(aes_state_shares);
    }
    
    // final round
    // Inverse of ShiftRows
    inv_shiftrows_masked(aes_state_shares);
    // Inverse of SubByte
    inv_subbyte_masked_table(aes_state_shares);
    // AddRoundKey[Nr]
    addroundkey_masked(aes_state_shares, 0);
    
};
