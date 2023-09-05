//
//  AES_shuffling.c
//  AES_shuffling
//
//  Created by Lorenzo SPIGNOLI on 20/02/21.
//

#include "AES_shuffling.h"

state_ss Wss[Nr+1];

void encoding_block_stsec(byte *plaintext, state_ss input_s){
    
    for (int i=0; i<BLOCKLEN; i++) {
        byte pl = plaintext[i];
        
        for (int j=0; j<m; j++) {
            int rdm = rand()%256;
            pl ^= rdm;
            int position = rand()%ell;
            input_s[i][j][ell] = position;
            for (int l=0; l<ell; l++) {
                if (l==position) {
                    input_s[i][j][l] = rdm;
                } else {
                    input_s[i][j][l] = dummy_value;
                }
            }
        }
        int position = rand()%ell;
        input_s[i][m][ell] = position;
        for (int l=0; l<ell; l++) {
            if (l==position) {
                input_s[i][m][l] = pl;
            } else {
                input_s[i][m][l] = dummy_value;
            }
        }
    }
};

byte *decoding_block_stsec(state_ss output_s){
    
    byte *output = calloc(16, sizeof(byte));
    
    for (int i=0; i<BLOCKLEN; i++) {
        byte aux = 0;
        for (int j=0; j<m+1; j++) {
            byte index = output_s[i][j][ell];
            aux ^= output_s[i][j][index];
        }
        output[i] = aux;
    }
    return output;
};

void print_state_stsec(state_ss input_s){
    
    for (int i=0; i<BLOCKLEN; i++) {
        printf("State[%d]: ",i);
        byte aux = 0;
        for (int j=0; j<m+1; j++) {
            byte index = input_s[i][j][ell];
            aux ^= input_s[i][j][index];
            for (int l=0; l<ell+1; l++) {
                printf("%X ",input_s[i][j][l]);
            }
            printf(" ");
        }
        printf("xor %X\n",aux);
    }
};

void print_expandedkey_stsec(){
    
    for (int i=0; i<Nr+1; i++) {
        printf("RoundKey[%d]:\n", i);
        print_state_stsec(Wss[i]);
    }
};

void key_expansion_stsec(state_ss mtx_key){
    
    sparse_shares temp[4];
    sparse rc;
    
    for (int i=0; i<BLOCKLEN; i++) {
        copy_sparse_shares(mtx_key[i], Wss[0][i]);
    }
    
    for (int r=1; r<(Nr+1); r++) {
        for (int c=0; c<Nk; c++) {
            if (c==0) {
                
                // W[i] = W[i-4]
                copy_sparse_shares(Wss[r-1][0], Wss[r][0]);
                copy_sparse_shares(Wss[r-1][1], Wss[r][1]);
                copy_sparse_shares(Wss[r-1][2], Wss[r][2]);
                copy_sparse_shares(Wss[r-1][3], Wss[r][3]);
                
                // Rot(W[i-1])
                copy_sparse_shares(Wss[r-1][13], temp[0]);
                copy_sparse_shares(Wss[r-1][14], temp[1]);
                copy_sparse_shares(Wss[r-1][15], temp[2]);
                copy_sparse_shares(Wss[r-1][12], temp[3]);
                // SBox[Rot(W[i-1])]
                sec_sbox_shuff(temp[0]);
                sec_sbox_shuff(temp[1]);
                sec_sbox_shuff(temp[2]);
                sec_sbox_shuff(temp[3]);
                
                // W[i] = W[i-4] ^ SBox[Rot(W[i-1])]
                sec_xor_shuff(Wss[r][0], temp[0], Wss[r][0]);
                sec_xor_shuff(Wss[r][1], temp[1], Wss[r][1]);
                sec_xor_shuff(Wss[r][2], temp[2], Wss[r][2]);
                sec_xor_shuff(Wss[r][3], temp[3], Wss[r][3]);
                
                // W[i] = W[i-4] ^ SBox[Rot(W[i-1])] ^ [RC(r),0,0,0]
                create_sparse(rc, get_rcon_value(r));
                xor_shuff(Wss[r][0][0], rc, Wss[r][0][0]);
                
            } else {
                
                // W[i] = W[i-4]
                copy_sparse_shares(Wss[r-1][4*c], Wss[r][4*c]);
                copy_sparse_shares(Wss[r-1][(4*c)+1], Wss[r][(4*c)+1]);
                copy_sparse_shares(Wss[r-1][(4*c)+2], Wss[r][(4*c)+2]);
                copy_sparse_shares(Wss[r-1][(4*c)+3], Wss[r][(4*c)+3]);
                
                // W[i] = W[i-4] ^ W[i-1]
                sec_xor_shuff(Wss[r][4*c], Wss[r][(4*c)-4], Wss[r][4*c]);
                sec_xor_shuff(Wss[r][(4*c)+1], Wss[r][(4*c)-3], Wss[r][(4*c)+1]);
                sec_xor_shuff(Wss[r][(4*c)+2], Wss[r][(4*c)-2], Wss[r][(4*c)+2]);
                sec_xor_shuff(Wss[r][(4*c)+3], Wss[r][(4*c)-1], Wss[r][(4*c)+3]);
            }
        }
    }
};

void subbyte_stsec(state_ss mtx_state){
    
    for (int i=0; i<BLOCKLEN; i++) {
        sec_sbox_shuff(mtx_state[i]);
    }
};

void inv_subbyte_stsec(state_ss mtx_state){
    
    for (int i=0; i<BLOCKLEN; i++) {
        sec_rsbox_shuff(mtx_state[i]);
    }
};

void shiftrows_stsec(state_ss mtx_state){
    
    sparse_shares temp;
    
    // shift the 1st sparse share
    copy_sparse_shares(mtx_state[1], temp);
    copy_sparse_shares(mtx_state[5], mtx_state[1]);
    copy_sparse_shares(mtx_state[9], mtx_state[5]);
    copy_sparse_shares(mtx_state[13], mtx_state[9]);
    copy_sparse_shares(temp, mtx_state[13]);
    
    // shift the 2nd sparse share
    copy_sparse_shares(mtx_state[6], temp);
    copy_sparse_shares(mtx_state[14], mtx_state[6]);
    copy_sparse_shares(temp, mtx_state[14]);
    copy_sparse_shares(mtx_state[2], temp);
    copy_sparse_shares(mtx_state[10], mtx_state[2]);
    copy_sparse_shares(temp, mtx_state[10]);
    
    // shift the 3rd sparse shares
    copy_sparse_shares(mtx_state[15], temp);
    copy_sparse_shares(mtx_state[11], mtx_state[15]);
    copy_sparse_shares(mtx_state[7], mtx_state[11]);
    copy_sparse_shares(mtx_state[3], mtx_state[7]);
    copy_sparse_shares(temp, mtx_state[3]);
};

void inv_shiftrows_stsec(state_ss mtx_state){
    
    sparse_shares temp;
    
    // shift the 1st sparse share
    copy_sparse_shares(mtx_state[1], temp);
    copy_sparse_shares(mtx_state[13], mtx_state[1]);
    copy_sparse_shares(mtx_state[9], mtx_state[13]);
    copy_sparse_shares(mtx_state[5], mtx_state[9]);
    copy_sparse_shares(temp, mtx_state[5]);
    
    // shift the 2nd sparse share
    copy_sparse_shares(mtx_state[6], temp);
    copy_sparse_shares(mtx_state[14], mtx_state[6]);
    copy_sparse_shares(temp, mtx_state[14]);
    copy_sparse_shares(mtx_state[2], temp);
    copy_sparse_shares(mtx_state[10], mtx_state[2]);
    copy_sparse_shares(temp, mtx_state[10]);
    
    // shift the 3rd sparse shares
    copy_sparse_shares(mtx_state[3], temp);
    copy_sparse_shares(mtx_state[7], mtx_state[3]);
    copy_sparse_shares(mtx_state[11], mtx_state[7]);
    copy_sparse_shares(mtx_state[15], mtx_state[11]);
    copy_sparse_shares(temp, mtx_state[15]);
};

void mixcolumns_stsec(state_ss mtx_state){
    
    // define auxiliary variables for the multiplication
    sparse_shares t;
    sparse_shares u;
    sparse_shares v;
    
    sparse_shares temp[4];
    
    // for each column perform the multiplication
    for (int i=0; i<Nb; i++) {
        
        // consider the i-th colum
        copy_sparse_shares(mtx_state[4*i],temp[0]);
        copy_sparse_shares(mtx_state[(4*i)+1],temp[1]);
        copy_sparse_shares(mtx_state[(4*i)+2],temp[2]);
        copy_sparse_shares(mtx_state[(4*i)+3],temp[3]);
        
        // efficent computation of MixColumn as describe in AES textbook
        sec_xor_shuff(temp[0], temp[1], t);
        sec_xor_shuff(t, temp[2], t);
        sec_xor_shuff(t, temp[3], t);
        copy_sparse_shares(temp[0],u);
        sec_xor_shuff(temp[0], temp[1], v);
        sec_xtime_shuff(v);
        sec_xor_shuff(mtx_state[4*i], v, mtx_state[4*i]);
        sec_xor_shuff(mtx_state[4*i], t, mtx_state[4*i]);
        sec_xor_shuff(temp[1], temp[2], v);
        sec_xtime_shuff(v);
        sec_xor_shuff(mtx_state[(4*i)+1], v, mtx_state[(4*i)+1]);
        sec_xor_shuff(mtx_state[(4*i)+1], t, mtx_state[(4*i)+1]);
        sec_xor_shuff(temp[2], temp[3], v);
        sec_xtime_shuff(v);
        sec_xor_shuff(mtx_state[(4*i)+2], v, mtx_state[(4*i)+2]);
        sec_xor_shuff(mtx_state[(4*i)+2], t, mtx_state[(4*i)+2]);
        sec_xor_shuff(temp[3], u, v);
        sec_xtime_shuff(v);
        sec_xor_shuff(mtx_state[(4*i)+3], v, mtx_state[(4*i)+3]);
        sec_xor_shuff(mtx_state[(4*i)+3], t, mtx_state[(4*i)+3]);
    }
};

void preprocessing_step_stsec(state_ss mtx_state){
    
    // define auxiliary variables
    sparse_shares u,v;
    sparse_shares aux_u,aux_v;
    
    sparse_shares temp[4];
    
    // for each column perform the multiplication
    for (int i=0; i<Nb; i++) {
        
        // consider the i-th colum
        copy_sparse_shares(mtx_state[4*i],temp[0]);
        copy_sparse_shares(mtx_state[(4*i)+1],temp[1]);
        copy_sparse_shares(mtx_state[(4*i)+2],temp[2]);
        copy_sparse_shares(mtx_state[(4*i)+3],temp[3]);
        
        sec_xor_shuff(temp[0], temp[2], aux_u);
        sec_xtime_shuff(aux_u);
        sec_xtime_shuff(aux_u);
        copy_sparse_shares(aux_u,u);
        sec_xor_shuff(temp[1], temp[3], aux_v);
        sec_xtime_shuff(aux_v);
        sec_xtime_shuff(aux_v);
        copy_sparse_shares(aux_v,v);
        
        sec_xor_shuff(mtx_state[4*i], u, mtx_state[4*i]);
        sec_xor_shuff(mtx_state[(4*i)+1],v,mtx_state[(4*i)+1]);
        sec_xor_shuff(mtx_state[(4*i)+2],u,mtx_state[(4*i)+2]);
        sec_xor_shuff(mtx_state[(4*i)+3],v,mtx_state[(4*i)+3]);
    }
};

void inv_mixcolumns_stsec(state_ss mtx_state){
    
    preprocessing_step_stsec(mtx_state);
    mixcolumns_stsec(mtx_state);
};

void addroundkey_stsec(state_ss mtx_state, state_ss mtx_key){
    
    for (int i=0; i<BLOCKLEN; i++) {
        sec_xor_shuff(mtx_state[i], mtx_key[i], mtx_state[i]);
    }
};

void AES_encrypting_cs(state_ss mtx_state, state_ss mtx_key){
    
    // expand the key
    key_expansion_stsec(mtx_key);
    
    // perform the first AddRoundKey
    addroundkey_stsec(mtx_state, Wss[0]);
    
    // perform the Nr-1 rounds of the algorithm
    for (int i=1; i<Nr; i++) {
        
        // compute SubByte
        subbyte_stsec(mtx_state);
        // compute ShiftRows
        shiftrows_stsec(mtx_state);
        // compute MixColumn
        mixcolumns_stsec(mtx_state);
        // compute AddRoundKey
        addroundkey_stsec(mtx_state, Wss[i]);
    }
    
    // perform the last round
    //compute SubByte
    subbyte_stsec(mtx_state);
    // compute ShiftRows
    shiftrows_stsec(mtx_state);
    // compute AddRoundKey
    addroundkey_stsec(mtx_state, Wss[Nr]);
};

void AES_decrypting_cs(state_ss mtx_state, state_ss mtx_key){
    
    // expand the key
    //key_expansion_sparse(mtx_key);
    
    // perform the last AddRoundKey
    addroundkey_stsec(mtx_state, Wss[Nr]);
    
    // perform the Nr-1 rounds of the algorithm
    for (int i=Nr-1; i>0; i--) {
        // compute InvShiftRows
        inv_shiftrows_stsec(mtx_state);
        // compute InvSubByte
        inv_subbyte_stsec(mtx_state);
        // compute AddRoundKey
        addroundkey_stsec(mtx_state, Wss[i]);
        // compute InvMixColumn
        inv_mixcolumns_stsec(mtx_state);
    }
    
    // perform the first round
    // compute InvShiftRows
    inv_shiftrows_stsec(mtx_state);
    // compute InvSubByte
    inv_subbyte_stsec(mtx_state);
    // compute AddRoundKey
    addroundkey_stsec(mtx_state, Wss[0]);
};

