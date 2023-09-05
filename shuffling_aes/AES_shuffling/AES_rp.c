//
//  AES_rp.c
//  AES_shuffling
//
//  Created by Lorenzo SPIGNOLI on 20/02/21.
//

#include "AES_rp.h"

// declare matrix for the shares of ExpandedKey
byte Ws[m+1][4*Nk*(Nr+1)];

void encoding_block(byte *plaintext, state_shares input_s){
    
    // define the (m+1)th state as the plaintext
    for (int j=0; j<BLOCKLEN; j++) {
        input_s[m][j] = plaintext[j];
    }
    
    // compute m+1 shares
    for (int j=0; j<BLOCKLEN; j++) {
        
        // for each column (i.e share) generete m bytes at random and xor all of them with the (m+1)th state
        for (int i=0; i<m; i++) {
            int rdm = rand()%256;
            input_s[i][j] = rdm;
            input_s[m][j] = input_s[m][j] ^ input_s[i][j];
        }
        
    }
};


byte *decoding_block(state_shares output_s){
    
    // define the decoded output as 0s
    byte *output = calloc(16, sizeof(byte));
    
    // xor the ith element of the state for every share
    for (int j=0; j<BLOCKLEN; j++) {
        for (int i=0; i<m+1; i++) {
            output[j] = output[j] ^ output_s[i][j];
        }
    }
    
    return output;
};

void encoding_key(byte *key, state_shares input_s){
    
    // define the (m+1)th state as the plaintext
    for (int j=0; j<KEYLEN; j++) {
        input_s[m][j] = key[j];
    }
    
    // compute m+1 shares
    for (int j=0; j<KEYLEN; j++) {
        
        // for each row generete m bytes at random and xor all of them with the (m+1)th share
        for (int i=0; i<m; i++) {
            int rdm = rand()%256;
            input_s[i][j] = rdm;
            input_s[m][j] = input_s[m][j] ^ input_s[i][j];
        }
    }
};


byte *decoding_key(state_shares output_s){
    
    // define the decoded output as 0s
    byte *output = calloc(16, sizeof(byte));
    
    // xor the ith element of the state for every share
    for (int j=0; j<KEYLEN; j++) {
        for (int i=0; i<m+1; i++) {
            output[j] = output[j] ^ output_s[i][j];
        }
    }
    
    return output;
};

void print_state_shares(state_shares mtx_state){
    
    for (int i=0; i<m+1; i++) {
        printf("Share[%d] = ",i);
        for (int j=0; j<BLOCKLEN; j++) {
            printf("%X ",mtx_state[i][j]);
        }
        printf("\n");
    }
};

void print_expandedkey_shares(){
    
    // print the ExpandedKey in matrix form
    for (int i=0; i<Nr+1; i++) {
        printf("Round %d: ",i);
        for (int j=0; j<16; j++) {
            byte aux = 0;
            for (int s=0; s<m+1; s++) {
                aux = aux ^ Ws[s][(i*16)+j];
            }
            printf("%X ", aux);
        }
        printf("\n");
    }
};

void key_expansion_shares(state_shares mtx_key){
    
    // define auxiliary vector for each share of the column
    byte temp[m+1][4];
    
    // the shares of the first KeyRound is equals to the shares of the key itself
    for (int j=0; j<Nk; j++) {
        for (int i=0; i<m+1; i++) {
            Ws[i][(4*j)] = mtx_key[i][(4*j)];
            Ws[i][(4*j)+1] = mtx_key[i][(4*j)+1];
            Ws[i][(4*j)+2] = mtx_key[i][(4*j)+2];
            Ws[i][(4*j)+3] = mtx_key[i][(4*j)+3];
        }
    }
    
    // compute the RoundKey for the remaining rounds
    for (int j=Nk; j<4*(Nr+1); j++) {
        
        // for each share consider (j-1)th column
        for (int i=0; i<m+1; i++) {
            temp[i][0] = Ws[i][(4*(j-1))];
            temp[i][1] = Ws[i][(4*(j-1))+1];
            temp[i][2] = Ws[i][(4*(j-1))+2];
            temp[i][3] = Ws[i][(4*(j-1))+3];
        }
        // if the jth column is the first column of a RoundKey
        if (j%4==0) {
        
            // for each value of the column collect each share for that value and compute secure-Sbox
            for (int l=0; l<4; l++) {
                shares aux;
                for (int i=0; i<m+1; i++) {
                    aux[i] = temp[i][l];
                }
                sec_sbox(aux);
                for (int i=0; i<m+1; i++) {
                    temp[i][l] = aux[i];
                }
            }
            
            // for each share compute the rotation of the column
            for (int i=0; i<m+1; i++) {
                byte t = temp[i][0];
                temp[i][0] = temp[i][1];
                temp[i][1] = temp[i][2];
                temp[i][2] = temp[i][3];
                temp[i][3] = t;
            }
            
            // only for the first share xor it with Rcon[j/Nk] (!!Error in the paper!!)
            temp[0][0] = temp[0][0] ^ get_rcon_value(j/4);

        }
        
        // compute the remaining value of the column
        for (int i=0; i<m+1; i++) {
            Ws[i][(4*j)] = Ws[i][(4*(j-Nk))] ^ temp[i][0];
            Ws[i][(4*j)+1] = Ws[i][(4*(j-Nk))+1] ^ temp[i][1];
            Ws[i][(4*j)+2] = Ws[i][(4*(j-Nk))+2] ^ temp[i][2];
            Ws[i][(4*j)+3] = Ws[i][(4*(j-Nk))+3] ^ temp[i][3];
        }
    }
};

void subbyte_shares(state_shares mtx_state){
    
    // apply secure SBox for each share (i.e column)
    for (int j=0; j<BLOCKLEN; j++) {
        
        // define auxiliary variable for a jth share (i.e jth column) and extract it from the shared state
        shares aux;
        for (int i=0; i<m+1; i++) {
            aux[i] = mtx_state[i][j];
        }
        
        // apply secure-Sbox to the jth share
        sec_sbox(aux);
        
        // update share values
        for (int i=0; i<m+1; i++) {
            mtx_state[i][j] = aux[i];
        }
    }
};

void inv_subbyte_shares(state_shares mtx_state){
    
    // apply secure InvSBox for each share (i.e column)
    for (int j=0; j<BLOCKLEN; j++) {
        
        // define auxiliary variable for a jth share (i.e jth column) and extract it from the states
        shares aux;
        for (int i=0; i<m+1; i++) {
            aux[i] = mtx_state[i][j];
        }
        
        // apply secure-InvSbox to the jth share
        sec_rsbox(aux);
        
        // update share values
        for (int i=0; i<m+1; i++) {
            mtx_state[i][j] = aux[i];
        }
    }
};

void shiftrows_shares(state_shares mtx_state){
    
    // for each shares state compute the classical ShiftRows
    for (int i=0; i<m+1; i++) {
        shiftrows(mtx_state[i]);
    }
};

void inv_shiftrows_shares(state mtx_state[]){
    
    // for each share state compute the classical ShiftRows
    for (int i=0; i<m+1; i++) {
        inv_shiftrows(mtx_state[i]);
    }
};

void mixcolumns_shares(state_shares mtx_state){
    
    // for each share state compute the classical ShiftRows
    for (int i=0; i<m+1; i++) {
        mixcolumns(mtx_state[i]);
    }
};

void inv_mixcolumns_shares(state mtx_state[]){
    
    // for each share state compute the classical ShiftRows
    for (int i=0; i<m+1; i++) {
        inv_mixcolumns(mtx_state[i]);
    }
};

void addroundkey_shares(state_shares mtx_state, byte round){
    
    // for each share state compute the classical AddRoundKey with the proper RoundKey
    for (int i=0; i<m+1; i++) {
        for (int j=0; j<BLOCKLEN; j++) {
            mtx_state[i][j] = mtx_state[i][j] ^ Ws[i][(16*round)+j];
        }
    }
};

void AES_encrypting_rp(state_shares mtx_state, state_shares mtx_key){
    
    // expand the key
    key_expansion_shares(mtx_key);
    
    // perform the first AddRoundKey
    addroundkey_shares(mtx_state, 0);
    
    // perform the Nr-1 rounds of the algorithm
    for (int i=1; i<Nr; i++) {
        
        // compute SubByte
        subbyte_shares(mtx_state);
        // compute ShiftRows
        shiftrows_shares(mtx_state);
        // compute MixColumn
        mixcolumns_shares(mtx_state);
        // compute AddRoundKey
        addroundkey_shares(mtx_state, i);
    }
    
    // perform the last round
    //compute SubByte
    subbyte_shares(mtx_state);
    // compute ShiftRows
    shiftrows_shares(mtx_state);
    // compute AddRoundKey
    addroundkey_shares(mtx_state, 10);
};

void AES_decrypting_rp(state_shares mtx_state, state_shares mtx_key){
    
    // expand the key
    key_expansion_shares(mtx_key);
    
    // perform the last AddRoundKey
    addroundkey_shares(mtx_state, Nr);
    
    // perform the Nr-1 rounds of the algorithm
    for (int i=Nr-1; i>0; i--) {
        // compute InvShiftRows
        inv_shiftrows_shares(mtx_state);
        // compute InvSubByte
        inv_subbyte_shares(mtx_state);
        // compute AddRoundKey
        addroundkey_shares(mtx_state, i);
        // compute InvMixColumn
        inv_mixcolumns_shares(mtx_state);
    }
    
    // perform the first round
    // compute InvShiftRows
    inv_shiftrows_shares(mtx_state);
    // compute InvSubByte
    inv_subbyte_shares(mtx_state);
    // compute AddRoundKey
    addroundkey_shares(mtx_state, 0);
};

int main5(int argc, char *argv[]) {
    
    time_t rnd = clock();
    srand((unsigned int) rnd);
    
    // define the plaintext (block) as a string
    //byte plaintext[BLOCKLEN] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    byte plaintext[BLOCKLEN] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    //byte plaintext[BLOCKLEN] = {0x54,0x77,0x6F,0x20,0x4F,0x6E,0x65,0x20,0x4E,0x69,0x6E,0x65,0x20,0x54,0x77,0x6F};
    //byte plaintext[BLOCKLEN] = {0x49,0x20,0x61,0x6d,0x20,0x73,0x6f,0x72,0x72,0x79,0x20,0x4a,0x75,0x6c,0x69,0x61};
    
    // define the key as a string
    byte key[KEYLEN] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    //byte key[KEYLEN] = {0x54,0x68,0x61,0x74,0x73,0x20,0x6D,0x79,0x20,0x4B,0x75,0x6E,0x67,0x20,0x46,0x75};
    
    // disply the plaintex and the key
    printf("Plaintext:\n");
    for (int i=0; i<BLOCKLEN; i++) {
        printf("%X ", plaintext[i]);
        if(i==BLOCKLEN-1){
            printf("\n");
        }
    }

    printf("Key:\n");
    for (int i=0; i<KEYLEN; i++) {
        printf("%X ", key[i]);
        if(i==KEYLEN-1){
            printf("\n");
        }
    }
    
    state_shares AES_state;
    encoding_block(plaintext, AES_state);
    
    state_shares AES_key;
    encoding_key(key, AES_key);
    
    clock_t start = clock();
    
//    printf("Block:\n");
//    print_state_sparse(AES_state);
//    printf("Key:\n");
//    print_state_sparse(AES_key);
//
    
    AES_encrypting_rp(AES_state, AES_key);
    
    byte *output_b = decoding_block(AES_state);
    printf("Decoded chiphertext = ");
    for (int i=0; i<BLOCKLEN; i++) {
        printf("%X ", output_b[i]);
    }
    printf("\n");
    
    AES_decrypting_rp(AES_state, AES_key);
    clock_t end = clock() - start;
    double time_taken = ((double)end)/CLOCKS_PER_SEC;
    
    byte *output_k = decoding_block(AES_state);
    printf("Decoded output plaintext = ");
    for (int i=0; i<KEYLEN; i++) {
        printf("%X ", output_k[i]);
    }
    printf("\n");
    
    printf("Total time computing: %f\n",time_taken);
    
    return 0;
};

