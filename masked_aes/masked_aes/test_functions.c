//
//  test_functions.c
//  masked_aes
//
//  Created by Lorenzo SPIGNOLI on 18/04/2023.
//

#include "test_functions.h"

void printstate(state aes_state){
    
    printf("[%X,", aes_state[0]);
    for (int i=1; i<AES_BLOCK_SIZE; i++) {
        printf("%X,",aes_state[i]);
        if(i==AES_BLOCK_SIZE-2){
            i++;
            printf("%X]\n",aes_state[i]);
        }
    }
};

void printstate_matrix(state aes_state){
    
    //printf("state in matrix form:\n");
    for (int i=0; i<4; i++) {
        printf("%X %X %X %X\n", aes_state[0+i], aes_state[4+i], aes_state[8+i], aes_state[12+i]);
    }
    
};

void printmaskedstate(masked_state aes_shares){
    
    for (int i=0; i<=n; i++) {
        printf("#%X -> [ ", i);
        for(int j=0; j<AES_BLOCK_SIZE; j++){
            if(j==AES_BLOCK_SIZE-1){
                printf("%X ]\n", aes_shares[i][j]);
            } else{
                printf("%X, ", aes_shares[i][j]);
            }
        }
    }
};

void print_expandedkey(byte W[AES_KEY_SIZE*(Nr+1)]){

    // print the ExpandedKey in matrix form
    for (int i=0; i<Nr+1; i++) {
        printf("Round %d: ",i);
        for (int j=0; j<16; j++) {
            printf("%X ", W[(i*16)+j]);
        }
        printf("\n");
    }
};

void check_keys(byte W[AES_KEY_SIZE*(Nr+1)]){
    
    state key0 = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6d, 0x79, 0x20, 0x4b, 0x75, 0x6e, 0x67, 0x20, 0x46, 0x75};
    state key1 = {0xe2, 0x32, 0xfc, 0xf1, 0x91, 0x12, 0x91, 0x88, 0xb1, 0x59, 0xe4, 0xe6, 0xd6, 0x79, 0xa2, 0x93};
    state key2 = {0x56, 0x08, 0x20, 0x07, 0xc7, 0x1a, 0xb1, 0x8f, 0x76, 0x43, 0x55, 0x69, 0xa0, 0x3a, 0xf7, 0xfa};
    state key3 = {0xd2, 0x60, 0x0d, 0xe7, 0x15, 0x7a, 0xbc, 0x68, 0x63, 0x39, 0xe9, 0x01, 0xc3, 0x03, 0x1e, 0xfb};
    state key4 = {0xa1, 0x12, 0x02, 0xc9, 0xb4, 0x68, 0xbe, 0xa1, 0xd7, 0x51, 0x57, 0xa0, 0x14, 0x52, 0x49, 0x5b};
    state key5 = {0xb1, 0x29, 0x3b, 0x33, 0x05, 0x41, 0x85, 0x92, 0xd2, 0x10, 0xd2, 0x32, 0xc6, 0x42, 0x9b, 0x69};
    state key6 = {0xbd, 0x3d, 0xc2, 0xb7, 0xb8, 0x7c, 0x47, 0x15, 0x6a, 0x6c, 0x95, 0x27, 0xac, 0x2e, 0x0e, 0x4e};
    state key7 = {0xcc, 0x96, 0xed, 0x16, 0x74, 0xea, 0xaa, 0x03, 0x1e, 0x86, 0x3f, 0x24, 0xb2, 0xa8, 0x31, 0x6a};
    state key8 = {0x8e, 0x51, 0xef, 0x21, 0xfa, 0xbb, 0x45, 0x22, 0xe4, 0x3d, 0x7a, 0x06, 0x56, 0x95, 0x4b, 0x6c};
    state key9 = {0xbf, 0xe2, 0xbf, 0x90, 0x45, 0x59, 0xfa, 0xb2, 0xa1, 0x64, 0x80, 0xb4, 0xf7, 0xf1, 0xcb, 0xd8};
    state key10 = {0x28, 0xfd, 0xde, 0xf8, 0x6d, 0xa4, 0x24, 0x4a, 0xcc, 0xc0, 0xa4, 0xfe, 0x3b, 0x31, 0x6f, 0x26};
    
    printf("keys check:\n");
    
    byte test0 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[0+i] != key0[i]) {
            test0 = 0;
        }
    }
    printf("ExpandedKey[0] = key0? -> %X\n", test0);
    
    byte test1 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[16+i] != key1[i]) {
            test1 = 0;
        }
    }
    printf("ExpandedKey[1] = key1? -> %X\n", test1);
    
    byte test2 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[32+i] != key2[i]) {
            test2 = 0;
        }
    }
    printf("ExpandedKey[2] = key2? -> %X\n", test2);
    
    byte test3 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[48+i] != key3[i]) {
            test3 = 0;
        }
    }
    printf("ExpandedKey[3] = key3? -> %X\n", test3);
    
    byte test4 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[64+i] != key4[i]) {
            test4 = 0;
        }
    }
    printf("ExpandedKey[4] = key4? -> %X\n", test4);
    
    byte test5 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[80+i] != key5[i]) {
            test5 = 0;
        }
    }
    printf("ExpandedKey[5] = key5? -> %X\n", test5);
    
    byte test6 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[96+i] != key6[i]) {
            test0 = 0;
        }
    }
    printf("ExpandedKey[6] = key6? -> %X\n", test6);
    
    byte test7 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[112+i] != key7[i]) {
            test7 = 0;
        }
    }
    printf("ExpandedKey[7] = key7? -> %X\n", test7);
    
    byte test8 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[128+i] != key8[i]) {
            test8 = 0;
        }
    }
    printf("ExpandedKey[8] = key8? -> %X\n", test8);
    
    byte test9 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[144+i] != key9[i]) {
            test9 = 0;
        }
    }
    printf("ExpandedKey[9] = key9? -> %X\n", test9);
    
    byte test10 = 1;
    for (int i=0; i<AES_KEY_SIZE; i++) {
        if(W[160+i] != key10[i]) {
            test10 = 0;
        }
    }
    printf("ExpandedKey[10] = key10? -> %X\n", test10);
};

void print_expandedkey_masked(byte Wp[n+1][AES_KEY_SIZE*(Nr+1)]){

    // print the ExpandedKey in matrix form
    byte sum[16] = {0,};
    
    for (int i=0; i<Nr+1; i++) {
        printf("Round %d:\n",i);
        
        for (int j=0; j<n+1; j++) {
            for (int k=0; k<16; k++) {
                sum[k] = sum[k] ^ Wp[j][(i*16)+k];
            }
        }
        printf("Xored key: [");
        for (int j=0; j<16; j++) {
            if(j==15){
                printf("%X]\n", sum[j]);
            } else {
                printf("%X,", sum[j]);
            }
        }
        for (int f=0; f<16; f++) {
            sum[f] = 0;
        }
        
    }
};

void printtable(shares T[256]){
    
    for (int u=0; u<256; u++) {
        printf("%u : ", u);
        for (int i=0; i<n+1; i++) {
            if(i==n){
                printf("%X\n", T[u][i]);
            } else{
                printf("%X ", T[u][i]);
            }
        }
    }
};

