//
//  aes.c
//  masked+prg_aes
//
//  Created by Lorenzo SPIGNOLI on 25/05/2023.
//

#include "aes.h"

byte sbox[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

byte rsbox[256]={
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,
0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,
0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,
0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,
0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,
0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,
0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,
0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,
0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,
0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,
0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

byte rcon[255]={
0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,
0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a,
0x2f,0x5e,0xbc,0x63,0xc6,0x97,0x35,0x6a,
0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,0x39,
0x72,0xe4,0xd3,0xbd,0x61,0xc2,0x9f,0x25,
0x4a,0x94,0x33,0x66,0xcc,0x83,0x1d,0x3a,
0x74,0xe8,0xcb,0x8d,0x01,0x02,0x04,0x08,
0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,
0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,
0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,
0xc5,0x91,0x39,0x72,0xe4,0xd3,0xbd,0x61,
0xc2,0x9f,0x25,0x4a,0x94,0x33,0x66,0xcc,
0x83,0x1d,0x3a,0x74,0xe8,0xcb,0x8d,0x01,
0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,
0x36,0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,
0xbc,0x63,0xc6,0x97,0x35,0x6a,0xd4,0xb3,
0x7d,0xfa,0xef,0xc5,0x91,0x39,0x72,0xe4,
0xd3,0xbd,0x61,0xc2,0x9f,0x25,0x4a,0x94,
0x33,0x66,0xcc,0x83,0x1d,0x3a,0x74,0xe8,
0xcb,0x8d,0x01,0x02,0x04,0x08,0x10,0x20,
0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,
0x9a,0x2f,0x5e,0xbc,0x63,0xc6,0x97,0x35,
0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,
0x39,0x72,0xe4,0xd3,0xbd,0x61,0xc2,0x9f,
0x25,0x4a,0x94,0x33,0x66,0xcc,0x83,0x1d,
0x3a,0x74,0xe8,0xcb,0x8d,0x01,0x02,0x04,
0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,
0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,
0xc6,0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,
0xef,0xc5,0x91,0x39,0x72,0xe4,0xd3,0xbd,
0x61,0xc2,0x9f,0x25,0x4a,0x94,0x33,0x66,
0xcc,0x83,0x1d,0x3a,0x74,0xe8,0xcb};

// declare vector for the ExpandedKey
byte W[AES_KEY_SIZE*(Nr+1)];

byte get_sbox_value(byte index){
    
    // return the index-th element of the SBox
    return sbox[index];
};

byte get_rsbox_value(byte index){
    
    // return the index-th element of the InvSBox
    return rsbox[index];
};

byte get_rcon_value(byte i){
    
    // return x^(i-1)
    return rcon[i];
};

byte xtime(byte x){
    
    // compute the moltiplication by x (02)
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
};

byte multiply(byte x, byte y){
    
    // compute the moltiplication between polynomials x * y mod x^4+1
    // taken from https://github.com/kokke/tiny-AES-c
    return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
};

void key_expansion(key aes_key){
    
    // define auxiliary vector for column of W
    byte temp[4];
    
    // the first RoundKey is the key itself
    for (int i=0; i<4; i++){
        W[4*i] = aes_key[4*i];
        W[(4*i)+1] = aes_key[(4*i)+1];
        W[(4*i)+2] = aes_key[(4*i)+2];
        W[(4*i)+3] = aes_key[(4*i)+3];
    }
    
    
    // compute the other RoundKeys
    for (int i=4; i<4*(Nr+1); i++) {
        
        // recover the 4th previous column
        temp[0] = W[4*(i-4)];
        temp[1] = W[(4*(i-4))+1];
        temp[2] = W[(4*(i-4))+2];
        temp[3] = W[(4*(i-4))+3];
        
        if (i%4 == 0) {
            
            // xor the 4th previous column with the Sbox values of the rotated 1st previous column
            temp[0] = temp[0] ^ get_sbox_value(W[(4*(i-1))+1]);
            temp[1] = temp[1] ^ get_sbox_value(W[(4*(i-1))+2]);
            temp[2] = temp[2] ^ get_sbox_value(W[(4*(i-1))+3]);
            temp[3] = temp[3] ^ get_sbox_value(W[4*(i-1)]);
            
            // xor the first element of the column with RC[i/4]
            temp[0] = temp[0] ^ get_rcon_value(i/4);
            
            // save the computed column in W
            W[4*i] = temp[0];
            W[(4*i)+1] = temp[1];
            W[(4*i)+2] = temp[2];
            W[(4*i)+3] = temp[3];
        } else{
            
            // xor with the 1st previous column
            temp[0] = temp[0] ^ W[4*(i-1)];
            temp[1] = temp[1] ^ W[(4*(i-1))+1];
            temp[2] = temp[2] ^ W[(4*(i-1))+2];
            temp[3] = temp[3] ^ W[(4*(i-1))+3];
            
            // save the computed column in W
            W[4*i] = temp[0];
            W[(4*i)+1] = temp[1];
            W[(4*i)+2] = temp[2];
            W[(4*i)+3] = temp[3];
        }
    }
};

void subbyte(state aes_state){
    
    //for every element of the state x = sbox(x)
    for (int i=0; i<AES_BLOCK_SIZE; i++) {
        aes_state[i] = get_sbox_value(aes_state[i]);
    }
};

void inv_subbyte(state aes_state){
    
    //for every element of the state x = rsbox(x)
    for (int i=0; i<AES_BLOCK_SIZE; i++) {
        aes_state[i] = get_rsbox_value(aes_state[i]);
    }
};

void shiftrows(state aes_state){
    
    // define auxiliary variable for the shifting
    byte temp;
    
    // the 0th row remain the same, so shift the 1st row by one column position
    temp = aes_state[1];
    aes_state[1] = aes_state[5];
    aes_state[5] = aes_state[9];
    aes_state[9] = aes_state[13];
    aes_state[13] = temp;
    
    // shift the 2nd row by two column positions
    temp = aes_state[2];
    aes_state[2] = aes_state[10];
    aes_state[10] = temp;
    temp = aes_state[6];
    aes_state[6] = aes_state[14];
    aes_state[14] = temp;
    
    // shift the 3rd row by three column positions
    temp = aes_state[3];
    aes_state[3] = aes_state[15];
    aes_state[15] = aes_state[11];
    aes_state[11] = aes_state[7];
    aes_state[7] = temp;
};

void inv_shiftrows(state aes_state){
    
    // define auxiliary variable for the shifting
    byte temp;
    
    // the 0th row remain the same, so shift the 1st row by one column position
    temp = aes_state[1];
    aes_state[1] = aes_state[13];
    aes_state[13] = aes_state[9];
    aes_state[9] = aes_state[5];
    aes_state[5] = temp;
    
    // shift the 2nd row by two column positions
    temp = aes_state[2];
    aes_state[2] = aes_state[10];
    aes_state[10] = temp;
    temp = aes_state[6];
    aes_state[6] = aes_state[14];
    aes_state[14] = temp;
    
    // shift the 3rd row by three column positions
    temp = aes_state[3];
    aes_state[3] = aes_state[7];
    aes_state[7] = aes_state[11];
    aes_state[11] = aes_state[15];
    aes_state[15] = temp;
};


void mixcolumns(state aes_state){
    
    // define auxiliary variables for the multiplication
    byte t;
    byte u;
    byte v;
    
    byte temp[4];
    
    // for each column perform the multiplication
    for (int i=0; i<4; i++) {
        
        // consider the i-th colum
        temp[0] = aes_state[4*i];
        temp[1] = aes_state[(4*i)+1];
        temp[2] = aes_state[(4*i)+2];
        temp[3] = aes_state[(4*i)+3];
        
        // efficent computation of MixColumn as describe in AES textbook
        t = temp[0] ^ temp[1] ^ temp[2] ^ temp[3];
        u = temp[0];
        v = temp[0] ^ temp[1];
        v = xtime(v);
        aes_state[4*i] = aes_state[4*i] ^ v ^ t;
        v = temp[1] ^ temp[2];
        v = xtime(v);
        aes_state[(4*i)+1] = aes_state[(4*i)+1] ^ v ^ t;
        v = temp[2] ^ temp[3];
        v = xtime(v);
        aes_state[(4*i)+2] = aes_state[(4*i)+2] ^ v ^ t;
        v = temp[3] ^ u;
        v = xtime(v);
        aes_state[(4*i)+3] = aes_state[(4*i)+3] ^ v ^ t;
    }
};

void preprocessing_step(state aes_state){
    
    // define auxiliary variables
    byte u;
    byte v;
    
    byte temp[4];
    
    // for each column perform the multiplication
    for (int i=0; i<4; i++) {
        
        // consider the i-th colum
        temp[0] = aes_state[4*i];
        temp[1] = aes_state[(4*i)+1];
        temp[2] = aes_state[(4*i)+2];
        temp[3] = aes_state[(4*i)+3];
        
        byte aux_u = temp[0] ^ temp[2];
        u = xtime(xtime(aux_u));
        byte aux_v = temp[1] ^ temp[3];
        v = xtime(xtime(aux_v));
        
        
        aes_state[4*i] = aes_state[4*i] ^ u;
        aes_state[(4*i)+1] = aes_state[(4*i)+1] ^ v;
        aes_state[(4*i)+2] = aes_state[(4*i)+2] ^ u;
        aes_state[(4*i)+3] = aes_state[(4*i)+3] ^ v;
    }
};

void inv_mixcolumns(state aes_state){
    
    // efficent computation of InvMixColumn as describe in AES textbook
    // i.e. it is composed by a preprocessing step followed by a MixColumn
    preprocessing_step(aes_state);
    mixcolumns(aes_state);
    
};

void addroundkey(state aes_state, byte round){
    
    // compute element by element the xor between the state and the round key
    for (int i=0; i<AES_BLOCK_SIZE; i++) {
        aes_state[i] = aes_state[i] ^ W[(AES_BLOCK_SIZE*round)+i];
    }
    
};

void aes_encryption(state aes_state, state aes_key){
    
    // expand the aes_key
    key_expansion(aes_key);
    
    // AddRoundKey[0]
    addroundkey(aes_state, 0);
    
    // first Nr-1 rounds
    for (int r=1; r<Nr; r++) {
        
        // SubByte
        subbyte(aes_state);
        // ShiftRows
        shiftrows(aes_state);
        // MixColumn
        mixcolumns(aes_state);
        // AddRoundKey[i]
        addroundkey(aes_state, r);
    }
    
    // final round
    // SubByte
    subbyte(aes_state);
    // ShiftRows
    shiftrows(aes_state);
    // AddRoundKey[Nr]
    addroundkey(aes_state, Nr);
    
};

void aes_decryption(state aes_state, state aes_key){
    
    // expand the aes_key
    //key_expansion(aes_key);
    
    // AddRoundKey[0]
    addroundkey(aes_state, Nr);
    
    // first Nr-1 rounds
    for (int r=Nr-1; r>0; r--) {
        
        // Inverse of ShiftRows
        inv_shiftrows(aes_state);
        // inverse of SubByte
        inv_subbyte(aes_state);
        // AddRoundKey[i]
        addroundkey(aes_state, r);
        // Inverse of MixColumn
        inv_mixcolumns(aes_state);
    }
    
    // final round
    // Inverse of ShiftRows
    inv_shiftrows(aes_state);
    // Inverse of SubByte
    inv_subbyte(aes_state);
    // AddRoundKey[Nr]
    addroundkey(aes_state, 0);
};

