//
//  sparse.c
//  AES_shuffling
//
//  Created by Lorenzo SPIGNOLI on 20/02/21.
//

#include "sparse.h"

void copy_sparse(sparse input, sparse output){
    
    for (int l=0; l<ell+1; l++) {
        output[l] = input[l];
    }
};

void copy_sparse_shares(sparse_shares input, sparse_shares output){
    
    for (int j=0; j<m+1; j++) {
        for (int l=0; l<ell+1; l++) {
            output[j][l] = input[j][l];
        }
    }
};

void random_sparse(sparse new_sparse){
    
    int value = rand()%256;
    int index = rand()%ell;
    new_sparse[ell] = index;
    for (int l=0; l<ell; l++) {
        if (l==index) {
            new_sparse[l] = value;
        } else {
            new_sparse[l] = dummy_value;
        }
    }
};

void create_sparse(sparse new_sparse, byte value){
    
    int index = rand()%ell;
    new_sparse[ell] = index;
    for (int l=0; l<ell; l++) {
        if (l==index) {
            new_sparse[l] = value;
        } else {
            new_sparse[l] = dummy_value;
        }
    }
};

void cyclic_shift(sparse x_sparse, int new_index){
    
    sparse temp;
    temp[ell] = new_index;
    
    int delta = new_index - x_sparse[ell];
    if (delta < 0) {
        delta = delta + ell;
    }
    
    for (int l=0; l<ell; l++) {
        temp[l] = x_sparse[(l + ell - delta)%ell];
    }
    
    copy_sparse(temp, x_sparse);
};

void xor_shuff(sparse a_sparse, sparse b_sparse, sparse c_sparse){
    
    int jjj = rand()%ell;
    cyclic_shift(a_sparse, jjj);
    cyclic_shift(b_sparse, jjj);
    c_sparse[ell] = jjj;
    
    for (int l=0; l<ell; l++) {
        c_sparse[l] = a_sparse[l] ^ b_sparse[l];
    }
};

void mult_shuff(sparse a_sparse, sparse b_sparse, sparse c_sparse){
    
    int jjj = rand()%ell;
    cyclic_shift(a_sparse, jjj);
    cyclic_shift(b_sparse, jjj);
    c_sparse[ell] = jjj;
    
    for (int l=0; l<ell; l++) {
        c_sparse[l] = multtable(a_sparse[l],b_sparse[l]);
    }
};

void square_shuff(sparse_shares x_sparse){
    
    for (int j=0; j<m+1; j++) {
        for (int l=0; l<ell; l++) {
            x_sparse[j][l] = square(x_sparse[j][l]);
        }
    }
};

void sec_mult_shuff(sparse_shares a_sparse, sparse_shares b_sparse, sparse_shares c_sparse){
    
    static sparse r[m+1][m+1];
    
    sparse aux, aibj, ajbi;
    
    for (int i=0; i<m+1; i++) {
        for (int j=i+1; j<m+1; j++) {
            random_sparse(aux);
            copy_sparse(aux, r[i][j]);
            mult_shuff(a_sparse[i], b_sparse[j], aibj);
            mult_shuff(a_sparse[j], b_sparse[i], ajbi);
            xor_shuff(r[i][j], aibj, r[j][i]);
            xor_shuff(r[j][i], ajbi, r[j][i]);
        }
    }
    
    for (int i=0; i<m+1; i++) {
        mult_shuff(a_sparse[i], b_sparse[i], c_sparse[i]);
        for (int j=0; j<m+1; j++) {
            if (i==j) {
                
            } else {
                xor_shuff(c_sparse[i], r[i][j], c_sparse[i]);
            }
        }
    }
};

void sec_xor_shuff(sparse_shares a_sparse, sparse_shares b_sparse, sparse_shares c_sparse){
    
    for (int j=0; j<m+1; j++) {
        xor_shuff(a_sparse[j], b_sparse[j], c_sparse[j]);
    }
};

void sec_xtime_shuff(sparse_shares x_sparse){
    
    for (int j=0; j<m+1; j++) {
        for (int l=0; l<ell; l++) {
            x_sparse[j][l] = xtime(x_sparse[j][l]);
        }
    }
};

void refresh_masks_shuff(sparse_shares x_sparse){
    
    sparse aux;
    
    for (int i=0; i<m; i++) {
        random_sparse(aux);
        xor_shuff(x_sparse[i], aux, x_sparse[i]);
        xor_shuff(x_sparse[m], aux, x_sparse[m]);
    }
};

void sec_e254_shuff(sparse_shares x_sparse){
    
    sparse_shares z_sparse, y_sparse, w_sparse;
    
    // z = x^2
    copy_sparse_shares(x_sparse, z_sparse);
    square_shuff(z_sparse);
    // refresh z
    refresh_masks_shuff(z_sparse);
    // y = z*x
    sec_mult_shuff(z_sparse, x_sparse, y_sparse);
    // w = y^4
    copy_sparse_shares(y_sparse, w_sparse);
    square_shuff(w_sparse);
    square_shuff(w_sparse);
    // refresh w
    refresh_masks_shuff(w_sparse);
    // y = y*w
    sec_mult_shuff(y_sparse, w_sparse, y_sparse);
    // y^16
    square_shuff(y_sparse);
    square_shuff(y_sparse);
    square_shuff(y_sparse);
    square_shuff(y_sparse);
    // y = y*w
    sec_mult_shuff(y_sparse, w_sparse, y_sparse);
    // y = y*z
    sec_mult_shuff(y_sparse, z_sparse, y_sparse);
    
    copy_sparse_shares(y_sparse, x_sparse);
};

void sec_sbox_shuff(sparse_shares x_sparse){
    
    sec_e254_shuff(x_sparse);
    
    for (int j=0; j<m+1; j++) {
        for (int l=0; l<ell; l++) {
            byte aux = affine(x_sparse[j][l]);
            x_sparse[j][l] = aux;
        }
    }
    
    if (m%2==1) {
        sparse temp;
        create_sparse(temp, 0x63);
        xor_shuff(x_sparse[0], temp, x_sparse[0]);
    }
};

void sec_rsbox_shuff(sparse_shares x_sparse){
    
    if (m%2==1) {
        sparse temp;
        create_sparse(temp, 0x63);
        xor_shuff(x_sparse[0], temp, x_sparse[0]);
    }
    
    for (int j=0; j<m+1; j++) {
        for (int l=0; l<ell; l++) {
            byte aux = inv_affine(x_sparse[j][l]);
            x_sparse[j][l] = aux;
        }
    }
    
    sec_e254_shuff(x_sparse);
};
