//
//  robust_prg.c
//  masked+prg_aes
//
//  Created by Lorenzo SPIGNOLI on 25/05/2023.
//

#include "robust_prg.h"

void locality_refreshing(shares input){
    
    // define auxiliary variable
    byte s;
    
    // compute the refreshing of the mask to minimize the randomness locality
    for (int i=0; i<n; i++) {
        input[n] = input[n] ^ input[i];
        s = rand()%256;
        input[i] = s;
        input[n] = input[n] ^ s;
    }
    
}
