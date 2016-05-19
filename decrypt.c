// clang decrypt.c -o decrypt

#include <inttypes.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t sbox_tb[] =
{
    7,  6,  5, 10,  8,  1, 12, 13,
    6, 11, 15, 11,  1,  6,  2,  7,
    0,  2,  8, 12,  3,  2, 15,  0,
    1, 15,  9,  7, 13,  6,  7,  5,
    9, 11,  3,  3, 12, 12,  5, 10,
    14, 14,  1,  4, 13,  3,  5, 10,
    4,  9, 11, 15, 10, 14,  8, 13,
    14,  2,  4,  0,  0,  4,  9,  8,
};

uint8_t lfsr_coeffs1[] = { 0x0 ,0x1 ,0x2 ,0x3 ,0x6 ,0x9 ,0xa };
uint8_t lfsr_coeffs2[] = { 0x0 ,0x1 ,0x2 ,0x3 ,0x6 ,0x7 ,0x9 ,0xa ,0xb };
uint8_t lfsr_coeffs3[] = { 0x0 ,0x2 ,0x7 ,0x8 ,0xa ,0xb ,0xc };
uint8_t lfsr_coeffs4[] = { 0x0 ,0x1 ,0x3 ,0x7 ,0xa ,0xb ,0xd };
uint8_t lfsr_coeffs5[] = { 0x0 ,0x3 ,0x4 ,0xa ,0xb ,0xc ,0xe };

typedef struct
{
    uint32_t l[5];
} ctx_st;

void make_poly_ctx(ctx_st* c)
{
    c->l[0] = 0;
    for(int i = 0; i < sizeof(lfsr_coeffs1); i++)
        c->l[0] |= 1 << lfsr_coeffs1[i];
    
    c->l[1] = 0;
    for(int i = 0; i < sizeof(lfsr_coeffs2); i++)
        c->l[1] |= 1 << lfsr_coeffs2[i];
    
    c->l[2] = 0;
    for(int i = 0; i < sizeof(lfsr_coeffs3); i++)
        c->l[2] |= 1 << lfsr_coeffs3[i];
    
    c->l[3] = 0;
    for(int i = 0; i < sizeof(lfsr_coeffs4); i++)
        c->l[3] |= 1 << lfsr_coeffs4[i];
    
    c->l[4] = 0;
    for(int i = 0; i < sizeof(lfsr_coeffs5); i++)
        c->l[4] |= 1 << lfsr_coeffs5[i];
}

uint8_t next(ctx_st* c, ctx_st* poly)
{
    uint8_t result = 0;
    for(int i = 0; i < 6; i++)
    {
        uint8_t tmp = 0;
        
        for(int j = 0; j < 5; j++)
        {
            uint8_t r = 0;
            
            r = c->l[j] >> (0x0a + j - 1);
            c->l[j] <<= 1;
            
            if(r == 1)
                c->l[j] ^= poly->l[j];
            
            tmp ^= r;
        }
        
        result |= tmp << i;
    }
    
    return  sbox_tb[result];
}


int decrypt_file(char* filename_in, char* filename_out, ctx_st* ctx, ctx_st* poly)
{
    uint8_t buffer[1024];
    uint8_t g1, g2;
    size_t read;
    
    printf("[>] Processing file: %s \n", filename_in);
    
    FILE* file_in = fopen(filename_in, "rb");
    if(file_in == NULL){
        printf("[E] Can't open file %s \n", filename_in);
        return 0;
    }
    
    FILE* file_out = fopen(filename_out, "wb");
    if(file_out == NULL){
        printf("[E] Can't open file %s \n", filename_out);
        fclose(file_in);
        return 0;
    }
    
    while(1)
    {
        read = fread(buffer, 1, sizeof(buffer), file_in);
        if(read > 0)
        {
            for(size_t i = 0; i < read; i++){
                g1 = next(ctx, poly);
                g2 = next(ctx, poly);
                
                buffer[i] = (g2 << 4) ^ g1 ^ buffer[i];
            }
            
            fwrite(buffer, 1, read, file_out);
        }
        else
            break;
    }
    
    fclose(file_in);
    fclose(file_out);
    
    return 1;
}

int main(int argc, char *argv[])
{
    char* file_template1 = "./rec/part0%i_raw";
    char* file_template2 = "./rec/part%i_raw";
    
    char infilename[2048];
    char outfilename[2048];
    
    memset(infilename, 0, sizeof(infilename));
    memset(outfilename, 0, sizeof(outfilename));
    
    ctx_st ctx;
    ctx_st poly;
    
    make_poly_ctx(&poly);
    // 1:309:2008:510:7942:5369
    ctx.l[0] = 309;
    ctx.l[1] = 2008;
    ctx.l[2] = 510;
    ctx.l[3] = 7942;
    ctx.l[4] = 5369;
    
    for(int i = 0; i < 10; i++){
        sprintf(infilename, file_template1, i);
        sprintf(outfilename, "%s_d", infilename);
        
        decrypt_file(infilename, outfilename, &ctx, &poly);
    }
    
    for (int i = 10; i <= 19; i++) {
        sprintf(infilename, file_template2, i);
        sprintf(outfilename, "%s_d", infilename);
        
        decrypt_file(infilename, outfilename, &ctx, &poly);
    }
    
    return 0;
}
