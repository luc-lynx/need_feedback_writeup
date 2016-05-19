// clang -O3 attack.c -Wno-format -lpthread -o attack

#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>

#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <assert.h>

#include <pthread.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

volatile uint64_t iteration = 0;
volatile uint64_t total_number = 0;
volatile int phase = 0;

time_t starttime;
time_t signaltime;

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

uint8_t data[32] = { 0 };
uint8_t ptxt[32] = { 0 };

char* real_ptxt = "HTTP/1.0 200 OK\r\nServer: Simple";
size_t real_ptxt_len = 0;
uint8_t keystream[32] = { 0 };

typedef struct
{
    uint32_t l[5];
} ctx_st;

struct st_state
{
    uint16_t reg4;
    uint16_t reg5;
    
    struct st_state* next;
    
};

typedef struct st_state state_st;

void* big_chunk_start;
void* big_chunk_position;
state_st** mitm_mem;

struct thstate_st {
    uint64_t iterations;
    uint64_t total_number;
    time_t start_time;
    
    uint16_t reg1_start;
    uint16_t reg2_start;
    uint16_t reg3_start;
    
    uint16_t reg1_num;
    uint16_t reg2_num;
    uint16_t reg3_num;
};

typedef struct thstate_st st_thstate;

st_thstate** th_states;
uint32_t threads_num = 0;

uint32_t preimages[1024] = {0};
pthread_t* pthread_str;

void prepare_keystream()
{
    for(int i = 0; i < MIN(real_ptxt_len, sizeof(keystream)); i++){
        keystream[i] = data[i] ^ real_ptxt[i];
    }
}

void get_preimages(uint8_t image, uint8_t* preimages, size_t len)
{
    assert(len == 4);
    int k = 0;
    for(int i = 0; i < sizeof(sbox_tb); i++){
        if(sbox_tb[i] == image){
            preimages[k] = i;
            k++;
        }
    }
}

void get_all_preimages(uint32_t* preimages_storage)
{
    uint8_t tmp[5][4];
    
    get_preimages(       keystream[0] & 0x0f, tmp[0], 4);
    get_preimages((keystream[0] & 0xf0) >> 4, tmp[1], 4);
    get_preimages(       keystream[1] & 0x0f, tmp[2], 4);
    get_preimages((keystream[1] & 0xf0) >> 4, tmp[3], 4);
    get_preimages(       keystream[2] & 0x0f, tmp[4], 4);
    
    for(int i5 = 0; i5 < 4; i5++){
        for(int i4 = 0; i4 < 4; i4++){
            for(int i3 = 0; i3 < 4; i3++){
                for(int i2 = 0; i2 < 4; i2++){
                    for(int i1 = 0; i1 < 4; i1++){
                        preimages_storage[i1 + 4*i2 + 16*i3 + 64*i4 + 256*i5] = tmp[4][i5] | (tmp[3][i4] << 6) | (tmp[2][i3] << 12) | (tmp[1][i2] << 18) | (tmp[0][i1] << 24);
                    }
                }
            }
        }
    }
}

void* allocale_big_chunk(uint64_t chunk)
{
    return malloc(chunk);
}

state_st* get_next_st()
{
    state_st* result = big_chunk_position;
    big_chunk_position += sizeof(state_st);
    
    return result;
}

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

uint8_t next_phase2(ctx_st* c, ctx_st* poly)
{
    uint8_t result = 0;
    for(int i = 0; i < 6; i++)
    {
        uint8_t tmp = 0;
        
        for(int j = 0; j < 3; j++)
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
    
    return result;
}

uint8_t next_phase1(ctx_st* c, ctx_st* poly)
{
    uint8_t result = 0;
    for(int i = 0; i < 6; i++)
    {
        uint8_t tmp = 0;
        
        for(int j = 3; j < 5; j++)
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
    
    return result;
}

uint32_t next_phase1_full(ctx_st* c, ctx_st* poly)
{
    uint32_t offset = 0;
    for(int k = 0; k < 5; k++)
    {
        uint8_t r = next_phase1(c, poly);
        offset <<= 6;
        offset |= r;
    }
    return offset;
}

uint32_t next_phase2_full(ctx_st* c, ctx_st* poly)
{
    uint32_t offset = 0;
    for(int k = 0; k < 5; k++)
    {
        uint8_t r = next_phase2(c, poly);
        offset <<= 6;
        offset |= r;
    }
    return offset;
}

void print_total_iterations(uint64_t it)
{
    fprintf(stdout, "[>] Total iterations: %llu\n", it);
}

void print_iter_per_second(uint64_t it)
{
    uint64_t diff = signaltime - starttime;
    if(diff > 0)
    {
        float speed = ((float)it) / diff;
        fprintf(stdout, "[>] Time passed: %llu days %llu hours %llu minutes %llu seconds \n",
                diff / 60/ 60 / 24, (diff / 60 / 60) % 24, (diff / 60) % 60, diff % 60);
        fprintf(stdout, "[>] Speed: %.2f it/s \n", speed);
        fprintf(stdout, "[>] Progress: %.2f%% \n", (float)it * 100.0 / total_number);
        
        uint64_t est_seconds = (uint64_t)((total_number - it) / speed);
        
        fprintf(stdout, "[>] Estimated time: %llu days %llu hours %llu minutes %llu seconds \n",
                est_seconds / 60 / 60 / 24, (est_seconds / 60 / 60) % 24, (est_seconds / 60) % 60, est_seconds % 60);
    }
}

void th_print_total_iterations(uint64_t it, int th_num)
{
    fprintf(stdout, "[>] Thread: %d\t Total iterations: %llu\n", th_num, it);
}

void th_print_iter_per_second(uint64_t it, int th_num)
{
    uint64_t diff = signaltime - th_states[th_num]->start_time;
    
    if(diff > 0)
    {
        float speed = ((float)it) / diff;
        fprintf(stdout, "[>] Thread: %d\t Time passed: %llu days %llu hours %llu minutes %llu seconds \n", th_num,
                diff / 60/ 60 / 24, (diff / 60 / 60) % 24, (diff / 60) % 60, diff % 60);
        fprintf(stdout, "[>] Thread: %d\t Speed: %.2f it/s \n", th_num, speed);
        fprintf(stdout, "[>] Thread: %d\t Progress: %.2f%% \n", th_num, (float)it * 100.0 / th_states[th_num]->total_number);
        
        uint64_t est_seconds = (uint64_t)((th_states[th_num]->total_number - it) / speed);
        
        fprintf(stdout, "[>] Thread: %d\t Estimated time: %llu days %llu hours %llu minutes %llu seconds \n",
                th_num, est_seconds / 60 / 60 / 24, (est_seconds / 60 / 60) % 24, (est_seconds / 60) % 60, est_seconds % 60);
    }
}

void sig_handler(int signal)
{
    if(signal == SIGUSR1)
    {
        uint64_t it = iteration;
        printf("[~] Phase: %d\n", phase);
        
        if(phase == 1)
        {
            print_total_iterations(it);
        
            time(&signaltime);
            if(signaltime == -1)
            {
                fprintf(stdout, "[E] Can't get system time!\n");
                return;
            }
        
            print_iter_per_second(it);
        
            fflush(stdout);
        }
        else
        {
            time(&signaltime);
            if(signaltime == -1)
            {
                fprintf(stdout, "[E] Can't get system time!\n");
                return;
            }
            
            for(int i = 0; i < threads_num; i++)
            {
                uint64_t it = th_states[i]->iterations;
                
                th_print_total_iterations(it, i);
                th_print_iter_per_second(it, i);
            }
            
            fflush(stdout);
        }
    }
}

int check_plaintext(uint8_t* dt, uint64_t len)
{
    if(memcmp(real_ptxt, dt, MIN(real_ptxt_len, len)) == 0)
        return 1;
     
    return 0;
}

int decrypt_iteration(ctx_st* ctx, ctx_st* poly)
{
    uint8_t lptxt[32] = {0};
    
    for(int i = 0; i < sizeof(lptxt); i++)
    {
        uint8_t g1 = next(ctx, poly);
        uint8_t g2 = next(ctx, poly);
        lptxt[i] = g1 ^ (g2 << 4) ^ data[i];
    }
    
    return check_plaintext(lptxt, sizeof(lptxt));
}

void mitm_phase_1(uint16_t* reg_start_state, uint16_t* reg_num_iterations)
{
    iteration = 0;
    phase = 1;
    total_number = reg_num_iterations[0] * reg_num_iterations[1];
    
    ctx_st poly;
    ctx_st ctx;
    make_poly_ctx(&poly);
    
    time(&starttime);
    
    printf("[~] One ctx struct consumes %lu bytes\n", sizeof(ctx_st));
    
    printf("[~] Mitm memory initialization...\n");
    
    uint64_t mitm_mem_cnt = (1ull << 30);
    
    mitm_mem = (state_st**)malloc(sizeof(state_st*) * mitm_mem_cnt);
    for(uint64_t i = 0; i < mitm_mem_cnt; i++)
    {
        mitm_mem[i] = NULL;
    }
    
    printf("[~] Allocating big amount of memory...\n");
    big_chunk_start = allocale_big_chunk(total_number * sizeof(state_st));
    
    if(big_chunk_start == NULL){
        printf("[E] Allocation failed!\n");
        return;
    }
    
    big_chunk_position = big_chunk_start;
    
    printf("[~] Starting phase 1 iterations...\n");
    printf("[~] Reg4 start state: %u\n", reg_start_state[0]);
    printf("[~] Reg5 start state: %u\n", reg_start_state[1]);
    
    uint16_t reg4_end = reg_start_state[0] + reg_num_iterations[0];
    uint16_t reg5_end = reg_start_state[1] + reg_num_iterations[1];
    
    // 1024 * 8
    for(uint16_t reg4_state = reg_start_state[0]; reg4_state < reg4_end; reg4_state++){
        // 1024 * 16
        for(uint16_t reg5_state = reg_start_state[1]; reg5_state < reg5_end; reg5_state++){
            
            ctx.l[3] =  reg4_state;
            ctx.l[4] =  reg5_state;
            
            uint32_t offset = next_phase1_full(&ctx, &poly);
            
            if(mitm_mem[offset] == NULL)
            {
                state_st* st = get_next_st();
                st->reg4 = reg4_state;
                st->reg5 = reg5_state;
                
                st->next = NULL;
                
                mitm_mem[offset] = st;
            }
            else
            {
                state_st* nxt = mitm_mem[offset];
                while(nxt->next != NULL)
                    nxt = nxt->next;
                    
                nxt->next = get_next_st();
                nxt->next->reg4 = reg4_state;
                nxt->next->reg5 = reg5_state;
                nxt->next->next = NULL;
            }
                
            iteration++;
        }
    }
    
    printf("[~] Phase 1 has been finished...\n");
    
    uint64_t longest_chain = 0;
    for(uint64_t i = 0; i < total_number; i++){
        if(mitm_mem[i] != NULL){
            uint64_t len = 1;
            state_st* t = mitm_mem[i];
            while (t->next != NULL) {
                t = t->next;
                len++;
            }
            if(len > longest_chain)
                longest_chain = len;
        }
    }
    
    printf("[~] The longest chain contains %llu elements\n", longest_chain);
}

void mitm_phase_2(uint32_t* preimages, uint32_t preimages_len, int th_num)
{
    //phase = 2;
    th_states[th_num]->iterations = 0;
    th_states[th_num]->total_number = th_states[th_num]->reg1_num * th_states[th_num]->reg2_num * th_states[th_num]->reg3_num;
    time(&(th_states[th_num]->start_time));
    
    char filename[32] = { 0 };
    sprintf(filename, "log_ctx_%d.txt", th_num);
    
    ctx_st ctx;
    ctx_st poly;
    ctx_st full_ctx;
    
    make_poly_ctx(&poly);
    
    uint16_t reg1_end =  th_states[th_num]->reg1_start + th_states[th_num]->reg1_num;
    uint16_t reg2_end =  th_states[th_num]->reg2_start + th_states[th_num]->reg2_num;
    uint16_t reg3_end =  th_states[th_num]->reg3_start + th_states[th_num]->reg3_num;
    
    // 1024
    for(uint16_t reg1_state = th_states[th_num]->reg1_start; reg1_state < reg1_end; reg1_state++){
        // 1024 * 2
        for(uint16_t reg2_state = th_states[th_num]->reg2_start; reg2_state < reg2_end; reg2_state++){
            // 1024 * 4
            for(uint16_t reg3_state = th_states[th_num]->reg3_start; reg3_state < reg3_end; reg3_state++){
            
                ctx.l[0] = reg1_state;
                ctx.l[1] = reg2_state;
                ctx.l[2] = reg3_state;
                
                uint32_t offset = next_phase2_full(&ctx, &poly);
            
                for(int i = 0; i < preimages_len; i++){
                    
                    uint32_t actual_offset = offset ^ preimages[i];
                
                    state_st* st_ctx = mitm_mem[actual_offset];
                    if(st_ctx != NULL){
                    
                        do
                        {
                            full_ctx.l[0] = reg1_state;
                            full_ctx.l[1] = reg2_state;
                            full_ctx.l[2] = reg3_state;
                            full_ctx.l[3] = st_ctx->reg4;
                            full_ctx.l[4] = st_ctx->reg5;
                        
                            int r = decrypt_iteration(&full_ctx, &poly);
                        
                            if(r)
                            {
                                printf("%d - %d:%hu:%hu:%hu:%hu:%hu \n", th_num, r, reg1_state, reg2_state, reg3_state, st_ctx->reg4, st_ctx->reg5);
                                FILE* fl = fopen(filename, "a");
                            
                                if(fl != NULL)
                                {
                                    fprintf(fl, "%d:%hu:%hu:%hu:%hu:%hu \n", r, reg1_state, reg2_state, reg3_state, st_ctx->reg4, st_ctx->reg5);
                                    fclose(fl);
                                    fl = NULL;
                                }
                                else
                                {
                                    printf("[E] Can't open file %s \n", filename);
                                }
                            }
                        
                            st_ctx = st_ctx->next;
                        }
                        while(st_ctx != NULL);
                    
                    }
                }
            
                th_states[th_num]->iterations++;
            }
        }
    }
    
}

void* thread_launcher(void *num){
    int n = *((int *) num);
    free(num);
    
    mitm_phase_2(preimages, 1024, n);
    
    return 0;
}

int main(int argc, char *argv[])
{
    real_ptxt_len = strlen(real_ptxt);
    
    if(argc < 2)
    {
        printf("[E] You need to specify a filename with ciphertext\n");
        return 1;
    }
    
    FILE* f = fopen(argv[1], "rb");
    if(!f)
    {
        printf("[E] Can't read file %s", argv[1]);
        return 1;
    }
    
    if(fread(data, 1, sizeof(data), f) != sizeof(data))
    {
        printf("[E] Can't read enough data from file %s", argv[1]);
        fclose(f);
        return 1;
    }
    
    fclose(f);
    
    prepare_keystream();
    
    get_all_preimages(preimages);
    
    time(&starttime);
    
    if(starttime == -1){
        fprintf(stderr, "[E] Can't get start time!\n");
        return -1;
    }
    
    signal(SIGUSR1, sig_handler);
        
    uint16_t reg_start_states2[] = { 1, 1, 1 };
    uint16_t reg_num_iterations2[] = { 1024 - 1, 1024 * 2 - 1, 1024 * 4 -1 };
        
    uint16_t reg_start_states1[] = { 1, 1 };
    uint16_t reg_num_iterations1[] = { 1024 * 8 - 1, 1024 * 16 - 1 };
   
    mitm_phase_1(reg_start_states1, reg_num_iterations1);
        
    printf("[>] Preparing threads... \n");
    
    /* hardcoded number of threads to create */
    threads_num = 32;
    
    th_states = (st_thstate**)malloc(threads_num * sizeof(st_thstate*));
    for(int i = 0; i < threads_num; i++)
        th_states[i] = (st_thstate*)malloc(sizeof(st_thstate));
        
    uint16_t interval = reg_num_iterations2[0] / (uint16_t)threads_num;
        
    for(int i = 0; i < threads_num; i++){
        th_states[i]->reg2_start = reg_start_states2[1];
        th_states[i]->reg3_start = reg_start_states2[2];
        th_states[i]->reg2_num = reg_num_iterations2[1];
        th_states[i]->reg3_num = reg_num_iterations2[2];
            
        th_states[i]->reg1_start = reg_start_states2[0] + interval * i;
        th_states[i]->reg1_num = interval;
            
        if(i == threads_num - 1)
        {
                th_states[i]->reg1_num = reg_num_iterations2[0] - interval * (threads_num - 1);
        }
    }
        
    pthread_str = (pthread_t*)malloc(threads_num * sizeof(pthread_t));
        
    printf("[>] Starting threads...\n");
    phase = 2;
        
    for(int i = 0; i < threads_num; i++)
    {
        int *arg = (int*)malloc(sizeof(int*));
        *arg = i;
        pthread_create(&(pthread_str[i]), NULL, thread_launcher, arg);
    }
        
    for(int i = 0; i < threads_num; i++)
        pthread_join(pthread_str[i], NULL);
    
    return 0;
}
