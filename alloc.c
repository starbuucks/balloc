#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

#define DEBUG_BIN       0

#define SORTED
#define FASTBIN_LIMIT   300
#define SEGREGATED_BIN

#define NUM_FB          16
#define MIN_FB_SIZE     0x20
#define MAX_FB_SIZE     ((NUM_FB << 3) + MIN_FB_SIZE - 0x8)

#define NUM_SB          12
#define STEP_SB         1
#define MAX_SB_SIZE     ((0x01 << (NUM_SB * STEP_SB)) - 1)

#define PREV_INUSE(x)   ((x)->chunk_size & 0x01)
#define NEXT_CHUNK(x)   ((pChunk)((void*)(x) + (x->chunk_size & ~(size_t)0x01)))
#define PREV_CHUNK(x)   ((pChunk)((void*)(x) - (x->prev_size)))
#define CHUNK_SIZE(x)   ((x)->chunk_size & ~(size_t)0x01)
#define PTR_C2D(x)      ((void*)x + 2 * sizeof(size_t))
#define PTR_D2C(x)      (pChunk)(x - 2 * sizeof(size_t))

typedef struct _chunk {
    size_t prev_size;       // 
    size_t chunk_size;      // PREV_INUSE
    struct _chunk * bk;
    struct _chunk * fd;
}* pChunk;

void insert_fastbin(struct _chunk* c_ptr, size_t size);
void insert_sortedbin(pChunk *root, pChunk c_ptr, size_t size);
#ifdef SEGREGATED_BIN
void insert_segregatedbin(pChunk c_ptr, size_t size);
pChunk pop_segregatedbin(size_t size);
#endif
pChunk pop_from_bin(pChunk* root, size_t size);
pChunk delete(pChunk* root, pChunk c_ptr);
pChunk coalescing(pChunk* root, struct _chunk* c_ptr);
pChunk _myalloc(pChunk ptr, pChunk* root, size_t c_size);
void *myalloc(size_t size);
void *myrealloc(void *ptr, size_t size);
void __myfree(struct _chunk* c_ptr, size_t size);
void _myfree(struct _chunk* c_ptr, size_t size);
void myfree(void *ptr);

pChunk top_chunk;

pChunk fastbin[NUM_FB];   // 0x20, 0x28, ... , 0x58

#ifdef SEGREGATED_BIN
pChunk segregatedbin[NUM_SB];   // 0x01, 0x02, 0x04, ... , 0x1000
#endif

pChunk sortedbin;

#ifdef FASTBIN_LIMIT

int fastbin_count[NUM_FB];

#endif

void debug_chunk(char* str, pChunk c_ptr){
    debug("%s: %p", str, c_ptr);
    if(c_ptr == top_chunk){
        debug(" : %llx %llx\n", c_ptr->prev_size, c_ptr->chunk_size);
        debug("sbrk(0): %p\n", sbrk(0));
    }
    else if(c_ptr) debug(" : %llx %llx %p %p\n", c_ptr->prev_size, c_ptr->chunk_size, c_ptr->bk, c_ptr->fd);

}

void debug_fastbin(int idx){
    int i;
    if(idx == -1){
        for(i=0; i<NUM_FB; i++){
            debug("fastbin[%02x] ", i);
            pChunk c_ptr = fastbin[i];
            while(1){
                debug("-> %p ", c_ptr);
                if(!c_ptr) break;
                c_ptr = c_ptr->fd;
            }
            debug("\n");
        }
    }
    else{
        debug("fastbin[%02x] ", idx);
        pChunk c_ptr = fastbin[idx];
        while(1){
            debug("-> %p ", c_ptr);
            if(!c_ptr) break;
            c_ptr = c_ptr->fd;
        }
        debug("\n");
    }
}

void debug_bin(char* str, pChunk* root){
    #if DEBUG_BIN == 0
    return;
    #endif
    debug("==== %s debug ====\n", str);
    debug("head[%p]\n", root);
    pChunk c_ptr = *root;
    while(c_ptr){
        debug("-> %p : %llx %llx %p %p\n", c_ptr, c_ptr->prev_size, c_ptr->chunk_size, c_ptr->bk, c_ptr->fd);
        c_ptr = c_ptr->fd;
    }
    debug("-> %p\n", c_ptr);
    return;
}

void insert_fastbin(struct _chunk* c_ptr, size_t size){

    int idx = (size - MIN_FB_SIZE) >> 3;

    if(fastbin[idx] == c_ptr)   return;     // double free corruption

    #ifdef FASTBIN_LIMIT

    if(fastbin_count[idx] >= FASTBIN_LIMIT){

        __myfree(c_ptr, size);

        return;
    }

    fastbin_count[idx] += 1;

    #endif

    //NEXT_CHUNK(c_ptr)->chunk_size |= 0x1;   // PREV_INUSE -> 1

    c_ptr->fd = fastbin[idx];

    fastbin[idx] = c_ptr;

    //debug_fastbin(idx);

    return;
}

pChunk pop_fastbin(size_t size){

    int idx = (size - MIN_FB_SIZE) >> 3;
    pChunk target;

    if(fastbin[idx]){

    #ifdef FASTBIN_LIMIT

        fastbin_count[idx] -= 1;
    #endif

        target = fastbin[idx];
        fastbin[idx] = target->fd;
        //debug_fastbin(idx);
        return target;
    }
    else{
        return NULL;
    }
}

#ifdef SEGREGATED_BIN

void insert_segregatedbin(pChunk c_ptr, size_t size){

    int idx = 0;
    
    while(size >> idx) idx++;

    insert_sortedbin(&segregatedbin[idx], c_ptr, size);

    return;
}

pChunk pop_segregatedbin(size_t size){

    int idx = 0;
    while(size >> idx) idx++;
    idx--;

    debug_bin("seg", &(segregatedbin[idx]));
    pChunk ptr = pop_from_bin(&(segregatedbin[idx]), size);
    if(ptr){
        ptr = _myalloc(ptr, &(segregatedbin[idx]), size);
    }

    return ptr;
}

#endif

void insert_sortedbin(pChunk *root, pChunk c_ptr, size_t size) {

    pChunk ptr = *root;

    // debug("inserted_sortedbin(%p, %p, %llx)\n", *root, c_ptr, size);
    // debug("insert_sortedbin, ptr: %p\n", ptr);
    // debug_chunk("ptr: ", ptr);
    // insert as the first node

    #ifdef SORTED

    // debug("top_chunk: %p\n", top_chunk);
    if(!ptr || size <= CHUNK_SIZE(ptr)){
        c_ptr->fd = ptr;

        if(ptr) ptr->bk = c_ptr;
        c_ptr->bk = NULL;

        *root = c_ptr;
        //debug_bin("sortedbin1", &sortedbin);
        return;
    }

    // insert in the order of chunk_size
    //debug_bin("sortedbin21", &sortedbin);
    while(ptr->fd && size > ptr->fd->chunk_size){ ptr = ptr->fd; }

    pChunk next = ptr->fd;
    ptr->fd = c_ptr;
    c_ptr->bk = ptr;
    if(next)    next->bk = c_ptr;
    c_ptr->fd = next;

    #else

    c_ptr->fd = ptr;
    if(ptr) ptr->bk = c_ptr;
    c_ptr->bk = NULL;
    *root = c_ptr;

    #endif

    return;
}   

pChunk delete(pChunk* root, pChunk c_ptr){

    debug("delete(%p)\n", c_ptr);
    // debug_chunk("top", top_chunk);
    if(c_ptr->bk) {
        // debug("c_ptr->bk: %p\n",c_ptr->bk);
        c_ptr->bk->fd = c_ptr->fd;
    }
    else{
        // debug("root: %p %p\n", root, *root);
        *root = c_ptr->fd;
    }
    //debug_bin("sortedbin", &sortedbin);
    // debug("c_ptr: %p %p %p\n", c_ptr, c_ptr->bk, c_ptr->fd);
    if(c_ptr->fd)   c_ptr->fd->bk = c_ptr->bk;

    NEXT_CHUNK(c_ptr)->chunk_size |= 0x1;
    return c_ptr;
}

pChunk pop_from_bin(pChunk* root, size_t size){
    pChunk ptr = *root;

    while(ptr && size != CHUNK_SIZE(ptr) && 
        size + MIN_FB_SIZE > ptr->chunk_size ) { ptr = ptr->fd; }

    return ptr;
}

pChunk _myalloc(pChunk ptr, pChunk* root, size_t c_size){

    pChunk target = (pChunk)delete(root, ptr);

    if(c_size != CHUNK_SIZE(target)){
        // if split needed
        pChunk splited = (pChunk)((void*)target + c_size);
        //debug("target: %p, c_size: %llx\n", target, c_size);
        size_t splited_size = CHUNK_SIZE(target) - c_size;
        splited->chunk_size = splited_size | (size_t)0x01;
        // debug_chunk("splited", splited);
        // insert splited chunk into bin
        //debug("_myfree(%p, %llx)\n", splited, splited_size);
        _myfree(splited, splited_size);
    }
    
    target->chunk_size = c_size | PREV_INUSE(target);
    return target;
}

void *myalloc(size_t size)
{ 
    //debug_chunk("start of alloc", sortedbin);
    debug("\nalloc(%x)\n", size);
    //debug("alloc(%u) started\n", (unsigned int)size);
    if(!top_chunk){
        top_chunk = (pChunk)sbrk(2 * sizeof(size_t));
        top_chunk->chunk_size = (2 * sizeof(size_t)) | 0x1;
        debug_chunk("first top_chunk", top_chunk);
    }

    if(!size)   return NULL;

    size_t c_size;
    pChunk target;
    void* p;

    c_size = (size + (2 * sizeof(size_t) - 1) < MIN_FB_SIZE)?
    MIN_FB_SIZE : (size + (2 * sizeof(size_t) - 1)) & ~(size_t)0x07;
    //debug("c_size: %llx\n", c_size);

    // from fastbin
    if(c_size <= MAX_FB_SIZE){
        target = pop_fastbin(c_size);
        if(target){
            NEXT_CHUNK(target)->chunk_size |= 0x01;
            p = PTR_C2D(target);
            debug("alloc(%x): %p\n", (unsigned int)size, p);
            return p;
        }
    }
    #ifdef SEGREGATED_BIN
    // from segregatedbin
    if(c_size <= MAX_SB_SIZE){
        target = pop_segregatedbin(c_size);
        if(target){
            target->chunk_size = c_size | PREV_INUSE(target);
            NEXT_CHUNK(target)->chunk_size |= 0x01;
            p = PTR_C2D(target);
            debug("alloc(%x): %p\n", (unsigned int)size, p);
            return p;            
        }
    }
    #endif
    // from sortedbin

    pChunk ptr = pop_from_bin(&sortedbin, c_size);
    debug("ptr: %p\n", ptr);

    if(!ptr){       // ptr == NULL (search from sortedbin failed)
        // get chunk from top chunk
        debug("get from topchunk\n");
        debug_chunk("top chunk before expand", top_chunk);
        size_t needed = c_size + 2 * sizeof(size_t);

        if(CHUNK_SIZE(top_chunk) < needed){
            //expand top chunk
            size_t expand = needed - CHUNK_SIZE(top_chunk);
            sbrk(expand);
            top_chunk->chunk_size += expand;
        }
        target = top_chunk;
        top_chunk = (pChunk)((void*)target + c_size);
        top_chunk->chunk_size = (target->chunk_size - c_size) | 0x01;
        target->chunk_size = c_size | PREV_INUSE(target);
        debug_chunk("target", target);
        debug_chunk("top chunk after expand", top_chunk);
    }
    else{           // ptr != NULL (can get chunk from sortedbin)
        target = _myalloc(ptr, &sortedbin, c_size);
    }

    NEXT_CHUNK(target)->chunk_size |= 0x01;
    p = PTR_C2D(target);
    debug("alloc(%x): %p\n", (unsigned int)size, p);
    return p;
}

void *myrealloc(void *ptr, size_t size)
{
    // debug("\nrealloc(%p, %x)", ptr, size);
    if(!ptr)    return myalloc(size);

    pChunk c_ptr = PTR_D2C(ptr);
    size_t original_size = CHUNK_SIZE(c_ptr);

    size_t target_size = (size + (2 * sizeof(size_t) - 1) < MIN_FB_SIZE)?
    MIN_FB_SIZE : (size + (2 * sizeof(size_t) - 1)) & ~(size_t)0x07;

    if (original_size >= target_size){
        debug("realloc(%p, %x): %p\n", ptr, (unsigned int)size, ptr);
        return ptr;
    }

    myfree(ptr);
    void* p = myalloc(size);

    debug("realloc(%p, %x): %p\n", ptr, (unsigned int)size, p);
    return p;
}

pChunk coalescing(pChunk* root, struct _chunk* c_ptr){

    pChunk prev_chunk;
    pChunk next_chunk = NEXT_CHUNK(c_ptr);

    if(!PREV_INUSE(c_ptr)){     // prev chunk not in used
        // debug("coal1\n");
        prev_chunk = PREV_CHUNK(c_ptr);
        prev_chunk->chunk_size += CHUNK_SIZE(c_ptr);
        // debug("prev_chunk: %p\n", prev_chunk);
        c_ptr = delete(root, prev_chunk);
    }
    if(next_chunk == top_chunk){
        //coalesce with top chunk, no bin insert
        c_ptr->chunk_size += CHUNK_SIZE(top_chunk);
        top_chunk = c_ptr;
        debug_chunk("coalesce", top_chunk);
        //debug_bin("sortedbin", &sortedbin);

        return c_ptr;
    }
    else if(!PREV_INUSE(next_chunk)){     // next chunk not in used
        // debug("coal2\n");
        c_ptr->chunk_size += CHUNK_SIZE(next_chunk);
        next_chunk = NEXT_CHUNK(delete(root, next_chunk));
    }

    next_chunk->prev_size = CHUNK_SIZE(c_ptr);
    // next_chunk->chunk_size &= ~(size_t)0x01;        // PREV_INUSE -> 0

    return c_ptr;
}

void __myfree(struct _chunk* c_ptr, size_t size){
    // coalesce and insert to sortedbin

    // if already freed, nothing happens
    if(!PREV_INUSE(NEXT_CHUNK(c_ptr))){
        debug("already freed\n");
        return;
    }

    pChunk* root = &sortedbin;

#ifdef SEGREGATED_BIN
    if(size <= MAX_SB_SIZE){
        int idx = 0;
        while(size >> idx) idx++;
        root = &segregatedbin[--idx];
    }
#endif

    c_ptr = coalescing(root, c_ptr);
    size = CHUNK_SIZE(c_ptr);

#ifdef SEGREGATED_BIN
    if(size <= MAX_SB_SIZE){
        int idx = 0;
        while(size >> idx) idx++;
        root = &segregatedbin[--idx];
    }
    else root = &sortedbin;
#endif

    if(c_ptr != top_chunk){
        insert_sortedbin(root, c_ptr, size);
    }
    //debug_bin("sortedbin", &sortedbin);

    return;
}

void _myfree(struct _chunk* c_ptr, size_t size){

    if(size <= MAX_FB_SIZE){

        insert_fastbin(c_ptr, size);
        return;
    }

    __myfree(c_ptr, size);

    return;
}

void myfree(void *ptr)
{
    debug("\nfree(%p)\n", ptr);

    if(!ptr)    return;

    pChunk c_ptr = PTR_D2C(ptr);
    size_t size = CHUNK_SIZE(c_ptr);
    if(((size_t)ptr & 0x0fff) == 0xc68){
        debug_chunk("top_chunk ", top_chunk);
        debug("size, %llx\n", size);
    }
    _myfree(c_ptr, size);

    return;
}
