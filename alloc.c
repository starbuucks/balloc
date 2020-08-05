#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

#define NUM_FB          16
#define MIN_FB_SIZE     0x20
#define MAX_FB_SIZE     ((NUM_FB << 3) + MIN_FB_SIZE - 0x8)

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

void *myalloc(size_t size);
void *myrealloc(void *ptr, size_t size);
void myfree(void *ptr);
pChunk delete(pChunk* root, pChunk c_ptr);
void _myfree(struct _chunk* c_ptr, size_t size);

pChunk top_chunk;

pChunk fastbin[NUM_FB];   // 0x20, 0x28, ... , 0x58
pChunk sortedbin;

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

    NEXT_CHUNK(c_ptr)->chunk_size |= 0x2;   // PREV_INUSE -> 1

    c_ptr->fd = fastbin[idx];

    fastbin[idx] = c_ptr;
    debug_fastbin(idx);

    return;
}

pChunk pop_fastbin(size_t size){

    int idx = (size - MIN_FB_SIZE) >> 3;
    pChunk target;

    if(fastbin[idx]){
        target = fastbin[idx];
        fastbin[idx] = target->fd;
        debug_fastbin(idx);
        return target;
    }
    else{
        return NULL;
    }
}

void insert_sortedbin(pChunk *root, pChunk c_ptr, size_t size) {

    pChunk ptr = *root;

    debug("insert_sortedbin, ptr: %p\n", ptr);
    // insert as the first node
    if(!ptr || size <= CHUNK_SIZE(ptr)){
        debug("here\n");
        c_ptr->fd = ptr;

        if(ptr) ptr->bk = c_ptr;
        c_ptr->bk = NULL;

        *root = c_ptr;
        debug_bin("sortedbin1", &sortedbin);
        return;
    }

    // insert in the order of chunk_size
    while(ptr->fd && size > ptr->fd->chunk_size){ ptr = ptr->fd; }

    if(! ptr->fd){
        ptr->fd = c_ptr;
        c_ptr->bk = ptr;
        c_ptr = NULL;
    }/////////////////////problem///////////////////////
    else{
        c_ptr->fd = ptr->fd;
        c_ptr->bk = ptr;
        if(ptr->fd) ptr->fd->bk = c_ptr;
        ptr->fd = c_ptr;
    }

    debug_bin("sortedbin2", &sortedbin);
    return;
}   

pChunk delete(pChunk* root, pChunk c_ptr){

    debug("delete(%p)\n", c_ptr);
    if(c_ptr->bk) {
        debug("c_ptr->bk: %p\n",c_ptr->bk);
        c_ptr->bk->fd = c_ptr->fd;
    }
    else{
        debug("root: %p %p\n", root, *root);
        *root = c_ptr->fd;
    }
    debug_bin("sortedbin", &sortedbin);
    debug("c_ptr: %p %p %p\n", c_ptr, c_ptr->bk, c_ptr->fd);
    if(c_ptr->fd)   c_ptr->fd->bk = c_ptr->bk;

    NEXT_CHUNK(c_ptr)->chunk_size |= 0x1;
    return c_ptr;
}

void *myalloc(size_t size)
{ 
    debug("\nalloc(%x)\n", size);
    //debug("alloc(%u) started\n", (unsigned int)size);
    if(!top_chunk){
        top_chunk = (pChunk)sbrk(2 * sizeof(size_t));
        top_chunk->chunk_size |= 0x1;
        debug("first top_chunk: %p\n", top_chunk);
    }

    if(!size)   return NULL;

    size_t c_size;
    pChunk target;
    void* p;

    c_size = (size + (2 * sizeof(size_t) - 1) < MIN_FB_SIZE)?
    MIN_FB_SIZE : (size + (2 * sizeof(size_t) - 1)) & ~(size_t)0x07;
    debug("c_size: %llx\n", c_size);

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

    // from sortedbin
    pChunk ptr = sortedbin;

    while(ptr && c_size != CHUNK_SIZE(ptr) && 
        c_size + MIN_FB_SIZE > ptr->chunk_size ) { ptr = ptr->fd; }

    if(!ptr){       // ptr == NULL (search from sortedbin failed)
        // get chunk from top chunk & expand top chunk
        debug("get from topchunk\n");
        target = top_chunk;
        target->chunk_size = c_size | PREV_INUSE(target);
        top_chunk = (pChunk)(sbrk(c_size) + c_size - 2 * sizeof(size_t));
        top_chunk->chunk_size = 0x01;
    }
    else{           // ptr != NULL (can get chunk from sortedbin)
        target = (pChunk)delete(&sortedbin, ptr);

        if(c_size != CHUNK_SIZE(target)){
            // if split needed
            pChunk splited = (pChunk)((void*)target + c_size);
            debug("target: %p, c_size: %llx\n", target, c_size);
            size_t splited_size = CHUNK_SIZE(target) - c_size;
            splited->chunk_size = splited_size | (size_t)0x01;
 
            // insert splited chunk into bin
            debug("_myfree(%p, %llx)\n", splited, splited_size);
            _myfree(splited, splited_size);
            //if(splited_size <= MAX_FB_SIZE)  insert_fastbin(splited, splited_size);
            //else insert_sortedbin(&sortedbin, splited, splited_size);
        }
        
        target->chunk_size = c_size | PREV_INUSE(target);

    }

    NEXT_CHUNK(target)->chunk_size |= 0x01;
    p = PTR_C2D(target);
    debug("alloc(%x): %p\n", (unsigned int)size, p);
    return p;
}

void *myrealloc(void *ptr, size_t size)
{
    debug("\nrealloc(%p, %x)", ptr, size);
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

pChunk coalescing(struct _chunk* c_ptr){

    pChunk prev_chunk;
    pChunk next_chunk = NEXT_CHUNK(c_ptr);

    if(!PREV_INUSE(c_ptr)){     // prev chunk not in used
        debug("coal1\n");
        prev_chunk = PREV_CHUNK(c_ptr);
        next_chunk->prev_size = prev_chunk->chunk_size += CHUNK_SIZE(c_ptr);
        debug("prev_chunk: %p\n", prev_chunk);
        c_ptr = delete(&sortedbin, prev_chunk);
    }
    if(next_chunk != top_chunk && !PREV_INUSE(next_chunk)){     // next chunk not in used
        debug("coal2\n");
        NEXT_CHUNK(next_chunk)->prev_size = c_ptr->chunk_size += CHUNK_SIZE(next_chunk);
        next_chunk = NEXT_CHUNK(delete(&sortedbin, next_chunk));
    }

    next_chunk->prev_size = CHUNK_SIZE(c_ptr);
    next_chunk->chunk_size &= ~(size_t)0x01;        // PREV_INUSE -> 0

    return c_ptr;
}

void _myfree(struct _chunk* c_ptr, size_t size){

    if(size <= MAX_FB_SIZE){
        insert_fastbin(c_ptr, size);
        return;
    }

    // if already freed, nothing happens
    if(!PREV_INUSE(NEXT_CHUNK(c_ptr))){
        debug("already freed\n");
        return;
    }

    c_ptr = coalescing(c_ptr);

    insert_sortedbin(&sortedbin, c_ptr, size);

    //debug_bin("sortedbin", &sortedbin);

    return;
}

void myfree(void *ptr)
{
    debug("\nfree(%p)\n", ptr);

    if(!ptr)    return NULL;

    pChunk c_ptr = PTR_D2C(ptr);
    size_t size = CHUNK_SIZE(c_ptr);
    _myfree(c_ptr, size);

    return;
}
