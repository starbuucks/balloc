#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

#define NUM_FB          16
#define MIN_FB_SIZE     0x20
#define MAX_FB_SIZE     (NUM_FB << 3 + MIN_FB_SIZE - 0x8)

#define PREV_INUSE(x)   ((x)->chunk_size & 0x01)
#define NEXT_CHUNK(x)   (pChunk)((void*)(x) + (x->chunk_size & ~(size_t)0x01))
#define PREV_CHUNK(x)   (pChunk)((void*)(x) - (x->prev_size))
#define // c_ptr 2 d_ptr

typedef struct _chunk {
    size_t prev_size;       // 
    size_t chunk_size;      // PREV_INUSE
    struct _chunk * bk;
    struct _chunk * fd;
}* pChunk;

pChunk top_chunk;

pChunk fastbin[NUM_FB];   // 0x20, 0x28, ... , 0x58
pChunk sortedbin;

void insert_fastbin(struct _chunk* c_ptr, size_t size){

    int idx = (size - MIN_FB_SIZE) >> 3;

    c_ptr->fd = fastbin[idx];

    fastbin[idx] = c_ptr;

    return;
}

pChunk pop_fastbin(size_t size){

    int idx = (size - MIN_FB_SIZE) >> 3;
    pChunk target;

    if(fastbin[idx]){
        target = fastbin[idx];
        fastbin[idx] = target->fd;
        return target;
    }
    else return NULL;
}

void insert_sortedbin(pChunk *root, pChunk c_ptr, size_t size) {

    pChunk ptr = *root;

    // insert as the first node
    if(!ptr || size <= (ptr->chunk_size & ~(size_t)0x01)){
        c_ptr->fd = ptr;

        if(ptr) ptr->bk = c_ptr;
        c_ptr->bk = NULL;

        *root = c_ptr;

        return;
    }

    // insert in the order of chunk_size
    while(ptr->fd || size > ptr->fd->chunk_size){ ptr = ptr->fd; }

    c_ptr->fd = ptr->fd;
    c_ptr->bk = ptr;
    if(ptr->fd) ptr->fd->bk = c_ptr;
    ptr->fd = c_ptr;

    return;
}   

pChunk delete(pChunk c_ptr){

    if(c_ptr->bk)   c_ptr->bk->fd = c_ptr->fd;
    if(c_ptr->fd)   c_ptr->fd->bk = c_ptr->bk;

    return c_ptr;
}

void *myalloc(size_t size)
{ 
    if(!top_chunk) top_chunk = (pChunk)sbrk(2 * sizeof(size_t));

    size_t c_size;
    pChunk target;

    c_size = (c_size + (2 * sizeof(size_t) - 1) < MIN_FB_SIZE)?
    MIN_FB_SIZE : (size + (2 * sizeof(size_t) - 1)) & ~(size_t)0x07;

    // from fastbin
    if(c_size <= MAX_FB_SIZE){
        target = pop_fastbin(c_Size);
        if(target) return (void*)target + 2 * sizeof(size_t);
    }

    // from sortedbin
    pChunk ptr = *sortedbin;

    while(ptr && c_size != (ptr->chunk_size & ~(size_t)0x01) && 
        c_size + MIN_FB_SIZE > ptr->chunk_size ) { ptr = ptr->fd; }

    if(!ptr){       // ptr == NULL (search from sortedbin failed)
        // get chunk from top chunk & expand top chunk
        target = top_chunk;
        target->chunk_size = c_size || PREV_INUSE(target);
        top_chunk = (pChunk)(sbrk(c_size) + c_size - 2 * sizeof(size_t));
        top_chunk->chunk_size = 0x01;
    }
    else{           // ptr != NULL (can get chunk from sortedbin)
        target = (pChunk)delte(ptr);

        if(c_size != (target->chunk_size & ~(size_t)0x01)){
            // if split needed
            pChunk splited = (pChunk)((void*)target + c_size);
            size_t splited_size = target->chunk_size - c_size;
            splited->chunk_size = splited_size | (size_t)0x01;
            // insert splited chunk into bin
            if(splited_size <= MAX_FB_SIZE)  insert_fastbin(splited, splited_size);
            else insert_sortedbin(&sortedbin, splited, splited_size);
        }
        
        target->chunk_size = c_size || PREV_INUSE(target);

    }

    return (void*)target + 2 * sizeof(size_t);
}

void *myrealloc(void *ptr, size_t size)
{
    // void *p = NULL;
    // if (size != 0)
    // {
    //     p = sbrk(size);
    //     if (ptr)
    //         memcpy(p, ptr, size);
    //     max_size += size;
    //     debug("max: %u\n", max_size);
    // }
    // debug("realloc(%p, %u): %p\n", ptr, (unsigned int)size, p);
    // return p;

}

pChunk coalescing(struct _chunk* c_ptr){

    pChunk prev_chunk = PREV_CHUNK(c_ptr);
    pChunk next_chunk = NEXT_CHUNK(c_ptr);

    if(!PREV_INUSE(c_ptr)){     // prev chunk not in used
        next_chunk->prev_size = prev_chunk->chunk_size += c_ptr->chunk_size & ~(size_t)0x01;
        c_ptr = delete(prev_chunk);
    }
    if(!PREV_INUSE(NEXT_CHUNK(next_chunk))){     // next chunk not in used
        NEXT_CHUNK(next_chunk)->prev_size = c_ptr->chunk_size += next_chunk->chunk_size - 1;
        next_chunk = NEXT_CHUNK(delete(next_chunk));
    }

    next_chunk->prev_size = c_ptr->chunk_size & ~(size_t)0x01;
    next_chunk->chunk_size &= ~(size_t)0x01;        // PREV_INUSE -> 0

    return c_ptr;
}

void _myfree(struct _chunk* c_ptr, size_t size){

    if(size <= MAX_FB_SIZE){
        insert_fastbin(c_ptr, size);
        return;
    }

    c_ptr = coalescing(c_ptr);

    insert_sortedbin(&sortedbin, c_ptr, size);

    return;
}

void myfree(void *ptr)
{
    pChunk c_ptr = (pChunk)(ptr - 2 * sizeof(size_t));
    size_t size = c_ptr->chunk_size & ~(size_t)0x01;
    _myfree(c_ptr, size);
}
