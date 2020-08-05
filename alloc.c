#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

unsigned int max_size;

#define NUM_FB          16
#define MIN_FB_SIZE     0x20
#define MAX_FB_SIZE     (NUM_FB << 3 + MIN_FB_SIZE - 0x8)

#define PREV_INUSE(x)        ((pChunk)(x)->chunk_size & 0x01)
#define NEXT_CHUNK(x)   (pChunk)((void*)(x) + (x->chunk_size & ~(size_t)0x01))
#define PREV_CHUNK(x)   (pChunk)((void*)(x) - (x->prev_size))

typedef struct _chunk {
    size_t prev_size;       // 
    size_t chunk_size;      // PREV_INUSE
    struct _chunk * bk;
    struct _chunk * fd;
}* pChunk;

pChunk top_chunk;

void* fastbin[NUM_FB];   // 0x20, 0x28, ... , 0x58
void* sortedbin;

void insert(pChunk *root, pChunk c_ptr, size_t size) {

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

void delete(pChunk root, pChunk c_ptr, size_t size){

}

void *myalloc(size_t size)
{
    // void *p = sbrk(size);
    // debug("alloc(%u): %p\n", (unsigned int)size, p);
    // max_size += size;
    // debug("max: %u\n", max_size);
    // return p;   
    size_t c_size = size + 
}
/
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

void _myfree(struct _chunk* c_ptr){

    size_t size = c_ptr->chunk_size;

    if(size <= MAX_FB_SIZE) {   // fast bin

        int idx = (size - 0x20) >> 3;

        c_ptr->fd = fastbin[idx];

        fastbin[idx] = c_ptr;

        return;
    }

    // coalescing
    pChunk prev_chunk = PREV_CHUNK(c_ptr);
    pChunk next_chunk = NEXT_CHUNK(c_ptr);

    if(!PREV_INUSE(c_ptr)){     // prev chunk not in used
        next_chunk->prev_size = prev_chunk->chunk_size += c_ptr->chunk_size & ~(size_t)0x01;
        delete(sortedbin, prev_chunk);
        c_ptr = prev_chunk;
    }
    if(!PREV_INUSE(NEXT_CHUNK(next_chunk))){     // next chunk not in used
        NEXT_CHUNK(next_chunk)->prev_size = c_ptr->chunk_size += next_chunk->chunk_size - 1;
        delete(sortedbin, next_chunk);
        next_chunk = NEXT_CHUNK(next_chunk);
    }

    next_chunk->prev_size = c_ptr->chunk_size & ~(size_t)0x01;
    next_chunk->chunk_size &= ~(size_t)0x01;        // PREV_INUSE -> 0

    insert(&sortedbin, c_ptr);

    return;
}

void myfree(void *ptr)
{
    pChunk c_ptr = (pChunk)(ptr - 2 * sizeof(size_t));
    _myfree(c_ptr);
}
