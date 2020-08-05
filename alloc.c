#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

unsigned int max_size;

#define NUM_FB          8
#define MIN_FB_SIZE     0x20
#define MAX_FB_SIZE     0x58 // (NUM_FB << 3 + MIN_FB_SIZE - 0x8)

typedef struct _chunk {
    size_t chunk_size;
    size_t prev_size;
    void * bk;
    void * fd;
}* pChunk;

void* fastbin[NUM_FB];   // 0x20, 0x28, ... , 0x58
void* sortedbin;

void insert(pChunk root, pChunk c_ptr) {}
    c_ptr->fd = sortedbin;
    if(!sortedbin)  sortedbin->bk = c_ptr;
    sortedbin = c_ptr;
}

void *myalloc(size_t size)
{
    // void *p = sbrk(size);
    // debug("alloc(%u): %p\n", (unsigned int)size, p);
    // max_size += size;
    // debug("max: %u\n", max_size);
    // return p;

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

void _myfree(struct _chunk* c_ptr){

    size_t size = c_ptr->chunk_size;

    if(size <= MAX_FB_SIZE) {
        // fast bin
        int idx = (size - 0x20) >> 3;
        void* head = fastbin[idx];

        c_ptr->fd = head;

        if(!head)   head->bk = c_ptr;

        fastbin[idx] = c_ptr;

        return;
    }

    insert(sortedbin, c_ptr);

    return;
}

void myfree(void *ptr)
{
    pChunk c_ptr = (pChunk)(ptr - sizeof(size_t));
    _myfree(c_ptr);
}
