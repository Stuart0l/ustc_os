/*
 * mm-explicit-1.c - small improvement on explicit linklist.
 * 
 * allocated block now has no foot, free block use the second
 * to represent if last block if free or allocated. May improve
 * space utilization a bit.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define WSIZE 4
#define DSIZE 8
#define CHUNKSIZE (1<<12)

#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define PACK(size, alloc_prev, alloc) ((size) | ((alloc_prev)<<1) | (alloc))

#define GET(p) (*(unsigned int *)(p))
#define GETP(p) (*(char **)(p))
#define PUT(p, val) (*(unsigned int *)(p) = (val))
#define PUTP(p, val) (*(char **)(p) = (val))

#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)
#define GET_ALLOC_PREV(p) ((GET(p) & 0x2)>>1)
#define SET_ALLOC_PREV_A(p) (GET(p) |= 0x2)
#define SET_ALLOC_PREV_F(p) (GET(p) &= ~0x2)

#define HDRP(bp) ((char *)(bp) - 3*WSIZE)  // free blk
#define HDRA(bp) ((char *)(bp) - WSIZE)  // allocated blk
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - 2*DSIZE)
#define PRED(bp) ((char *)(bp) - DSIZE)
#define SUCC(bp) ((char *)(bp) - WSIZE)

/* use on free blk, and only when next/prev blk is free */
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - 3*WSIZE)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - 2*DSIZE)))

static char *head_listp;


static void *coalesce(void *bp) {
    size_t prev_alloc = GET_ALLOC_PREV(HDRP(bp));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));

    if (prev_alloc && next_alloc) {
        char *tmp = GETP(SUCC(head_listp));
        PUTP(SUCC(head_listp), bp);
        PUTP(PRED(bp), head_listp);
        PUTP(SUCC(bp), tmp);
        PUTP(PRED(tmp), bp);
        return bp;
    }
    else if (prev_alloc && !next_alloc) {
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));

        /* remove next blk from linklist */
        PUTP(SUCC(GET(PRED(NEXT_BLKP(bp)))), GETP(SUCC(NEXT_BLKP(bp))));
        PUTP(PRED(GET(SUCC(NEXT_BLKP(bp)))), GETP(PRED(NEXT_BLKP(bp))));

        /* set blk info */
        PUT(HDRP(bp), PACK(size, 1, 0));
        PUT(FTRP(bp), PACK(size, 1, 0));

        /* insert in the beginning */
        char *tmp = GETP(SUCC(head_listp));
        PUTP(SUCC(head_listp), bp);
        PUTP(PRED(bp), head_listp);
        PUTP(SUCC(bp), tmp);
        PUTP(PRED(tmp), bp);
    }
    else if (!prev_alloc && next_alloc) {
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));

        PUTP(SUCC(GET(PRED(PREV_BLKP(bp)))), GETP(SUCC(PREV_BLKP(bp))));
        PUTP(PRED(GET(SUCC(PREV_BLKP(bp)))), GETP(PRED(PREV_BLKP(bp))));

        PUT(FTRP(bp), PACK(size, 1, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 1, 0));
        bp = PREV_BLKP(bp);

        char *tmp = GETP(SUCC(head_listp));
        PUTP(SUCC(head_listp), bp);
        PUTP(PRED(bp), head_listp);
        PUTP(SUCC(bp), tmp);
        PUTP(PRED(tmp), bp);
    }
    else {
        size += GET_SIZE(HDRP(NEXT_BLKP(bp))) + GET_SIZE(HDRP(PREV_BLKP(bp)));

        PUTP(SUCC(GETP(PRED(NEXT_BLKP(bp)))), GETP(SUCC(NEXT_BLKP(bp))));
        PUTP(PRED(GETP(SUCC(NEXT_BLKP(bp)))), GETP(PRED(NEXT_BLKP(bp))));

        PUTP(SUCC(GETP(PRED(PREV_BLKP(bp)))), GETP(SUCC(PREV_BLKP(bp))));
        PUTP(PRED(GETP(SUCC(PREV_BLKP(bp)))), GETP(PRED(PREV_BLKP(bp))));

        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 1, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 1, 0));
        bp = PREV_BLKP(bp);

        char* tmp = GETP(SUCC(head_listp));
        PUTP(SUCC(head_listp), bp);
        PUTP(PRED(bp), head_listp);
        PUTP(SUCC(bp), tmp);
        PUTP(PRED(tmp), bp);
    }
    return bp;
}

static void *extend_heap(size_t words) {
    char *bp;
    size_t size;

    size = MAX(4 * WSIZE, (words % 4) ? (words+3) / 4 * 4 * WSIZE : words * WSIZE);  // min: 4 words
    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;
    bp += (2*WSIZE);

    PUT(HDRP(bp), PACK(size, GET_ALLOC_PREV(HDRP(bp)), 0));  // set head
    PUT(FTRP(bp), GET(HDRP(bp)));  // set foot
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 0, 1));  // set end

    return coalesce(bp);
}

static void *find_fit(size_t asize) {
    char *bp = GETP(SUCC(head_listp));
    size_t size = 0;

    while (bp != head_listp) {
        if ((size = GET_SIZE(HDRP(bp))) >= asize)
            return bp;
        bp = GETP(SUCC(bp));
    }

    return NULL;
}

static void place(void *bp, size_t asize) {
    size_t size = GET_SIZE(HDRP(bp)) - asize;

    PUT(HDRP(bp), PACK(asize, 1, 1));

    if (size > 0) {
        PUT(HDRP(NEXT_BLKP(bp)), PACK(size, 1, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 1, 0));

        /* modify this blk's pointer */
        PUTP(SUCC(NEXT_BLKP(bp)), GETP(SUCC(bp)));
        PUTP(PRED(NEXT_BLKP(bp)), GETP(PRED(bp)));

        /* modify pred's and succ's pointer */
        PUTP(SUCC(GETP(PRED(bp))), NEXT_BLKP(bp));
        PUTP(PRED(GETP(SUCC(bp))), NEXT_BLKP(bp));
    }
    else {
        SET_ALLOC_PREV_A(HDRP(NEXT_BLKP(bp)));
        /* when no free space for this blk, remove it from the linklist */
        PUTP(SUCC(GETP(PRED(bp))), GETP(SUCC(bp)));
        PUTP(PRED(GETP(SUCC(bp))), GETP(PRED(bp)));
    }
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((head_listp = mem_sbrk(6*WSIZE)) == (void*)-1)
        return -1;
    PUT(head_listp, 0);
    PUT(head_listp + (1*WSIZE), PACK(2*DSIZE, 1, 1));
    PUT(head_listp + (4*WSIZE), PACK(2*DSIZE, 1, 1));
    PUT(head_listp + (5*WSIZE), PACK(0, 1, 1));  // end blk
    head_listp += (4*WSIZE);

    /* make a circle to eliminate boundary */
    PUTP(SUCC(head_listp), head_listp);
    PUTP(PRED(head_listp), head_listp);

    if (extend_heap(CHUNKSIZE/WSIZE) == NULL)
        return -1;
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t asize;
    size_t extend_size;
    char *bp;

    if (size == 0)
        return NULL;

    if(size <= 3*WSIZE)
        asize = 2*DSIZE;
    else
        asize = 2*DSIZE * ((size + WSIZE + (2*DSIZE-1))/(2*DSIZE));  // blk size must be multiple of 4 words

    if ((bp = find_fit(asize)) != NULL) {
        place(bp, asize);
        bp -= DSIZE;
        return bp;
    }

    extend_size = MAX(asize, CHUNKSIZE);
    if ((bp = extend_heap(extend_size/WSIZE)) == NULL)
        return NULL;
    place(bp, asize);
    bp -= DSIZE;
    return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    size_t size = GET_SIZE(HDRA(ptr));
    ptr += (2*WSIZE);  // change format to free blk

    SET_ALLOC_PREV_F(HDRP(NEXT_BLKP(ptr)));
    PUT(HDRP(ptr), PACK(size, GET_ALLOC_PREV(HDRP(ptr)), 0));
    PUT(FTRP(ptr), GET(HDRP(ptr)));
    coalesce(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;
    
    newptr = mm_malloc(size);
    if (newptr == NULL)
      return NULL;
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
      copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}
