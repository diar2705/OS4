#include <string.h>
#include <unistd.h>

#define MAX_BLOCK_SIZE 100000000
class Heap
{
private:
    struct MallocMetadata
    {
        size_t __size;
        bool __is_free;
        MallocMetadata *__next;
        MallocMetadata *__prev;
    };

    MallocMetadata *__blocks_list_head;
    MallocMetadata *__block_list_tail; 

    size_t __num_free_blocks;
    size_t __num_free_bytes;
    size_t __num_allocated_blocks;
    size_t __num_allocated_bytes;

    void insert(MallocMetadata *block);
    MallocMetadata *get_MMD(void *ptr);

public:
    Heap();

    void *alloc_block(size_t size);
    void free_block(void *ptr);
    size_t numFreeBlocks();
    size_t numFreeBytes();
    size_t numAlocatedBlocks();
    size_t numAlocatedBytes();
    size_t numMetaDataBytes();
    size_t sizeMetaData();

    size_t block_size(void *ptr);
};

Heap::Heap() : __blocks_list_head(nullptr),
               __block_list_tail(nullptr),
               __num_free_blocks(0),
               __num_free_bytes(0),
               __num_allocated_blocks(0),
               __num_allocated_bytes(0)
{
}

void Heap::insert(MallocMetadata *block)
{
    __num_allocated_blocks++;
    __num_allocated_bytes += block->__size;
    if (__blocks_list_head == nullptr)
    {
        __blocks_list_head = block;
        __block_list_tail = block;
        return;
    }

    __block_list_tail->__next = block;
    block->__prev = __block_list_tail;
    __block_list_tail = block;
}

Heap::MallocMetadata *Heap::get_MMD(void *ptr)
{
    return (MallocMetadata *)((char *)ptr - sizeof(MallocMetadata));
}

void *Heap::alloc_block(size_t size)
{
    MallocMetadata *tmp = __blocks_list_head;
    while (tmp != nullptr)
    {
        if (tmp->__is_free && tmp->__size >= size)
        {
            tmp->__is_free = false;
            __num_free_blocks--;
            __num_free_bytes -= tmp->__size;
            return tmp;
        }
        tmp = tmp->__next;
    }

    size_t alloc_size = sizeof(MallocMetadata) + size;
    void *ptr = sbrk(alloc_size);

    if (ptr == (void *)-1)
    {
        return nullptr;
    }

    MallocMetadata *new_block = (MallocMetadata *)ptr;
    new_block->__size = size;
    new_block->__is_free = false;
    new_block->__next = nullptr;
    new_block->__prev = nullptr;
    insert(new_block);
    return ptr;
}

void Heap::free_block(void *ptr)
{
    MallocMetadata *block = get_MMD(ptr);
    if (block->__is_free)
    {
        return;
    }
    block->__is_free = true;

    __num_free_blocks++;
    __num_free_bytes += block->__size;
}

size_t Heap::numFreeBlocks()
{
    return __num_free_blocks;
}

size_t Heap::numFreeBytes()
{
    return __num_free_bytes;
}

size_t Heap::numAlocatedBlocks()
{
    return __num_allocated_blocks;
}

size_t Heap::numAlocatedBytes()
{
    return __num_allocated_bytes;
}

size_t Heap::numMetaDataBytes()
{
    return __num_allocated_blocks * sizeof(MallocMetadata);
}

size_t Heap::sizeMetaData()
{
    return sizeof(MallocMetadata);
}

size_t Heap::block_size(void *ptr)
{
    MallocMetadata *block = get_MMD(ptr);
    return block->__size;
}

//------------------------------------------------------------------------------------------------//

Heap heap;

void *smalloc(size_t size)
{
    if (size <= 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }
    void *res = heap.alloc_block(size);

    return (res == nullptr) ? res : (char *)res + heap.sizeMetaData();
}

void *scalloc(size_t num, size_t size)
{
    void *res = smalloc(num * size);

    if (res == nullptr)
    {
        return nullptr;
    }

    memset(res, 0, num * size);

    return res;
}

void sfree(void *ptr)
{
    if (ptr == nullptr)
    {
        return;
    }
    heap.free_block(ptr);
}

void *srealloc(void *oldp, size_t size)
{
    if (size <= 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }

    if (oldp == nullptr)
    {
        return smalloc(size);
    }

    if (heap.block_size(oldp) >= size)
    {
        return oldp;
    }

    void *res = smalloc(size);

    if (res == nullptr)
    {
        return nullptr;
    }

    memmove(res, oldp, size);

    sfree(oldp);
    return res;
}

size_t _num_free_blocks()
{
    return heap.numFreeBlocks();
}

size_t _num_free_bytes()
{
    return heap.numFreeBytes();
}

size_t _num_allocated_blocks()
{
    return heap.numAlocatedBlocks();
}

size_t _num_allocated_bytes()
{
    return heap.numAlocatedBytes();
}

size_t _num_meta_data_bytes()
{
    return heap.numMetaDataBytes();
}

size_t _size_meta_data()
{
    return heap.sizeMetaData();
}
