#include <string.h>
#include <unistd.h>
#include <cmath>
#include <string>

#define MAX_BLOCK_SIZE 128 * 1024
#define MAX_ORDER 10

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

    struct list
    {
        MallocMetadata *__first;
        MallocMetadata *__last;
        size_t __size;
    };

    bool __is_first_time;

    list __allocated_blocks[11];
    list __free_blocks[11];

    list __mmap_blocks;

    size_t __num_free_blocks;
    size_t __num_free_bytes;
    size_t __num_allocated_blocks;
    size_t __num_allocated_bytes;

    MallocMetadata *get_MMD(void *ptr);
    void init();
    bool split(int order);
    void merge(int order);
    MallocMetadata *find_suitable_block(size_t size);

    void insert(list &lst, MallocMetadata *block);
    void remove(list &lst, MallocMetadata *block);

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

//----------------------------------------------Heap Implementation--------------------------------------//

Heap::Heap() : __is_first_time(true),
               __allocated_blocks(),
               __free_blocks(),
               __num_free_blocks(0),
               __num_free_bytes(0),
               __num_allocated_blocks(0),
               __num_allocated_bytes(0)
{
}

void *Heap::alloc_block(size_t size)
{
    init();
    double order = std::log2(size);
    void *res;
    if (ceil(order) > MAX_ORDER)
    {
        // TODO: allocate a block using mmap
    }
    else
    {
        res = find_suitable_block(size);
    }

    if (res != nullptr)
    {
        __num_free_blocks--;
        __num_free_bytes -= size;
    }

    return res;
}

void Heap::free_block(void *ptr)
{
    MallocMetadata *block = get_MMD(ptr);
    if (block->__is_free)
    {
        return;
    }
    block->__is_free = true;
    int order = std::log2(block->__size);

    remove(__allocated_blocks[order], block);
    insert(__free_blocks[order], block);
    __num_free_blocks++;
    __num_free_bytes += block->__size;

    merge(order);
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

//----------------------------------------------Heap Helper--------------------------------------//

Heap::MallocMetadata *Heap::get_MMD(void *ptr)
{
    return (MallocMetadata *)((char *)ptr - sizeof(MallocMetadata));
}

void Heap::init()
{
    if (!__is_first_time)
    {
        return;
    }

    __is_first_time = true;

    void *program_break = sbrk(0);
    int pk = std::stoi((char *)program_break);
    int order = std::log2(pk);
    int diff = pow(2, order + 1) - pk;
    void *blocks = sbrk(32 * MAX_BLOCK_SIZE + pk);
    blocks = (char *)blocks + diff;

    for (int i = 0; i < 32; i++)
    {
        MallocMetadata *data = get_MMD((char *)blocks + MAX_BLOCK_SIZE * i);
        data->__is_free = true;
        data->__size = MAX_BLOCK_SIZE;
        insert(__free_blocks[MAX_ORDER], data);
    }
    __num_free_blocks = 32;
    __num_free_bytes = 32 * MAX_BLOCK_SIZE;
}

bool Heap::split(int order)
{
    // TODO
}

void Heap::merge(int order)
{
    // TODO
}

Heap::MallocMetadata *Heap::find_suitable_block(size_t size)
{
    double order = std::log2(size);

    int ord = floor(order);
    if (__free_blocks[ord].__size == 0)
    {
        split(ord);
    }

    MallocMetadata *res = __free_blocks[ord].__first;
    res->__is_free = false;
    remove(__free_blocks[ord], res);
    insert(__allocated_blocks[ord], res);

    return res;
}

void Heap::insert(list &lst, MallocMetadata *block)
{
    if (lst.__size == 0)
    {
        lst.__first = block;
        lst.__last = block;
        return;
    }

    lst.__last->__next = block;
    block->__prev = lst.__last;
    lst.__last = block;
    lst.__size++;
}

void Heap::remove(list &lst, MallocMetadata *block)
{
    MallocMetadata *temp = lst.__first;
    while (temp != nullptr)
    {
        if (temp == block)
        {
            temp->__prev->__next = temp->__next;
            temp->__next->__prev = temp->__prev;
            temp->__next = nullptr;
            temp->__prev = nullptr;
            return;
        }
        temp = temp->__next;
    }
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
