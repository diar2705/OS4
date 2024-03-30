#include <string.h>
#include <unistd.h>
#include <cmath>
#include <string>
#include <sys/mman.h>

#define MAX_BLOCK_SIZE 128 * 1024
#define MAX_ORDER 10

class Heap
{
private:
    struct MallocMetadata
    {
        size_t __block_size;
        bool __is_free;
        MallocMetadata *__next;
        MallocMetadata *__prev;
    };

    struct list
    {
        MallocMetadata *__first;
        MallocMetadata *__last;
        size_t __block_size;
    };

    bool __is_first_time;

    list __allocated_blocks[MAX_ORDER + 1];
    list __free_blocks[MAX_ORDER + 1];

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
    bool remove(list &lst, MallocMetadata *block);

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
    double order = std::log2(ceil(static_cast<double>(size) / 128));
    MallocMetadata *res;
    if (ceil(order) > MAX_ORDER)
    {
        res = (MallocMetadata *)mmap(nullptr, size + sizeof(MallocMetadata), PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
        res->__block_size = size;
        res->__next = nullptr;
        res->__prev = nullptr;
        res->__is_free = false;
    }
    else
    {
        res = find_suitable_block(size + sizeof(MallocMetadata));
        if (res != nullptr)
        {
            __num_free_blocks--;
            __num_free_bytes -= size;
        }
    }

    return res;
}

void Heap::free_block(void *ptr)
{
    MallocMetadata *block = get_MMD(ptr);
    size_t size = block->__block_size;
    if (block->__is_free)
    {
        return;
    }
    block->__is_free = true;
    int order = std::log2(ceil(static_cast<double>(size) / 128));

    if (remove(__allocated_blocks[order], block))
    {
        insert(__free_blocks[order], block);

        __num_free_blocks++;
        __num_free_bytes += size;

        merge(order);
    }
    else
    {
        munmap(block, size);
    }
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
    return block->__block_size;
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

    __is_first_time = false;
    void *program_break = sbrk(0);
    int pk = reinterpret_cast<size_t>(program_break);
    double order = std::log2(pk);
    int diff = pow(2, ceil(order)) - pk;
    void *blocks = sbrk(32 * MAX_BLOCK_SIZE + diff);
    blocks = (char *)blocks + diff;

    for (int i = 0; i <= MAX_ORDER; i++)
    {
        __free_blocks[i] = {nullptr, nullptr, 0};
        __allocated_blocks[i] = {nullptr, nullptr, 0};
    }

    for (int i = 0; i < 32; i++)
    {
        MallocMetadata *data = get_MMD((char *)blocks + MAX_BLOCK_SIZE * i);
        data->__is_free = true;
        data->__block_size = MAX_BLOCK_SIZE;
        insert(__free_blocks[MAX_ORDER], data);
    }
    __num_free_blocks = 32;
    __num_free_bytes = 32 * MAX_BLOCK_SIZE;
}

bool Heap::split(int order)
{
    if (order == MAX_ORDER + 1)
    {
        return false;
    }

    if (__free_blocks[order].__block_size == 0)
    {
        if (split(order + 1) == false)
        {
            return false;
        }
    }

    MallocMetadata *temp = __free_blocks[order].__first;
    MallocMetadata *buddy1, *buddy2;

    buddy1 = temp;
    buddy1->__block_size = (temp->__block_size) / 2;
    buddy1->__is_free = true;

    buddy2 = temp + ((temp->__block_size) / 2);
    buddy2->__is_free = true;
    buddy2->__block_size = (temp->__block_size) / 2;

    remove(__free_blocks[order], temp);
    insert(__free_blocks[order - 1], buddy1);
    insert(__free_blocks[order - 1], buddy2);
    return true;
}

void Heap::merge(int order)
{
    if (order == MAX_ORDER)
    {
        return;
    }

    MallocMetadata *temp = __free_blocks[order].__first;
    while (temp != nullptr && temp->__next != nullptr)
    {

        if ((reinterpret_cast<size_t>(temp) xor temp->__block_size) == reinterpret_cast<size_t>(temp->__next))
        {
            MallocMetadata *dad = temp;
            dad->__block_size = temp->__block_size * 2;

            remove(__free_blocks[order], temp->__next);
            remove(__free_blocks[order], temp);

            insert(__free_blocks[order + 1], dad);
            merge(order + 1);
            return;
        }
        temp = temp->__next;
    }
}

Heap::MallocMetadata *Heap::find_suitable_block(size_t size)
{
    double order = std::log2(ceil(static_cast<double>(size) / 128));
    int ord = floor(order);

    if (__free_blocks[ord].__block_size == 0)
    {
        if (ord == MAX_ORDER)
        {
            return nullptr;
        }
        split(ord + 1);
    }

    MallocMetadata *res = __free_blocks[ord].__first;
    if (res == nullptr)
    {
        return nullptr;
    }

    res->__is_free = false;
    remove(__free_blocks[ord], res);
    insert(__allocated_blocks[ord], res);

    return res;
}

void Heap::insert(list &lst, MallocMetadata *block)
{
    block->__prev = nullptr;
    block->__next = nullptr;

    if (lst.__block_size == 0)
    {
        lst.__first = block;
        lst.__last = block;
    }
    else if (lst.__last <= block)
    {
        lst.__last->__next = block;
        block->__prev = lst.__last;
        lst.__last = block;
    }
    else
    {
        MallocMetadata *temp;
        while (temp != nullptr)
        {
            if (temp > block)
            {
                block->__next = temp;
                block->__prev = temp->__prev;
                temp->__prev = block;
                break;
            }
            temp = temp->__next;
        }
    }
    lst.__block_size++;
}

bool Heap::remove(list &lst, MallocMetadata *block)
{
    if (lst.__block_size == 0)
    {
        return false;
    }
    MallocMetadata *temp = lst.__first;

    if (lst.__block_size == 1)
    {
        if (temp == block)
        {
            temp->__next = nullptr;
            temp->__prev = nullptr;
            lst.__first = nullptr;
            lst.__last = nullptr;
            lst.__block_size--;
            return true;
        }
        else
        {
            return false;
        }
    }

    while (temp != nullptr)
    {
        if (temp == block)
        {
            if (temp->__prev != nullptr)
            {
                temp->__prev->__next = temp->__next;
            }
            if (temp->__next != nullptr)
            {
                temp->__next->__prev = temp->__prev;
            }
            temp->__next = nullptr;
            temp->__prev = nullptr;
            lst.__block_size--;
            return true;
        }
        temp = temp->__next;
    }
    return false;
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
