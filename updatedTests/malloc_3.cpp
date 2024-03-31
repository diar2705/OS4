#include <string.h>
#include <unistd.h>
#include <cmath>
#include <string>
#include <sys/mman.h>

#define MAX_BLOCK_SIZE 128 * 1024
#define MAX_ORDER 10
#define MAX_SIZE 100000000
class Heap
{
private:
    struct MallocMetadata
    {
        size_t __block_size;
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

    list __allocated_blocks[MAX_ORDER + 1];
    list __free_blocks[MAX_ORDER + 1];

    size_t __num_free_blocks;
    size_t __num_free_bytes;
    size_t __num_allocated_blocks;
    size_t __num_allocated_bytes;

    size_t __diff;

    MallocMetadata *get_MMD(void *ptr);
    void init();
    bool split(int order);
    void merge(int order);
    MallocMetadata *find_suitable_block(int ord);

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
               __num_allocated_bytes(0),
               __diff(0)
{
}

void *Heap::alloc_block(size_t size)
{
    init();
    double order = std::log2(ceil((size + sizeof(MallocMetadata)) / static_cast<double>(128)));
    int ord = ceil(order);
    MallocMetadata *res;
    if (ord > MAX_ORDER)
    {
        void *ptr = mmap(nullptr, size + sizeof(MallocMetadata), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (ptr == (void *)-1)
        {
            return nullptr;
        }
        res = (MallocMetadata *)ptr;

        res->__block_size = size + sizeof(MallocMetadata);
        res->__size = size;
        res->__next = nullptr;
        res->__prev = nullptr;
        res->__is_free = false;

        __num_allocated_blocks++;
        __num_allocated_bytes += res->__size;
    }
    else
    {
        res = find_suitable_block(ord);
        if (res != nullptr)
        {
            res->__size = size;
            __num_free_blocks--;
            __num_free_bytes -= (res->__block_size - sizeof(MallocMetadata));
        }
    }

    return res;
}

void Heap::free_block(void *ptr)
{
    MallocMetadata *block = get_MMD(ptr);
    if (block == nullptr || block->__is_free)
    {
        return;
    }

    block->__is_free = true;

    double order = std::log2(ceil(block->__block_size / static_cast<double>(128)));
    int ord = ceil(order);

    if (ord > MAX_ORDER)
    {
        size_t size = block->__size;

        munmap(block, block->__block_size);

        __num_allocated_blocks--;
        __num_allocated_bytes -= size;
    }
    else if (remove(__allocated_blocks[ord], block))
    {
        insert(__free_blocks[ord], block);

        __num_free_blocks++;
        __num_free_bytes += block->__block_size - sizeof(MallocMetadata);

        merge(ord);
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
    if (ptr == nullptr)
    {
        return nullptr;
    }
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
    size_t pk = reinterpret_cast<size_t>(program_break);

    double order = std::log2(pk);

    size_t diff = (size_t)pow(2, ceil(order)) - pk;
    this->__diff = diff;

    void *temp = sbrk(32 * MAX_BLOCK_SIZE);

    void *blocks = (char *)temp;

    for (int i = 0; i <= MAX_ORDER; i++)
    {
        __free_blocks[i] = {nullptr, nullptr, 0};
        __allocated_blocks[i] = {nullptr, nullptr, 0};
    }

    for (int i = 0; i < 32; i++)
    {
        MallocMetadata *data = (MallocMetadata *)((char *)blocks + MAX_BLOCK_SIZE * i);
        data->__is_free = true;
        data->__block_size = MAX_BLOCK_SIZE;
        data->__size = 0;
        insert(__free_blocks[MAX_ORDER], data);
    }
    __num_free_blocks = 32;
    __num_free_bytes = 32 * MAX_BLOCK_SIZE - 32 * sizeof(MallocMetadata);
    __num_allocated_blocks = __num_free_blocks;
    __num_allocated_bytes = __num_free_bytes;
}

bool Heap::split(int order)
{
    if (order == MAX_ORDER + 1)
    {
        return false;
    }

    if (__free_blocks[order].__size == 0)
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

    buddy2 = (MallocMetadata*)((char*)temp + (buddy1->__block_size));
    buddy2->__is_free = true;
    buddy2->__block_size = buddy1->__block_size;

    remove(__free_blocks[order], temp);
    insert(__free_blocks[order - 1], buddy1);
    insert(__free_blocks[order - 1], buddy2);

    __num_allocated_blocks++;
    __num_free_blocks++;
    __num_allocated_bytes -= sizeof(MallocMetadata);
    __num_free_bytes -= sizeof(MallocMetadata);

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

        if (((reinterpret_cast<size_t>(temp) + __diff) xor (temp->__block_size)) == reinterpret_cast<size_t>(temp->__next) + __diff)
        {
            MallocMetadata *dad = temp;
            dad->__block_size = temp->__block_size * 2;

            remove(__free_blocks[order], temp->__next);
            remove(__free_blocks[order], temp);
            insert(__free_blocks[order + 1], dad);

            __num_allocated_blocks--;
            __num_free_blocks--;
            __num_allocated_bytes += sizeof(MallocMetadata);
            __num_free_bytes += sizeof(MallocMetadata);

            merge(order + 1);
            return;
        }
        temp = temp->__next;
    }
}

Heap::MallocMetadata *Heap::find_suitable_block(int ord)
{
    if (__free_blocks[ord].__size == 0)
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

    if (lst.__size == 0)
    { // List is empty
        lst.__first = block;
        lst.__last = block;
    }
    else if (reinterpret_cast<uintptr_t>(lst.__last) <= reinterpret_cast<uintptr_t>(block))
    { // Insert at the end
        lst.__last->__next = block;
        block->__prev = lst.__last;
        lst.__last = block;
    }
    else if (reinterpret_cast<uintptr_t>(lst.__first) > reinterpret_cast<uintptr_t>(block))
    { // Insert at the beginning
        lst.__first->__prev = block;
        block->__next = lst.__first;
        lst.__first = block;
    }
    else
    { // Insert in the middle
        MallocMetadata *temp = lst.__first;
        while (temp != nullptr)
        {
            if (reinterpret_cast<uintptr_t>(temp) > reinterpret_cast<uintptr_t>(block))
            {
                block->__next = temp;
                block->__prev = temp->__prev;
                if (temp->__prev != nullptr)
                {
                    temp->__prev->__next = block;
                }
                temp->__prev = block;
                break;
            }
            temp = temp->__next;
        }
    }
    lst.__size++;
}

bool Heap::remove(list &lst, MallocMetadata *block)
{
    if (lst.__size == 0)
    {
        return false;
    }
    MallocMetadata *temp = lst.__first;

    if (lst.__size == 1)
    {
        if (temp == block)
        {
            temp->__next = nullptr;
            temp->__prev = nullptr;

            lst.__first = nullptr;
            lst.__last = nullptr;
            lst.__size--;
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
            else
            {
            lst.__first = temp->__next;
            }
            if (temp->__next != nullptr)
            {
                temp->__next->__prev = temp->__prev;
            }
            else
            {
                lst.__last = temp->__prev;
            }

            temp->__next = nullptr;
            temp->__prev = nullptr;

            lst.__size--;
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
    /**
     * TODO: we should check if we have to alloc the 32 block even if the first smalloc fails, which imo is stupid.
     * either way, if we have to alloc them, we should make init public rather than private.
     * and then we should remove it from Heap::alloc_block (won't affect anything but better).
     * and in the end we should call the init function here at the start of smalloc. 
    */
    //

    if (size <= 0 || size > MAX_SIZE)
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
