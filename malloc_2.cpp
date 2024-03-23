#include <unistd.h>
#include <list>

class MallocMetadata
{
public:
    void *__ptr;
    size_t __size;
    bool __is_free;
    MallocMetadata *__next;
    MallocMetadata *__prev;

    MallocMetadata() = default;
    MallocMetadata(void *ptr, size_t size) : __ptr(ptr), __size(size), __is_free(false), __next(nullptr), __prev(nullptr)
    {
    }
};

class Heap
{
public:
    std::list<MallocMetadata> __meta_data; // TODO: we cant use std::list so we have to fix this
    size_t __num_free_blocks;
    size_t __num_free_bytes;
    size_t __num_allocated_blocks;
    size_t __num_allocated_bytes;

    Heap() : __meta_data(), __num_free_blocks(0), __num_free_bytes(0), __num_allocated_blocks(0), __num_allocated_bytes(0)
    {
    }
};

Heap heap;

void *smalloc(size_t size)
{
    if (size <= 0 || size > 10 ^ 8)
    {
        return nullptr;
    }

    for (MallocMetadata &temp : heap.__meta_data)
    {
        if (temp.__is_free == true && temp.__size >= size)
        {
            temp.__is_free = false;
            heap.__num_free_blocks--;
            heap.__num_free_bytes -= temp.__size;
            return temp.__ptr;
        }
    }

    void *res = sbrk(size);
    if (*(int *)res == -1)
    {
        return nullptr;
    }

    MallocMetadata data(res, size);
    heap.__meta_data.push_back(data);
    heap.__num_allocated_blocks++;
    heap.__num_allocated_bytes += size;
    return res;
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

    for (MallocMetadata &temp : heap.__meta_data)
    {
        if (temp.__ptr == ptr)
        {
            temp.__is_free = true;
            heap.__num_free_blocks++;
            heap.__num_free_bytes += temp.__size;
            return;
        }
    }
}

void *srealloc(void *oldp, size_t size)
{
    if (size <= 0 || size > 10 ^ 8)
    {
        return nullptr;
    }

    for (MallocMetadata &temp : heap.__meta_data)
    {
        if (temp.__ptr == oldp)
        {
            if (temp.__size >= size)
            {
                return oldp;
            }
        }
    }

    void *res = smalloc(size);

    if (res == nullptr)
    {
        return nullptr;
    }

    memmove(oldp, res, size);

    sfree(oldp);
    return res;
}

size_t _num_free_blocks()
{
    return heap.__num_free_blocks;
}

size_t _num_free_bytes()
{
    return heap.__num_free_bytes;
}

size_t _num_allocated_blocks()
{
    return heap.__num_allocated_blocks;
}

size_t _num_allocated_bytes()
{
    return heap.__num_allocated_bytes;
}

size_t _num_meta_data_bytes()
{
    return heap.__num_allocated_blocks * sizeof(MallocMetadata);
}

size_t _size_meta_data()
{
    return sizeof(MallocMetadata);
}