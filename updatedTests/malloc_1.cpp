#include <unistd.h>

#define MAX_BLOCK_SIZE 100000000

void *smalloc(size_t size)
{
    if (size <= 0 || size > MAX_BLOCK_SIZE)
    {
        return nullptr;
    }

    void *res = sbrk(size);

    if (*(int *)res == -1)
    {
        return nullptr;
    }

    return res;
}