#include <errno.h>
#include <malloc.h>
#include <stdlib.h>

void *memalign(size_t alignment, size_t size) {
	void *ptr = nullptr;
	int ret = posix_memalign(&ptr, alignment, size);
	if(ret) {
		errno = ret;
		return nullptr;
	}
	return ptr;
}
