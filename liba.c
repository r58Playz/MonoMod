#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <stdio.h>

#include <mono/metadata/class-internals.h>
#include <mono/mini/interp/interp-internals.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"

int32_t _mincore(void *addr, void *length, void *vec) {
	return mincore(addr, length, vec);
}

int32_t _mkstemp(void *template) {
	return mkstemp(template);
}

void *_mmap(void *addr, void *length, int32_t prot, int32_t flags, int32_t fd, int32_t offset) {
	return mmap(addr, length, prot, flags, fd, offset);
}

int32_t _mprotect(void *addr, void *len, int32_t prot) {
	// return mprotect(addr, len, prot);
	return 0;
}

int _munmap(void *addr, size_t len) {
	return munmap(addr, len);
}

int _pipe2(int pipefd[2], int flags) {
	// return pipe2(pipefd, flags);
	return 0;
}

void *_read(int fd, void *buf, void *count) {
	return read(fd, buf, count);
}

void *_write(int fd, const void *buf, void *count) {
	return write(fd, buf, count);
}

int64_t _sysconf(int32_t name) {
	return sysconf(name);
}

int32_t _uname(void *x) {
	return uname(x);
}


void *magictranslate(InterpMethod *mono) {
	mono = mono_interp_get_imethod(mono->method);
	return mono_method_get_header_internal(mono->method, NULL)->code;
}

uint32_t magictranslatelen(InterpMethod *mono) {
	mono = mono_interp_get_imethod(mono->method);
	return mono_method_get_header_internal(mono->method, NULL)->code_size;
}

void magicwrap(InterpMethod *mono) {
	mono = mono_interp_get_imethod(mono->method);
	MonoMethodHeader *head = mono_method_get_header_internal(mono->method, NULL);
	MonoMethodWrapper *wrap;

	if (!mono->method->sre_method) {
		wrap = g_malloc0(sizeof(MonoMethodWrapper));
		memcpy(wrap, mono->method, sizeof(MonoMethod));
		mono->method = wrap;
	} else {
		wrap = (MonoMethodWrapper*)mono->method;
	}

	mono->method->wrapper_type = MONO_WRAPPER_OTHER;
	wrap->header = head;
	wrap->mem_manager = m_class_get_mem_manager(mono->method->klass);

	wrap->method_data = g_malloc0(sizeof(void*) * 4);
	void **datav = (void **)(wrap)->method_data;

	WrapperInfo *info = g_malloc0(sizeof(WrapperInfo));
	info->subtype = WRAPPER_SUBTYPE_NONE;

	datav[0] = 2;
	datav[1] = info;
	datav[2] = mono->method->signature;
}

void magicinvalidate(InterpMethod *mono) {
	mono = mono_interp_get_imethod(mono->method);
	mono->transformed = 0;
}
