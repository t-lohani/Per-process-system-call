#ifndef __REG_UNREG_H_
#define __REG_UNREG_H_

#define MAX_VECTOR_NAME_LEN 256
#define MAX_BUFF 4096

#include "override_syscall.h"

struct new_vector {
	int vector_id;
	unsigned long vector_address;
	int ref_count;
	struct module *vector_module;
	struct new_vector *next;
};

#endif
