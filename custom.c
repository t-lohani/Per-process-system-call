/*
 * This module is an implementation of an overridden system_call_vector/table.
 * This module can represent any application that wants to override basic file
 * operations call like open and read.
 *
 * open, read, and fchown have been implemented.
 *
 * A vector ("struct syscall_vector") is a linked list of all the system
 * calls, here represented as a structure "struct overriden_syscall". Both structures
 * are declared in "override_syscall.h".
 *
 * The vector contains all the system calls that this module wants to override.
 * "struct overridden_syscall" contains information about one particular system call -
 * 1) system call number("syscall_no") and 2) the address of function or function pointer
 *     of implementation of that systemcall function("function_ptr").
 *
 * register_syscall() and unregister_syscall() API are used to add and remove the vector
 * respectively, in the list of registered and unregistered vectors maintained in "reg_unreg"
 * module. These functions are exported in "reg_unreg" module.
 *
 * overridden functions are declared as "asmlinkage" to tell the compiler that arguements
 * are to be taken from stack.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/syscall.h>
#include "override_syscall.h"
#include "ioctl.h"

#define MAX_USER_BUF_INPUT_SIZE 512
#define AUTHOR "Homework3 gp-12"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);

extern void dummy(void);
int vector_id = 1;
struct syscall_vector *vec_head = NULL;

extern int register_syscall(int vector_id, unsigned long vector_address, struct module *vector_module);
extern int unregister_syscall(unsigned long vector_address);

asmlinkage long custom_open_syscall(const char __user *filename, int flags, umode_t mode)
{
	long ret_val = -212;
	char *fname = NULL;

	fname = (char *)kmalloc(MAX_USER_BUF_INPUT_SIZE, GFP_KERNEL);
	if (fname == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(fname)) {
		ret_val = PTR_ERR(fname);
		goto out;
	}

	ret_val = copy_from_user(fname, filename, MAX_USER_BUF_INPUT_SIZE);
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}

	ret_val = -212;
	printk(KERN_INFO "In wrapped open syscall \n");
	printk(KERN_INFO "filename is: %s", fname);

out:
	if (fname != NULL)
		kfree(fname);
	return ret_val;
}
asmlinkage long custom_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	int ret = 0;
	char *output_buf = NULL;

	output_buf = (char *)kmalloc(MAX_USER_BUF_INPUT_SIZE, GFP_KERNEL);
	if (output_buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	if (IS_ERR(output_buf)) {
		ret = PTR_ERR(output_buf);
		goto out;
	}
	memcpy(output_buf, "ITS HIGHLY CONFIDENTIAL.YOU ARE NOT ALLOWED TO READ", 100);

    ret = copy_to_user(buf, output_buf, 100);
    if (ret < 0) {
		ret = -EFAULT;
		goto out;
    }

	ret = count;
	printk(KERN_INFO "In overridden read Syscall\n");
	printk(KERN_INFO "Received fd: %u\n", fd);
out:
	if (output_buf != NULL)
		kfree(output_buf);
	return ret;
}
asmlinkage long custom_write_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret = -212;
	char *output_buf = NULL;

	output_buf = (char *)kmalloc(MAX_USER_BUF_INPUT_SIZE, GFP_KERNEL);
	if (output_buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	if (IS_ERR(output_buf)) {
		ret = PTR_ERR(output_buf);
		goto out;
	}

	ret = copy_from_user(output_buf, buf, MAX_USER_BUF_INPUT_SIZE);
	if (ret < 0) {
		ret = -EFAULT;
		goto out;
	}

	ret = -212;
	printk(KERN_INFO "In wrapped write syscall\n");
	printk(KERN_INFO "Received fd: %u\n", fd);

out:
	if (output_buf != NULL)
		kfree(output_buf);

	return ret;
}

asmlinkage long custom_unlink_syscall(const char __user *pathname)
{
	long ret_val = -212;
	char *path_name = NULL;
	int path_len;
	path_name = (char *)kmalloc(MAX_USER_BUF_INPUT_SIZE, GFP_KERNEL);
	if (path_name == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}

	if (IS_ERR(path_name)) {
		ret_val = PTR_ERR(path_name);
		goto out;
	}

	ret_val = copy_from_user(path_name, pathname, MAX_USER_BUF_INPUT_SIZE);
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}
	path_len = strlen(path_name);
	if (!strcmp(path_name+path_len-8, ".protect")) {
		printk("file is protected for unlink");
		ret_val = -222;
	} else
		ret_val = -212;

	printk(KERN_INFO "Inside custom unlink System Call Function ..");
	printk(KERN_INFO "Received path name is: %s", path_name);

out:
	if (path_name != NULL)
		kfree(path_name);
	return ret_val;
}
asmlinkage long custom_stat_syscall(const char __user *filename,
				struct __old_kernel_stat __user *statbuf)
{
	long ret_val = -212;
	char *file_name = NULL;
	int path_len;
	file_name = (char *)kmalloc(MAX_USER_BUF_INPUT_SIZE, GFP_KERNEL);
	if (file_name == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(file_name)) {
		ret_val = PTR_ERR(file_name);
		goto out;
	}

	ret_val = copy_from_user(file_name, filename, MAX_USER_BUF_INPUT_SIZE);
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}
	path_len = strlen(file_name);
	if (!strcmp(file_name+path_len-8, ".protect")) {
		printk("file is protected");
		ret_val = -222;
	} else
		ret_val = -212;

	printk(KERN_INFO "Inside custom stat System Call Function ..");

out:
	if (file_name != NULL)
		kfree(file_name);
	return ret_val;
}

static int add_syscall_to_vector(int syscall_no, sys_call_ptr_t func_ptr, signed char override)
{
	int ret_val = 0;
	struct syscall_vector *vec = NULL;
	struct syscall_vector *temp = NULL;

	vec = (struct syscall_vector *)kmalloc(sizeof(struct syscall_vector), GFP_KERNEL);
		if (vec == NULL) {
			ret_val = -ENOMEM;
			goto out;
		}

		if (IS_ERR(vec)) {
			ret_val = PTR_ERR(vec);
			goto out;
		}

		memset(vec, 0, sizeof(struct syscall_vector));
		vec->sys_call.syscall_no = syscall_no;
		vec->sys_call.function_ptr = func_ptr;
		vec->sys_call.override = override;

		if (vec_head == NULL) {
			vec_head = vec;
			goto out;
		}

		temp = vec_head;
		while (temp->next != NULL)
			temp = temp->next;

		temp->next = vec;
out:
	return ret_val;
}


static int initialize_syscall_vector(void)
{
	int ret_val = 0;
	int open_syscall_no = 2;
	int write_syscall_no = 1;
	int read_syscall_no = 0;
	int unlink_syscall_no = 87;
	int stat_syscall_no = 4;
	int override = 0;
	ret_val = add_syscall_to_vector(open_syscall_no, (sys_call_ptr_t)custom_open_syscall, override);

	if (ret_val < 0)
		goto out;

	override = 1;
	ret_val = add_syscall_to_vector(read_syscall_no, (sys_call_ptr_t)custom_read_syscall, override);

	if (ret_val < 0)
		goto out;
	override = 0;
	ret_val = add_syscall_to_vector(unlink_syscall_no, (sys_call_ptr_t)custom_unlink_syscall, override);

	if (ret_val < 0)
		goto out;

	override = 0;
	ret_val = add_syscall_to_vector(write_syscall_no, (sys_call_ptr_t)custom_write_syscall, override);

	if (ret_val < 0)
		goto out;

	override = 0;
	ret_val = add_syscall_to_vector(stat_syscall_no, (sys_call_ptr_t)custom_stat_syscall, override);

	if (ret_val < 0)
		goto out;

	ret_val = register_syscall(vector_id, (unsigned long)vec_head, THIS_MODULE);

out:
	return ret_val;
}

static void delete_vector(void)
{
	struct syscall_vector *temp = NULL;
	struct syscall_vector *new_head = NULL;
	new_head = vec_head;


	if (vec_head == NULL)
		goto end;

	while (new_head->next != NULL) {
		temp = new_head;
		new_head = new_head->next;
		kfree(temp);
		temp = NULL;
	}

	kfree(new_head);
	new_head = NULL;
	vec_head = NULL;
	goto end;
end:
;
}


static int __init custom_open_init(void)
{
	int ret_val = 0;
	dummy();
	ret_val = initialize_syscall_vector();
	if (ret_val < 0)
		delete_vector();
	return ret_val;
}

static void __exit custom_open_cleanup(void)
{
	int ret_val;
	ret_val = unregister_syscall((unsigned long)vec_head);
	if (vec_head != NULL)
		delete_vector();
}

module_init(custom_open_init);
module_exit(custom_open_cleanup);

