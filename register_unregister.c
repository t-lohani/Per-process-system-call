#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include "../kernel/vector.h"
#include "register_unregister.h"

#define EXPORT_SYMTAB
#define AUTHOR "Group 12"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);

char buf[MAX_BUFF];

/* write_file for writing to a file*/
static int write_file(struct file *file, char *buff, int len)
{
	int ret;
	mm_segment_t fs;
	fs = get_fs();
	set_fs(get_ds());

	ret = vfs_write(file, buff, len, &file->f_pos);

	set_fs(fs);
	return ret;
}

/* writes the list of loaded vectors to a file /tmp/vector.txt */

int show_vectors(void)
{
	struct new_vector *i;
	int ret;
	char *current_ptr;
	int len;
	char defa[35] = "No System Call Vectors Loaded";

	char filename[30] = "/tmp/vector.txt";
	struct file *fp = NULL;
	char str[35];

	printk("\n List of System Call Vectors Loaded");

	fp = filp_open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (IS_ERR(fp)) {
		printk(KERN_ERR "File Open Error! \n");
		ret = -EINVAL;
		goto out;
	}

	ret = 0;
	i = NULL;
	current_ptr = NULL;
	len = 0;

	memset(buf, 0, MAX_BUFF);

	current_ptr = buf;

	if (head == NULL) {

		len = len + strlen(defa) + 1;
		memcpy(current_ptr, defa, len);
		current_ptr[len - 1] = '\n';

		ret = len;

		write_file(fp, buf, len);

		goto out;
	} else {
		i = head;

		while (i != NULL) {
			printk("Vector ID: %d\n", i->vector_id);
			sprintf(str, "Vector ID: %d", i->vector_id);

			len = len + strlen(str) + 1;
			memcpy(current_ptr, str, strlen(str));
			current_ptr[len - 1] = '\n';
			current_ptr = current_ptr + strlen(str) + 1;

			sprintf(str, "No. of Users: %d", i->ref_count);

			len = len + strlen(str) + 1;
			memcpy(current_ptr, str, strlen(str));
			current_ptr[len - 1] = '\n';

			current_ptr = current_ptr + strlen(str) + 1;

			ret = len;

			i = i->next;
		}

		write_file(fp, buf, len - 1);

	}

out:
	return ret;
}

EXPORT_SYMBOL(show_vectors);

static int add_vector_address(int vector_id, unsigned long vector_address,
			      struct module *vector_module)
{
	int ret_val = 0;
	struct new_vector *va = NULL;
	struct new_vector *temp = NULL;

	va = (struct new_vector *)kmalloc(sizeof(struct new_vector),
					  GFP_KERNEL);
	if (va == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(va)) {
		ret_val = PTR_ERR(va);
		goto out;
	}

	memset(va, 0, sizeof(struct new_vector));

	va->vector_id = vector_id;
	va->vector_address = vector_address;
	va->ref_count = 0;
	va->vector_module = vector_module;
	va->next = NULL;

	if (head == NULL) {
		head = va;
		goto out;
	}

	temp = head;
	while (temp->next != NULL) {
		temp = temp->next;
	}

	temp->next = va;

out:
	return ret_val;
}

static int remove_vector_address(unsigned long vector_address)
{
	int ret_val = 0;
	int flag = 0;
	struct new_vector *ptr = NULL;
	struct new_vector *temp = NULL;

	if (head == NULL) {

		ret_val = -EFAULT;
		goto out;
	}

	if ((head->next == NULL) && (head->vector_address == vector_address)) {

		ptr = head;
		goto check_ref_count;
	}

	else if (head->next != NULL) {
		temp = head;
		ptr = temp->next;
		while (ptr != NULL) {
			if (ptr->vector_address == vector_address) {
				flag = 1;
				break;
			}
			ptr = ptr->next;
			temp = ptr;
		}
	} else
	printk("In else");
	if (flag == 0) {
		ret_val = -EFAULT;
		goto out;
	}

check_ref_count:
	if (ptr->ref_count > 0) {

		ret_val = -2222;
		goto out;
	}

	if (ptr != head)
		temp->next = ptr->next;
	else
		head = NULL;
	kfree(ptr);
	ptr = NULL;

out:
	return ret_val;
}

int register_syscall(int vector_id, unsigned long vector_address,
		     struct module *vector_module)
{
	int ret_val = 0;

	mutex_lock(&list_lock);
	ret_val = add_vector_address(vector_id, vector_address, vector_module);

	mutex_unlock(&list_lock);
	return ret_val;
}

EXPORT_SYMBOL(register_syscall);

int unregister_syscall(unsigned long vector_address)
{
	int ret_val = 0;

	mutex_lock(&list_lock);
	ret_val = remove_vector_address(vector_address);

	mutex_unlock(&list_lock);
	return ret_val;
}

EXPORT_SYMBOL(unregister_syscall);

/* Using get_vector_address in ioctl set case. To get the vector_address of the
 * vector_id given by the user and this is then used to set into the task_struct
    returns vector_address on success and 0 on failure;
*/

unsigned long get_vector_address(int vector_id)
{

	struct new_vector *test = NULL;
	unsigned long vec_addr = 0;

	mutex_lock(&list_lock);
	if (head == NULL) {
		goto out;
	}

	test = head;
	while (test != NULL) {

		if (test->vector_id == vector_id) {
			break;
		}
		test = test->next;
	}

	if (test != NULL) {
		test->ref_count = test->ref_count + 1;
		vec_addr = test->vector_address;
		try_module_get(test->vector_module);
	}
	mutex_unlock(&list_lock);
out:
	return vec_addr;
}

EXPORT_SYMBOL(get_vector_address);

/* Using reduce_ref_count function in ioctl for removing the vector for a given process.
   Traverses the list of vectors and reduces the count for the curresponding vector.
   Returns Updated reference count on success and -1 on failure.
 */

int reduce_ref_count(int vector_id)
{

	struct new_vector *test = NULL;
	int ret = -1;

	mutex_lock(&list_lock);

	if (head == NULL) {
		goto out;
	}

	test = head;
	while (test != NULL) {

		if (test->vector_id == vector_id) {
			break;
		}
		test = test->next;
	}

	if (test != NULL) {
		test->ref_count = test->ref_count - 1;
		ret = test->ref_count;
		module_put(test->vector_module);

	}
	mutex_unlock(&list_lock);
out:
	return ret;
}

EXPORT_SYMBOL(reduce_ref_count);

int init_module(void)
{

	head = NULL;
	mutex_init(&list_lock);

	printk("Loaded module for registering Vectors");
	return 0;
}

void cleanup_module(void)
{
	printk("Registering Vector module Unloadded");
}
