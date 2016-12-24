
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>
#include "override_syscall.h"
#include "ioctl.h"

#define AUTHOR "Group 12"
#define DESCRIPTION "mkdir_override"
#define MAX_USER_BUFFER_SIZE 512

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

int vector_id = 2;
struct syscall_vector *vector_head;

extern void dummy(void);
extern int register_syscall(int vector_id, unsigned long vector_address,
			    struct module *vector_module);
extern int unregister_syscall(unsigned long vector_address);
extern struct task_struct *pid_task(struct pid *pid, enum pid_type);
extern struct pid *find_vpid(int nr);
extern long sys_getpid(void);
extern struct task_struct *find_task_by_vpid(pid_t vnr);

asmlinkage long custom_mkdir_syscall(const char __user *pathname, mode_t mode)
{
	long ret_val = -212;
	char *received_pathname = NULL;
	char *process_name = NULL;
	struct task_struct *task = NULL;

	printk("-------->Inside custom_mkdir_syscall\n");
	received_pathname = (char *)kmalloc(MAX_USER_BUFFER_SIZE, GFP_KERNEL);
	if (received_pathname == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(received_pathname)) {
		ret_val = PTR_ERR(received_pathname);
		goto out;
	}

	ret_val =
	    copy_from_user(received_pathname, pathname,
			   sizeof(received_pathname));
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}

	task = get_current();

	process_name =
	    (char *)kmalloc(sizeof(MAX_USER_BUFFER_SIZE), GFP_KERNEL);
	if (process_name == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}

	if (IS_ERR(process_name)) {
		ret_val = PTR_ERR(process_name);
		goto out;
	}

	strcpy(process_name, task->comm);

	if (strcmp(process_name, "httpd") == 0) {
		printk("------->httpd isn't allowed to run mkdir\n");
		ret_val = -222;
		goto out;
	}

	else
		ret_val = -212;

out:
	if (received_pathname != NULL)
		kfree(received_pathname);
	if (process_name != NULL)
		kfree(process_name);
	return ret_val;
}

asmlinkage long custom_rename_syscall(const char __user *old_pathname,
				      const char __user *new_pathname)
{
	long ret_val = -212;
	char *received_old_pathname = NULL;
	char *received_new_pathname = NULL;
	char *process_name = NULL;
	struct task_struct *task = NULL;

	printk("-------->Inside custom_rename_syscall\n");
	received_old_pathname =
	    (char *)kmalloc(MAX_USER_BUFFER_SIZE, GFP_KERNEL);
	if (received_old_pathname == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(received_old_pathname)) {
		ret_val = PTR_ERR(received_old_pathname);
		goto out;
	}

	ret_val =
	    copy_from_user(received_old_pathname, old_pathname,
			   sizeof(received_old_pathname));
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}

	received_new_pathname =
	    (char *)kmalloc(MAX_USER_BUFFER_SIZE, GFP_KERNEL);
	if (received_new_pathname == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(received_new_pathname)) {
		ret_val = PTR_ERR(received_new_pathname);
		goto out;
	}

	ret_val =
	    copy_from_user(received_new_pathname, new_pathname,
			   sizeof(received_new_pathname));
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}

	task = get_current();

	process_name =
	    (char *)kmalloc(sizeof(MAX_USER_BUFFER_SIZE), GFP_KERNEL);
	if (process_name == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}

	if (IS_ERR(process_name)) {
		ret_val = PTR_ERR(process_name);
		goto out;
	}

	strcpy(process_name, task->comm);

	if (strcmp(process_name, "httpd") == 0) {
		printk("------->httpd isn't allowed to run rename\n");
		ret_val = -222;
		goto out;
	}

	else
		ret_val = -212;

out:
	if (received_old_pathname != NULL)
		kfree(received_old_pathname);
	if (received_new_pathname != NULL)
		kfree(received_new_pathname);
	if (process_name != NULL)
		kfree(process_name);
	return ret_val;
}

asmlinkage long custom_chdir_syscall(const char __user *pathname)
{
	long ret_val = -212;
	char *received_pathname = NULL;
	char *process_name = NULL;
	struct task_struct *task = NULL;

	printk("-------->Inside custom_chdir_syscall\n");
	received_pathname = (char *)kmalloc(MAX_USER_BUFFER_SIZE, GFP_KERNEL);
	if (received_pathname == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(received_pathname)) {
		ret_val = PTR_ERR(received_pathname);
		goto out;
	}

	ret_val =
	    copy_from_user(received_pathname, pathname,
			   sizeof(received_pathname));
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}

	task = get_current();

	process_name =
	    (char *)kmalloc(sizeof(MAX_USER_BUFFER_SIZE), GFP_KERNEL);
	if (process_name == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}

	if (IS_ERR(process_name)) {
		ret_val = PTR_ERR(process_name);
		goto out;
	}

	strcpy(process_name, task->comm);

	if (strcmp(process_name, "httpd") == 0) {
		printk("------->httpd isn't allowed to run chdir\n");
		ret_val = -222;
		goto out;
	}

	else
		ret_val = -212;

out:
	if (received_pathname != NULL)
		kfree(received_pathname);
	if (process_name != NULL)
		kfree(process_name);
	return ret_val;
}

asmlinkage long custom_rmdir_syscall(const char __user *pathname)
{
	long ret_val = -212;
	char *received_pathname = NULL;

	printk("--------->Inside custom_rmdir_syscall\n");
	received_pathname = (char *)kmalloc(MAX_USER_BUFFER_SIZE, GFP_KERNEL);
	if (received_pathname == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(received_pathname)) {
		ret_val = PTR_ERR(received_pathname);
		goto out;
	}

	ret_val =
	    copy_from_user(received_pathname, pathname,
			   sizeof(received_pathname));
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}

out:
	if (received_pathname != NULL)
		kfree(received_pathname);

	return ret_val;
}

asmlinkage long custom_chmod_syscall(const char __user *pathname, mode_t mode)
{
	long ret_val = -212;
	char *received_pathname = NULL;

	printk("--------->Inside custom_chmod_syscall\n");
	received_pathname = (char *)kmalloc(MAX_USER_BUFFER_SIZE, GFP_KERNEL);
	if (received_pathname == NULL) {
		ret_val = -ENOMEM;
		goto out;
	}
	if (IS_ERR(received_pathname)) {
		ret_val = PTR_ERR(received_pathname);
		goto out;
	}

	ret_val =
	    copy_from_user(received_pathname, pathname,
			   sizeof(received_pathname));
	if (ret_val < 0) {
		ret_val = -EFAULT;
		goto out;
	}

out:
	if (received_pathname != NULL)
		kfree(received_pathname);

	return ret_val;
}

static int add_syscall_to_vector(int syscall_no, sys_call_ptr_t func_ptr,
				 signed char override)
{
	int ret_val = 0;
	struct syscall_vector *vec = NULL;
	struct syscall_vector *temp = NULL;

	printk("------->Inside add_syscall_to_vectorn\n");
	vec =
	    (struct syscall_vector *)kmalloc(sizeof(struct syscall_vector),
					     GFP_KERNEL);
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

	if (vector_head == NULL) {
		vector_head = vec;
		goto out;
	}

	temp = vector_head;
	while (temp->next != NULL) {
		temp = temp->next;
	}

	temp->next = vec;
out:
	return ret_val;
}

static int initialize_syscall_vector(void)
{
	int ret_val = 0;
	int mkdir_syscall_no = 83;
	int chdir_syscall_no = 80;
	int rmdir_syscall_no = 84;
	int chmod_syscall_no = 90;
	int rename_syscall_no = 82;
	int override = 0;

	printk("-------->Inside initialize_syscall\n");
	ret_val =
	    add_syscall_to_vector(mkdir_syscall_no,
				  (sys_call_ptr_t) custom_mkdir_syscall,
				  override);
	if (ret_val < 0) {
		goto out;
	}

	ret_val =
	    add_syscall_to_vector(chdir_syscall_no,
				  (sys_call_ptr_t) custom_chdir_syscall,
				  override);
	if (ret_val < 0) {
		goto out;
	}

	ret_val =
	    add_syscall_to_vector(rmdir_syscall_no,
				  (sys_call_ptr_t) custom_rmdir_syscall,
				  override);
	if (ret_val < 0) {
		goto out;
	}

	ret_val =
	    add_syscall_to_vector(chmod_syscall_no,
				  (sys_call_ptr_t) custom_chmod_syscall,
				  override);
	if (ret_val < 0) {
		goto out;
	}

	ret_val =
	    add_syscall_to_vector(rename_syscall_no,
				  (sys_call_ptr_t) custom_rename_syscall,
				  override);
	if (ret_val < 0) {
		goto out;
	}

	ret_val =
	    register_syscall(vector_id, (unsigned long)vector_head,
			     THIS_MODULE);

out:
	return ret_val;
}

static void delete_vector(void)
{
	struct syscall_vector *temp = NULL;
	struct syscall_vector *new_head = NULL;
	new_head = vector_head;

	printk("------->Inside delete_vector\n");
	if (vector_head == NULL) {
		goto end;
	}

	while (new_head->next != NULL) {
		temp = new_head;
		new_head = new_head->next;
		kfree(temp);
		temp = NULL;
	}

	kfree(new_head);
	new_head = NULL;
	vector_head = NULL;
	goto end;
end:
	;
}

static int __init custom_mkdir_init(void)
{
	int ret_val = 0;
	vector_head = NULL;
	dummy();
	printk("------->Inside __init custom_mkdir_init\n");
	ret_val = initialize_syscall_vector();
	if (ret_val < 0) {
		delete_vector();
	}

	return ret_val;
}

static void __exit custom_mkdir_cleanup(void)
{
	int ret_val;
	printk("------->Inside __exit custom_mkdir_cleanup\n");
	ret_val = unregister_syscall((unsigned long)vector_head);
	if (vector_head != NULL) {
		delete_vector();
	}
}

module_init(custom_mkdir_init);
module_exit(custom_mkdir_cleanup);
