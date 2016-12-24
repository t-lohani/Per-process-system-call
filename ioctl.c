
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include "override_syscall.h"
#include "ioctl.h"

#define DEVICE_NAME "ioctl_device"
#define AUTHOR "Group 12"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);

extern struct task_struct *pid_task(struct pid *pid, enum pid_type);
extern struct pid *find_vpid(int nr);
extern unsigned long get_vector_address(int vector_id);
extern int reduce_ref_count(int vector_id);
extern int show_vectors(void);

struct mutex mut_lock;

static void remove_from_task_struct(int p_id)
{
	struct task_struct *task = NULL;

	printk(KERN_INFO "Inside Remove from task_struct\n");

	task = pid_task(find_vpid(p_id), PIDTYPE_PID);
	if (task != NULL) {
		if (task->custom_sys_vector != NULL) {
			printk(KERN_INFO
			       "Removing vector from void* custom_sys_vector \n");
			task->custom_sys_vector = NULL;
			task->vector_id = 0;
		}
	}

}

static int get_vector_id(pid_t p)
{
	int ret = 0;
	struct task_struct *task;

	printk(KERN_INFO "inside get_vector_id \n");

	task = pid_task(find_vpid(p), PIDTYPE_PID);
	if (IS_ERR(task)) {
		printk(KERN_ERR "find_task_by_vpid failed. wrong pid given \n");
		ret = -EINVAL;
		goto out;
	}
	ret = task->vector_id;

out:
	return ret;
}

void dummy(void)
{
	printk(KERN_INFO "Inside Dummy \n");
}

EXPORT_SYMBOL(dummy);

static int add_to_task_struct(struct syscall_vector *sys_vec, int p_id,
			      int v_id)
{
	int ret = -1;

	struct task_struct *task = NULL;

	printk(" Inside add to task structure\n");

	task = pid_task(find_vpid(p_id), PIDTYPE_PID);
	if (IS_ERR(task)) {
		printk(KERN_INFO "add_to_task_struct failed\n");
		ret = -EINVAL;
		goto out;
	}
	if (task->custom_sys_vector == NULL) {
		ret = 0;
		printk(KERN_INFO "Adding vector \n");
		task->custom_sys_vector = (void *)sys_vec;
		task->vector_id = v_id;
	}

out:
	return ret;
}

static long device_ioctl(struct file *file, unsigned int ioctl_num,
			 unsigned long ioctl_param)
{
	int ret = 0;
	struct param *temp = NULL;
	int vector_id;
	struct syscall_vector *sys_vec = NULL;
	struct task_struct *task = NULL;
	struct pid *tp = NULL;
	int len;

	temp = kmalloc(sizeof(struct param), GFP_KERNEL);
	if (temp == NULL) {
		printk(KERN_ERR "memory allocation failed");
		ret = -EINVAL;
		goto out1;
	}

	printk(KERN_INFO "Inside device_ioctl\n");
	mutex_lock(&mut_lock);

	switch (ioctl_num) {
	case SET_IOCTL:

		if (copy_from_user
		    ((void *)temp, (void *)ioctl_param, sizeof(temp))) {
			printk(KERN_ERR "copy_from_user failed \n");
			ret = -EINVAL;
			goto out;
		}

		printk(KERN_INFO " VECTOR_ID_RECEIVED is: %d\n", temp->v_id);
		printk(KERN_INFO " P_ID_RECEIVED is: %d\n", temp->p_id);

		tp = find_vpid(temp->p_id);

		if (!IS_ERR(tp)) {
			task = pid_task(tp, PIDTYPE_PID);
			if (!IS_ERR(task)) {

				sys_vec =
				    (struct syscall_vector *)
				    get_vector_address(temp->v_id);

				if (sys_vec == NULL) {
					ret = -EINVAL;
				} else {
					printk(KERN_INFO
					       " VECTOR ADDRESS RECEIVED is: %ld\n",
					       (unsigned long)sys_vec);
					ret =
					    add_to_task_struct(sys_vec,
							       temp->p_id,
							       temp->v_id);
				}
				if (ret < 0) {

				}
			} else {
				printk(KERN_INFO
				       "Wrong PID Passed. SET_IOCTL Failed");
				ret = -EINVAL;
			}
		} else {
			printk(KERN_INFO "Wrong PID Passed. SET_IOCTL Failed");
			ret = -EINVAL;
		}
		break;
	case LIST_VECTOR:
		printk("Inside LIST_VECTOR\n");
		len = show_vectors();
		if (len > 0) {
			printk(KERN_INFO
			       "show vectors passed. Open /tmp/vectors.txt to see the list of vectors \n");
		}
		ret = len;
		break;
	case LIST_ID:

		if (copy_from_user
		    ((void *)&vector_id, (void *)ioctl_param,
		     sizeof(vector_id))) {
			printk(KERN_ERR "copy_from_user failed \n");
			ret = -EINVAL;
			goto out;
		}
		printk(KERN_INFO "pid in list_id:%d\n", vector_id);

		tp = find_vpid(temp->p_id);
		if (!IS_ERR(tp)) {
			task = pid_task(tp, PIDTYPE_PID);
			if (!IS_ERR(task)) {
				vector_id = get_vector_id(vector_id);
				printk(KERN_INFO "Vector id of the process: %d",
				       vector_id);

				if (copy_to_user
				    ((void *)ioctl_param, (void *)&vector_id,
				     sizeof(vector_id))) {
					printk(KERN_ERR
					       "copy_to_user failed \n");
					ret = -EINVAL;
					goto out;
				}
			} else {
				printk(KERN_INFO
				       "Wrong PID Passed. LIST_ID Failed");
				ret = -EINVAL;
			}
		} else {
			printk(KERN_INFO "Wrong PID Passed. LIST_ID Failed");
			ret = -EINVAL;
		}
		break;
	case REMOVE_IOCTL:

		if (copy_from_user
		    ((void *)temp, (void *)ioctl_param, sizeof(temp))) {
			printk(KERN_ERR "copy_from_user failed \n");
			ret = -EINVAL;
			goto out;
		}

		printk(KERN_INFO " VECTOR_ID_RECEIVED is: %d\n", temp->v_id);
		printk(KERN_INFO " P_ID_RECEIVED is: %d\n", temp->p_id);

		tp = find_vpid(temp->p_id);
		if (!IS_ERR(tp)) {
			task = pid_task(tp, PIDTYPE_PID);
			if (!IS_ERR(task)) {
				if (task->vector_id == temp->v_id) {
					ret = reduce_ref_count(temp->v_id);

					if (ret != -1) {
						remove_from_task_struct(temp->
									p_id);

					}
				}
			} else {
				printk(KERN_ERR
				       "Wrong PID Passed. REMOVE_IOCTL Failed \n");
				ret = -EINVAL;

			}
		} else {
			printk(KERN_ERR
			       "Wrong PID Passed. REMOVE_IOCTL Failed \n");
			ret = -EINVAL;
		}
		break;

	default:
		ret = -1;

	}

out:
	kfree(temp);
	mutex_unlock(&mut_lock);
out1:
	return (long)ret;
}

struct file_operations ioctl_ops = {
	.unlocked_ioctl = device_ioctl,
};

static int __init init_ioctl(void)
{
	int ret = 0;
	ret = register_chrdev(MAGIC_NO, DEVICE_NAME, &ioctl_ops);
	if (ret < 0) {
		printk(KERN_ALERT "%s with error no: %d\n",
		       "Failed to register ioctl ", ret);
		goto out;
	}
	mutex_init(&mut_lock);
out:
	return ret;
}

static void __exit exit_ioctl(void)
{
	unregister_chrdev(MAGIC_NO, DEVICE_NAME);
}

module_init(init_ioctl);
module_exit(exit_ioctl);
