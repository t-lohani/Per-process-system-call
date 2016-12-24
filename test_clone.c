/*
  User program which sets and removes system call vectors through ioctl to this user program's process
 */


#include "ioctl.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include "/usr/include/linux/sched.h"


#define MAX_IOCTL_PATH_LENGTH 512
#define CLONE_SYSCALLS	0x00001000

/*
 Functions to remove and set ioctl vectors
    */

int ioctl_remove_vector(int fd, struct param *ioctl_param)
{
	int ret_value = 0;

	ret_value = ioctl(fd, REMOVE_IOCTL, ioctl_param);
	if (ret_value < 0) {
		printf("ioctl_remove_vector failed:%d %d\n", errno, fd);
		perror("ERROR ");
	}
	return ret_value;
}

int ioctl_set_vector(int fd, struct param *ioctl_param)
{
	int ret_value = 0;

	ret_value = ioctl(fd, SET_IOCTL, ioctl_param);
	if (ret_value < 0) {
		printf("ioctl_set_vector failed:%d %d %d \n", errno, fd, ret_value);
		perror("ERROR ");
	}

	return ret_value;
}

int ioctl_list_vector_id(int fd, int *p_id)
{
	int ret_value = 0;

	ret_value = ioctl(fd, LIST_ID, p_id);
	if (ret_value < 0) {
		printf("ioctl_list_vector failed:%d %d %d \n", errno, fd, ret_value);
		perror("ERROR ");
	}

	return ret_value;
}


clone_body(void *arg) {
	int ret1 = 0;
	printf("Child process ID : %d\n", getpid());
	ret1 = open("test_clone", 66, 77);
	printf("child return value is: %d\n\n", ret1);
	_exit(0);
}

/*
 *  * Main program - ioctl functions called from here
 *   */
int main(int argc, char **argv)
{
	int child_vec_id;
	int fd;
	struct param *ioctl_param = NULL;
	struct param *ioctl_param_child = NULL;
	int ret_value = 0;
	char *dummy_file_ioctl;
	char device[] = "/dev/ioctl_device";
	int vec_id;
	pid_t wpid;
	char user_clone_flag;
	void **stack = NULL;
	int status;
	int clone_ret_value = 0;
	int list_pid = 0;
	int list_child_pid = 0;
	int child_pid;

	if ((argc < 3) || ((((int) *argv[1])-'0') >= 6) || (argc > 3)) {
		printf("Syntax to run: \n$/> ./clone {vector_id - parent process} and {vector_id - child process}\n");
		goto main_out;
	}

	printf("My process ID : %d\n", getpid());

	dummy_file_ioctl = (char *) malloc(MAX_IOCTL_PATH_LENGTH);
	memset(dummy_file_ioctl, 0, MAX_IOCTL_PATH_LENGTH);
	memcpy(dummy_file_ioctl, device, strlen(device));

	ioctl_param = (struct param *)malloc(sizeof(struct param));
	ioctl_param->v_id = (int) *argv[1];
	ioctl_param->v_id = ioctl_param->v_id - '0';

	child_vec_id = (int) *argv[2];
	child_vec_id = child_vec_id-'0';
	printf("Vector passed to be set to child %d \n ", child_vec_id);

	printf("Vector id passed to be set to parent: %d\n", ioctl_param->v_id);
	fd = open(dummy_file_ioctl, 0);

	if (fd < 0) {
		printf("Can't open file: %s\n", dummy_file_ioctl);
		goto out1;
	}

	ioctl_param->p_id = getpid();

	ret_value = ioctl_set_vector(fd, ioctl_param);
	if (ret_value < 0) {
		printf("error\n");
		goto out1;
	}

	stack = (void **) malloc(65536);
	printf("Calling clone .. \n");
	clone_ret_value = syscall(329, SIGCHLD, 0, NULL, NULL, 0, child_vec_id);

	if (clone_ret_value == 0) {
		ioctl_param_child = (struct param *)malloc(sizeof(struct param));
		ioctl_param_child->p_id = child_pid;
		mkdir("clone_test", 777);
		list_child_pid = ioctl_param_child->p_id;

		sleep(10);

	} else if (clone_ret_value > 0) {
		child_pid = clone_ret_value;

		list_pid = ioctl_param->p_id;
		ioctl_list_vector_id(fd, &list_pid);
		sleep(10);
		printf("vector id of parent process : %d \n", list_pid);
		ret_value = ioctl_remove_vector(fd, ioctl_param);

		if (ret_value < 0)
			goto out1;

		ioctl_param_child = (struct param *) malloc(sizeof(struct param));
		ioctl_param_child->p_id = child_pid;

		list_child_pid = ioctl_param_child->p_id;
		ioctl_list_vector_id(fd, &list_child_pid);
		printf("vector id of child process %d \n", list_child_pid);
		ioctl_param_child->v_id = list_child_pid;

		ret_value = ioctl_remove_vector(fd, ioctl_param_child);
		if (ret_value < 0)
			goto out1;

		waitpid(clone_ret_value, &status, 0);
	}
	close(fd);

out1:
	if (dummy_file_ioctl)
		free(dummy_file_ioctl);
	if (ioctl_param)
		free(ioctl_param);
	if (ioctl_param_child)
		free(ioctl_param_child);
	if (stack)
		free(stack);

main_out:
	return ret_value;
}
