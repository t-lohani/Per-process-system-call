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

/* Functions to remove and set ioctl vectors*/

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
		printf("ioctl_set_vector failed:%d %d %d \n", errno, fd,
		       ret_value);
		perror("ERROR ");
	}

	return ret_value;
}

int ioctl_list_vector_id(int fd, int *p_id)
{
	int ret_value = 0;

	ret_value = ioctl(fd, LIST_ID, p_id);
	if (ret_value < 0) {
		printf("ioctl_list_vector failed:%d %d %d \n", errno, fd,
		       ret_value);
		perror("ERROR ");
	}

	return ret_value;
}

clone_body(void *arg)
{
	int ret1 = 0;
	printf("Child process ID : %d\n", getpid());
	ret1 = open("test_clone", 66, 77);
	_exit(0);
}

/**  * Main program - ioctl functions called from here
 *   */
int main(int argc, char **argv)
{
	int child_id = -1;
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
	int status = 0;
	int clone_ret_value = 0;
	int list_pid = 0;
	int list_child_pid = 0;

	if ((argc < 3) || ((((int)*argv[1]) - '0') >= 6) || (argc > 3)) {
		printf
		    ("Syntax to run: \n$/> ./pass_ioctl {vector_id} and vector-id range in [0,5]\n");
		goto main_out;
	}
	user_clone_flag = *argv[2];
	if (user_clone_flag != 'Y' && user_clone_flag != 'N') {
		printf(" enter either Y or N  \n");
		goto main_out;
	}

	printf("Parent process id : %d \n ", getpid());

	dummy_file_ioctl = (char *)malloc(MAX_IOCTL_PATH_LENGTH);
	memset(dummy_file_ioctl, 0, MAX_IOCTL_PATH_LENGTH);
	memcpy(dummy_file_ioctl, device, strlen(device));

	ioctl_param = (struct param *)malloc(sizeof(struct param));
	ioctl_param->v_id = (int)*argv[1];
	ioctl_param->v_id = ioctl_param->v_id - '0';

	printf("Vector id passed : %d\n", ioctl_param->v_id);
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

	stack = (void **)malloc(65536);
	printf("Calling clone .. \n");

	if (user_clone_flag == 'Y')
		clone_ret_value =
		    clone(&clone_body, stack + 6553,
			  SIGCHLD | CLONE_FILES | CLONE_VM | CLONE_SYSCALLS,
			  NULL);
	else
		clone_ret_value =
		    clone(&clone_body, stack + 6553,
			  SIGCHLD | CLONE_FILES | CLONE_VM, NULL);

	if (clone_ret_value < 0) {
		printf("ERROR:  Ret of clone is negative\n\n");
	}

	ioctl_param_child = (struct param *)malloc(sizeof(struct param));

	ioctl_param_child->p_id = clone_ret_value;

	list_pid = ioctl_param->p_id;
	list_child_pid = ioctl_param_child->p_id;

	ioctl_list_vector_id(fd, &list_pid);
	ioctl_list_vector_id(fd, &list_child_pid);

	printf("vector id of parent process : %d \n", list_pid);
	printf("vector id of child process : %d \n", list_child_pid);
	wpid = wait(&status);

	sleep(20);

	ret_value = ioctl_remove_vector(fd, ioctl_param);
	if (ret_value < 0) {
		goto out1;
	}

	close(fd);

out1:
	if (dummy_file_ioctl) {
		free(dummy_file_ioctl);
	}
	if (ioctl_param) {
		free(ioctl_param);
	}
	if (ioctl_param_child) {
		free(ioctl_param_child);
	}
	if (stack) {
		free(stack);
	}

main_out:
	return ret_value;
}
