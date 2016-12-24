/*
  User program to test the default functionality of parent and child process.
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

#define MAX_IOCTL_PATH_LENGTH 512

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

/* *  * Main program - ioctl functions called from here
 *   */
int main(int argc, char **argv)
{
	pid_t parent;
	pid_t pid;
	pid_t child_pid;
	int ret_val = 0;
	int fd;
	int status;

/*        if((argc < 2) || ((((int) *argv[1])-'0') >=6) || (argc > 2)) {*/
/*                printf("Syntax to run: \n$/> ./pass_ioctl {vector_id} and vector-id range in [0,5]\n");*/
/*                goto main_out;*/
/*        }*/

	char *dummy_file_ioctl;
	char device[] = "/dev/ioctl_device";

	dummy_file_ioctl = (char *)malloc(MAX_IOCTL_PATH_LENGTH);
	memset(dummy_file_ioctl, 0, MAX_IOCTL_PATH_LENGTH);
	memcpy(dummy_file_ioctl, device, strlen(device));

	fd = open(dummy_file_ioctl, 0);

	if (fd < 0) {
		printf("Can't open file: %s\n", dummy_file_ioctl);
		goto out1;
	}

	printf("ID of the parent process :%d \n", getpid());
	pid = fork();
	if (pid == 0) {
		child_pid = getpid();
		printf("pid of child process : %d \n ", child_pid);
		ioctl_list_vector_id(fd, &child_pid);
		printf("vector id of the child  process : %d \n", child_pid);
		sleep(5);

	} else if (pid > 0) {
		parent = getpid();
		ioctl_list_vector_id(fd, &pid);

		printf("vector id of the parent process : %d \n", pid);
		waitpid(pid, &status, 0);

	}
out1:
	if (fd > 0)
		close(fd);
	if (dummy_file_ioctl) {
		free(dummy_file_ioctl);
	}
}
