/* User Program to test custom vector 2 i
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

int main(int argc, char **argv)
{
	int fd;
	int fd_write;
	struct param *ioctl_param = NULL;
	int ret_value = 0;
	char *dummy_file_ioctl;
	char device[] = "/dev/ioctl_device";
	int vec_id;
	int list_pid;
	char *buf = "Data to test custom sys call write";

	if ((argc < 2) || ((((int)*argv[1]) - '0') >= 3) || (argc > 2)) {
		printf
		    ("Syntax to run: \n$/> ./testvector2 {vector_id} and vector-id range in [1,2]\n");
		goto main_out;
	}

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

	printf("ID of this process :%d \n", ioctl_param->p_id);

	ret_value = ioctl_set_vector(fd, ioctl_param);
	if (ret_value < 0) {
		printf("error\n");
		goto out1;
	}

	/*httpd */
	printf("wrapped system call mkdir is called \n ");
	mkdir("mkdir_test", 777);

	/*httpd */
	printf("wrapped system call chdir is called \n ");
	chdir("chdir_test");

	printf("wrapped system call rmdir is called \n ");
	rmdir("rmdir_test");

	printf("Wrapped system call chmod is called \n ");
	chmod("chdir_test", 777);

	/*http */
	printf("Wrapped system call rename is called \n ");
	rename("old_name_test.txt", "new_name_test.txt");

	ret_value = ioctl_remove_vector(fd, ioctl_param);
	if (ret_value < 0) {
		goto out1;
	}

	close(fd);
/*	close(fd_write);*/

out1:
	if (dummy_file_ioctl) {
		free(dummy_file_ioctl);
	}
	if (ioctl_param) {
		free(ioctl_param);
	}

main_out:
	return ret_value;
}
