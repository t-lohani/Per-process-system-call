#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "ioctl.h"

int main(int argc, char *argv[])
{

	int fd;
	char ioctl_device[25] = "/dev/ioctl_device";
	char *ptr;
	int ret;
	struct param *test = NULL;

	unsigned long v_id;
	unsigned long p_id;

	fd = open(ioctl_device, 0);
	if (fd < 0) {
		printf("Failed to open:%s \n", ioctl);
		exit(1);
	}
	test = malloc(sizeof(struct param));
	if (test == NULL) {
		printf("malloc failed\n");
		goto out1;
	}

	if (argc != 2 && argc != 3 && argc != 4) {
		printf("Error : Usage: Any of the Following Four Options\n");
		printf("./uioctl SET [Vector_ID] [P_ID]\n");
		printf("./uioctl REMOVE [Vector_ID] [P_ID]\n");
		printf("./uioctl VECTORS \n");
		printf("./uioctl VECTOR_ID [P_ID] \n");

		goto out;
	}
	if (argc == 3) {

		p_id = strtoul(argv[2], &ptr, 10);

		if (p_id == 0) {
			printf
			    ("Wrong P_ID entered. Enter Positive Numeric Value\n");
			goto out;
		}

		if (strcmp(argv[1], "VECTOR_ID") == 0 && p_id > 0) {
			printf("P_ID: %d\n", p_id);

			ret = ioctl(fd, LIST_ID, &p_id);

			if (ret == 0) {
				printf("Vector_ID of the Process: %d\n", p_id);
			} else {
				printf("Error! in LIST_ID\n");

			}

		} else {
			printf("Wrong Input Entered\n");
		}

	}

	else if (argc == 2) {

		if (strcmp(argv[1], "VECTORS") == 0) {
			ret = ioctl(fd, LIST_VECTOR, 0);
			if (ret > 0) {
				printf
				    ("Open /tmp/vector.txt  to see the list of the vectors loaded\n");
			} else {
				printf("Error in LIST_VECTOR\n");
			}
		} else {
			printf("Wrong Input Entered\n");
		}

	} else if (argc == 4) {
		v_id = strtoul(argv[2], &ptr, 10);

		if (v_id == 0) {
			printf
			    ("Wrong V_ID entered. Enter Positive Numeric Value\n");
			goto out;
		}

		p_id = strtoul(argv[3], &ptr, 10);

		if (p_id == 0) {
			printf
			    ("Wrong P_ID Entered. Enter Positive Numeric Value\n");
			goto out;
		}

		if (strcmp(argv[1], "SET") == 0 && p_id > 0 && v_id > 0) {

			printf("P_ID: %d\n", p_id);
			printf("V_ID: %d\n", v_id);
			test->v_id = v_id;
			test->p_id = p_id;

			ret = ioctl(fd, SET_IOCTL, test);
			if (ret == 0) {
				printf
				    ("Vector set for the Process Successfully\n");
			} else {
				printf
				    ("SET_IOCTL Failed. Was not able to set vector\n");
			}

		} else if (strcmp(argv[1], "REMOVE") == 0 && p_id > 0
			   && v_id > 0) {

			printf("P_ID: %d\n", p_id);
			printf("V_ID: %d\n", v_id);
			test->v_id = v_id;
			test->p_id = p_id;

			ret = ioctl(fd, REMOVE_IOCTL, test);
			if (ret == 0) {
				printf
				    ("Vector removed for the Process Successfully\n");
			} else {
				printf
				    ("remove_IOCTL Failed. Was not able to remove vector\n");
			}

		} else {
			printf("Wrong Input Passed. Try again\n");
		}
	}

out:
	free(test);
out1:
	close(fd);
	return 0;

}
