#include <stdlib.h>
#include <stdio.h>


int main() {
	char* data = malloc(100);
	for (char i=1; i<100; i++) {
		data[i-1] = i;
	}
	free(0x13);

	malloc(200);
	free(data);
	return 0;
}