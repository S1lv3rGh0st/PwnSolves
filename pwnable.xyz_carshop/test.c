#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int main() {
	const char* data = "Hello world";
	char data2[200] = {0};
	snprintf(data2, strlen(data), "%s", data);
	printf("%s\n", data2);
	return 0;
}