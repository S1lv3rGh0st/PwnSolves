#include <stdio.h>
#include <signal.h>

void sigint_handler(int x)
{
	printf("sigint_handler says Hi!\n");
}

void sigsegv_handler(int x)
{
	printf("Catched sigsegv signal\n");
	sigint_handler(x);
}

int trigger_sigsegv(int *b) {
	printf("Triggerring sigsegv...\n");
	return *b;
}

int main()
{
	/* Register the handler */
	signal(SIGINT, sigint_handler);
	signal(SIGSEGV, sigsegv_handler);
	printf("Entering infinite loop.\n");
	trigger_sigsegv(0);
	while(1);
}
