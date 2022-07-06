#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "challenge.h"
#include "source.h"


void init_game()
{
  unsigned int v0; // eax

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  // signal(14, handler);
  // alarm(0xF0u);
  v0 = time(0LL);
  srand(v0);
}

state_s *init_constants()
{
  char *v0; // rax
  state_s *result; // rax

  game_table = malloc(0xA0uLL);
  setup_score();
  game_state = (state_s *)malloc(0x28uLL);
  game_state->score_1 = 0;
  game_state->score_2 = 0;
  game_state->game_logic = (__int64)game_logic;
  menu = (char *)malloc(0xC8uLL);
  memset(menu, 0, 0xC8uLL);
  v0 = menu;
  strcpy(menu, "1.Play a game\n2. Show hiscore\n3. Reset hiscore\n4. Drop me a note\n5. Exit\n");
  result = game_state;
  strcpy(game_state->game_name, "KNUM v.01\n");
  return result;
}

int print_header()
{
  putchar(10);
  __printf_chk(1LL, "KNUM v0.1 (alpha release)");
  putchar(10);
  puts("Congratulations, you've been invited to the alpha test of knum v0.1");
  puts("Keep in mind, that this is an alpha version and computer ai hasn't been");
  puts("implemented yet, so you can only test the scoring system by now.");
  return putchar(10);
}



__int64 main(__int64 a1, char **a2, char **a3)
{
  init_game();
  init_constants(a1);
  print_header(a1);
  game_entry(a1);
  return 0LL;
}



