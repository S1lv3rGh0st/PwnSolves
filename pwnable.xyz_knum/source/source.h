#include "challenge.h"

state_s *game_state;
note_s *note;
score_record_s *score;
char *menu;
char *game_table;

void *cleanup_state()
{
  game_state->score_1 = 0;
  game_state->score_2 = 0;
  game_state->round = 1;
  game_state->player = 1;
  return memset(game_table, 0, 0xA0uLL);
}

void add_score(int pos, const char *name, int score_n, const char *comment)
{
  strcpy(score[pos].name, name);
  score[pos].scored = score_n;
  strcpy(score[pos].comment, comment);
}

void append_to_hiscore(int a1)
{
  int i; // [rsp+1Ch] [rbp-14h]
  void *name; // [rsp+20h] [rbp-10h]
  char *remark; // [rsp+28h] [rbp-8h]

  name = malloc(0x40uLL);
  remark = (char *)malloc(0x80uLL);
  memset(name, 0, 0x40uLL);
  memset(remark, 0, 0x80uLL);
  getchar();
  getchar();
  __printf_chk(1LL, "Enter your name (max 63 chars) : ");
  fgets((char *)name, 64, stdin);
  __printf_chk(1LL, "Enter a remark (max 127 chars) : ");
  fgets(remark, 128, stdin);
  if ( *((char *)name + strlen((const char *)name) - 1) == '\n' )
    *((char *)name + strlen((const char *)name) - 1) = 0;
  if ( remark[strlen(remark) - 1] == '\n' )
    remark[strlen(remark) - 1] = 0;
  for ( i = 0; i <= 9; ++i )
  {
    if ( a1 > score[i].scored )
    {
      add_score(i, (const char *)name, a1, remark);
      break;
    }
  }
  free(remark);
  free(name);
}

void summarize(int mine_score)
{
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 9; ++i )
  {
    if ( mine_score > score[i].scored ) {
      append_to_hiscore((unsigned int)mine_score);
      return;
    }
  }
  puts("You didn't make it in the hall of fame :(");
}

__int64 game_logic()
{
  int i; // [rsp+0h] [rbp-10h]
  int j; // [rsp+4h] [rbp-Ch]
  int k; // [rsp+8h] [rbp-8h]
  int m; // [rsp+Ch] [rbp-4h]

  putchar(10);
  __printf_chk(1LL, "Round %d\n\n", (unsigned int)game_state->round);
  for ( i = 0; i < 10; ++i )                    // Print table
  {
    __printf_chk(1LL, "%2d|", (unsigned int)(10 - i));
    for ( j = 0; j < 16; ++j )
      __printf_chk(1LL, "%4d", (unsigned __int8)game_table[16 * i + j]);
    puts("|");
  }
  __printf_chk(1LL, "  ");
  for ( k = 0; k < 66; ++k )
    putchar('-');
  __printf_chk(1LL, "\n   ");
  for ( m = 0; m < 16; ++m )
    __printf_chk(1LL, "%4d", (unsigned int)(m + 1));
  putchar(10);
  return __printf_chk(
           1LL,
           "\nPlayer 1: %d\t\tPlayer 2: %d\n\n",
           (unsigned int)game_state->score_1,
           (unsigned int)game_state->score_2);
}

__int64 some_crypto_empty()
{
  unsigned int v1; // [rsp+0h] [rbp-24h]
  int i; // [rsp+4h] [rbp-20h]
  int v3; // [rsp+8h] [rbp-1Ch]
  int j; // [rsp+Ch] [rbp-18h]
  int k; // [rsp+10h] [rbp-14h]
  int m; // [rsp+14h] [rbp-10h]
  int v7; // [rsp+18h] [rbp-Ch]
  int n; // [rsp+1Ch] [rbp-8h]
  int ii; // [rsp+20h] [rbp-4h]

  v1 = 0;
  for ( i = 0; i < 16; ++i )
  {
    v3 = 0;
    for ( j = 0; j < 10; ++j )
      v3 += *((unsigned __int8 *)game_table + 16 * j + i);
    if ( v3 == 1000 )
    {
      ++v1;
      for ( k = 0; k < 10; ++k )
        *((char *)game_table + 10 * k + i) = 0;
    }
  }
  for ( m = 0; m < 10; ++m )
  {
    v7 = 0;
    for ( n = 0; n < 16; ++n )
      v7 += *((unsigned __int8 *)game_table + 16 * m + n);
    if ( v7 == 1000 )
    {
      ++v1;
      for ( ii = 0; ii < 16; ++ii )
        *((char *)game_table + 10 * m + ii) = 0;
    }
  }
  return v1;
}

__int64 print_menu()
{
  __printf_chk(1LL, (const char *)game_state);
  return __printf_chk(1LL, menu);
}

void play_game()
{
  unsigned int coord_x; // [rsp+4h] [rbp-1Ch] BYREF
  unsigned int coord_y; // [rsp+8h] [rbp-18h] BYREF
  unsigned int to_put; // [rsp+Ch] [rbp-14h] BYREF
  int v4; // [rsp+10h] [rbp-10h]
  unsigned int v5; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v4 = 1;
  cleanup_state();
  while ( 1 )
  {
    coord_x = 0;
    coord_y = 0;
    to_put = 0;
    ((void (*)(void))game_state->game_logic)();
    while ( !coord_x && !coord_y || game_table[16 * coord_y + coord_x] )
    {
      __printf_chk(1LL, "Player %d - Enter your move (invalid input to end game)\n", (unsigned int)game_state->player);
      __printf_chk(1LL, "- Enter target field (x y): ");
      if ( (unsigned int)scanf("%d %d", &coord_x, &coord_y) != 2 )
      {
        v4 = 0;
        break;
      }
    }
    if ( !v4 )
      break;
    if ( coord_x > 0x10 || coord_y > 0xA )
    {
      puts("Invalid move...");
    }
    else
    {
      while ( !to_put || to_put > 0xFF )
      {
        __printf_chk(1LL, "- Enter the value you want to put there (< 255): ");
        scanf("%d", &to_put);
      }
      game_table[16 * (10 - coord_y) - 1 + coord_x] = to_put;
      v5 = some_crypto_empty();
      if ( (int)v5 > 0 )
      {
        __printf_chk(1LL, "You scored %d points!\n", v5);
        game_state->score_1 += v5;
      }
    }
    ++game_state->round;
  }
  summarize((unsigned int)game_state->score_1);
}

int print_score()
{
  int i; // [rsp+Ch] [rbp-4h]

  putchar(10);
  puts("Hall of fame - All time best knum players");
  puts("#################################################################");
  for ( i = 0; i <= 9; ++i )
  {
    __printf_chk(1LL, "%d. %s - %d\n\t", (unsigned int)(i + 1), score[i].name, (unsigned int)score[i].scored);
    __printf_chk(1LL, score[i].comment);
    putchar(10);
  }
  puts("#################################################################");
  return putchar(10);
}

void setup_score()
{
  if ( score )
    free(score);
  score = malloc(0x7A8uLL);
  add_score(0LL, "Kileak", 1000LL, "You cannot beat me in my own game, can you? :P");
  add_score(1LL, "vakzz", 999LL, "Expected a kernel pwn here :(");
  add_score(2LL, "uafio", 998LL, "My knum senses are tingling...");
  add_score(3LL, "grazfather", 997LL, "I hope you used gef to debug this shitty piece of software!");
  add_score(4LL, "rh0gue", 997LL, "I eat kbbq");
  add_score(5LL, "corb3nik", 996LL, "Where's my putine???");
  add_score(6LL, "reznok", 995LL, "Did anyone find the web interface by now?");
  add_score(7LL, "zer0", 3LL, "Will be a draw...");
  add_score(8LL, "Tuan Linh", 2LL, "how can I delete my message here???");
  add_score(
           9LL,
           "zophike1",
           1LL,
           "No time to play this game, have to do pwn2own and some kernel pwnz instead...");
}

int input_note()
{
  if ( note )
    return puts("You already sent me a note, that should be enough...");
  note = (note_s *)malloc(0x48uLL);
  __printf_chk(1LL, "Enter your note for me: ");
  fgets(note->data, 72, stdin);
  return puts("Thanks for your input :)");
}




__int64 game_entry()
{
  __int64 result; // rax
  char v1; // [rsp+Fh] [rbp-1h]

  while ( 1 )
  {
    print_menu();
    v1 = getchar();
    getchar();
    result = (unsigned int)(v1 - 49);
    switch ( v1 )
    {
      case '1':
        play_game();
        break;
      case '2':
        print_score();
        break;
      case '3':
        setup_score();
        break;
      case '4':
        input_note();
        break;
      case '5':
        return result;
      default:
        puts("Invalid option...");
        break;
    }
  }
}