#ifndef CHALLENGE_INCLUDED
#define CHALLENGE_INCLUDED

#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

struct _IO_FILE;
struct _IO_marker;

/* 1 */
// struct __attribute__((aligned(8))) Elf64_Sym
// {
//   unsigned __int32 st_name;
//   unsigned __int8 st_info;
//   unsigned __int8 st_other;
//   unsigned __int16 st_shndx;
//   unsigned __int64 st_value;
//   unsigned __int64 st_size;
// };

// /* 2 */
// struct Elf64_Rela
// {
//   unsigned __int64 r_offset;
//   unsigned __int64 r_info;
//   __int64 r_addend;
// };

// /* 3 */
// struct Elf64_Dyn
// {
//   unsigned __int64 d_tag;
//   unsigned __int64 d_un;
// };

// /* 4 */
// struct __attribute__((aligned(4))) Elf64_Verneed
// {
//   unsigned __int16 vn_version;
//   unsigned __int16 vn_cnt;
//   unsigned __int32 vn_file;
//   unsigned __int32 vn_aux;
//   unsigned __int32 vn_next;
// };

// /* 5 */
// struct __attribute__((aligned(4))) Elf64_Vernaux
// {
//   unsigned __int32 vna_hash;
//   unsigned __int16 vna_flags;
//   unsigned __int16 vna_other;
//   unsigned __int32 vna_name;
//   unsigned __int32 vna_next;
// };

// /* 6 */
// typedef struct _IO_FILE FILE;

// /* 9 */
// typedef __int64 __off_t;

// /* 10 */
// typedef void _IO_lock_t;

// /* 11 */
// typedef __int64 __off64_t;

//  12 
// typedef unsigned __int64 size_t;

// /* 7 */
// struct _IO_FILE
// {
//   int _flags;
//   char *_IO_read_ptr;
//   char *_IO_read_end;
//   char *_IO_read_base;
//   char *_IO_write_base;
//   char *_IO_write_ptr;
//   char *_IO_write_end;
//   char *_IO_buf_base;
//   char *_IO_buf_end;
//   char *_IO_save_base;
//   char *_IO_backup_base;
//   char *_IO_save_end;
//   struct _IO_marker *_markers;
//   struct _IO_FILE *_chain;
//   int _fileno;
//   int _flags2;
//   __off_t _old_offset;
//   unsigned __int16 _cur_column;
//   signed __int8 _vtable_offset;
//   char _shortbuf[1];
//   _IO_lock_t *_lock;
//   __off64_t _offset;
//   void *__pad1;
//   void *__pad2;
//   void *__pad3;
//   void *__pad4;
//   size_t __pad5;
//   int _mode;
//   char _unused2[20];
// };

// /* 8 */
// struct _IO_marker
// {
//   struct _IO_marker *_next;
//   struct _IO_FILE *_sbuf;
//   int _pos;
// };

// /* 13 */
// struct __va_list_tag
// {
//   unsigned int gp_offset;
//   unsigned int fp_offset;
//   void *overflow_arg_area;
//   void *reg_save_area;
// };

// /* 14 */
// typedef __va_list_tag gcc_va_list[1];

/* 15 */
typedef struct 
{
  char name[64];
  int scored;
  char comment[128];
} score_record_s;

/* 16 */
typedef struct 
{
  char game_name[16];
  int round;
  int score_1;
  int score_2;
  int player;
  __int64 game_logic;
} state_s;

/* 17 */
typedef struct 
{
  char data[72];
} note_s;

#endif //CHALLENGE_INCLUDED