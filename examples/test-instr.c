#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef TEST_SHARED_OBJECT
  #define main main_exported
#endif

int main(int argc, char **argv) {

  int   fd = 0, cnt;
  char  buff[8];
  char *buf = buff;

  // 支持命令行参数或标准输入两种输入方式
  if (argc == 2) {

    buf = argv[1];

  } else {

    if (argc >= 3 && strcmp(argv[1], "-f") == 0) {

      if ((fd = open(argv[2], O_RDONLY)) < 0) {

        fprintf(stderr, "Error: unable to open %s\n", argv[2]);
        exit(-1);

      }

    }

    if ((cnt = read(fd, buf, sizeof(buf) - 1)) < 1) {

      printf("Hum?\n");
#ifdef EXIT_AT_END
      exit(1);
#else
      return 1;
#endif

    }

    buf[cnt] = 0;

  }

  if (getenv("AFL_DEBUG")) fprintf(stderr, "test-instr: %s\n", buf);

  // 支持三种输入情况（若使用 stdin 但无输入，则为第四种情况）
  switch (buf[0]) {

    case '0':
      printf("Looks like a zero to me!\n");
      break;

    case '1':
      printf("Pretty sure that is a one!\n");
      break;

    default:
      printf("Neither one or zero? How quaint!\n");
      break;

  }

#ifdef EXIT_AT_END
  exit(0);
#endif

  return 0;

}
