#ifndef _SYS_PTRACE_H_
  #define _SYS_PTRACE_H_

  #include <sys/types.h>

  #define PT_TRACE_ME      0
  #define PT_READ_I        1
  #define PT_READ_D        2
  #define PT_READ_U        3
  #define PT_WRITE_I       4
  #define PT_WRITE_D       5
  #define PT_WRITE_U       6
  #define PT_CONTINUE      7
  #define PT_KILL          8
  #define PT_STEP          9
  #define PT_ATTACH        10
  #define PT_DETACH        11
  #define PT_SIGEXC        12
  #define PT_THUPDATE      13
  #define PT_ATTACHEXC     14
  #define PT_FORCEQUOTA    30
  #define PT_DENY_ATTACH   31
  #define PT_FIRSTMACH     32

  #ifdef __cplusplus
  extern "C" {
  #endif

  int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

  #ifdef __cplusplus
  }
  #endif

  #endif /* _SYS_PTRACE_H_ */
  