/* Runtime-mitigation mechanism demo (safe, self-contained).
 *
 * Verifies the core of io.security's "runtime vulnerability patching &
 * mitigation without redeployment": a RUNNING process has its vulnerable
 * function neutralised live -- the function entry is overwritten with the
 * same safe stub Wisp's patch.c writes (xor eax,eax; ret) -- and the process
 * keeps running, no restart. Build: cc -O0 -no-pie -fno-pic. Output shows
 * vulnerable() flip from 1 (EXPLOITABLE) to 0 (mitigated) mid-run.
 *
 * This patches the process's OWN code (self-modification) to demonstrate the
 * patch bytes and the no-restart property safely. In the agent, the same
 * stub is delivered to another process via ptrace (patch.c); that cross-
 * process injection path is dual-use and its demo is blocked by this
 * sandbox's RCE guard, but the mitigation itself is what this proves.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

/* The "CVE-ridden" code path: returns 1 (exploitable). */
int __attribute__((noinline)) vulnerable(void){ return 1; }

/* Apply the same stub Wisp's patch.c writes: xor eax,eax ; ret  (return 0). */
static int apply_patch(void *fn){
    uintptr_t page = (uintptr_t)fn & ~(uintptr_t)0xfff;
    if(mprotect((void*)page, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC)) return -1;
    unsigned char stub[]={0x31,0xc0,0xc3};   /* xor eax,eax ; ret */
    memcpy(fn, stub, sizeof stub);
    __builtin___clear_cache(fn,(char*)fn+16);
    return 0;
}

int main(void){
    for(int i=0;i<6;i++){
        if(i==3){
            printf("[wisp] runtime mitigation: patching vulnerable() live, no restart\n");
            apply_patch((void*)vulnerable);
        }
        printf("tick %d: vulnerable() -> %d  (%s)\n", i, vulnerable(),
               vulnerable()? "EXPLOITABLE" : "mitigated");
        fflush(stdout);
    }
    return 0;
}
