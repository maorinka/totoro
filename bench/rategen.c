/* Fork/exec /bin/true exactly RATE times/sec for SECS, using nanosleep
   (a syscall, not an exec) so the only execs the sensor sees are ours. */
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
int main(int c,char**v){
  int rate=atoi(v[1]), secs=atoi(v[2]);
  long ns=1000000000L/rate;
  struct timespec iv={ns/1000000000L, ns%1000000000L};
  long total=(long)rate*secs;
  for(long i=0;i<total;i++){
    pid_t p=fork();
    if(p==0){execl("/bin/true","true",(char*)0);_exit(0);}
    waitpid(p,0,0);
    nanosleep(&iv,0);
  }
  return 0;
}
