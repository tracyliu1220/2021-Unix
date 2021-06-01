#include "libmini.h"

void printint(int x) {
  if (x < 0) {
    write(1, "-", 1);
    x = -x;
  }
  char buf[100];
  int l = 0;
  if (x == 0) {
    write(1, "0\n", 2);
    return;
  }
  while (x) {
    buf[l] = '0' + x % 10;
    x /= 10;
    l++;
  }
  for (int i = 0; i < l / 2; i++) {
    char tmp = buf[i];
    buf[i] = buf[l - i - 1];
    buf[l - i - 1] = tmp;
  }
  buf[l] = '\n';
  write(1, buf, l + 1);
}


void signal_handler (int signum) {
  write(1, "hello\n", 6);
}

int main() {
  int ret;

  struct sigaction new_action, old_action;
  sigset_t sigset, old_sigset, empty_sigset;

  new_action.sa_handler = signal_handler;
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;

  // sigaction (SIGALRM, &new_action, &old_action);
  signal(SIGALRM, signal_handler);
  
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGALRM);
  // sigprocmask(SIG_BLOCK, &sigset, NULL);

	alarm(1);
	pause();


  sigaddset(&sigset, SIGALRM);
  sigdelset(&sigset, SIGALRM);
  sigfillset(&sigset);
  sigismember(&sigset, SIGALRM);
  write(1, "finish\n", 7);

  ret = sigpending(&sigset);
  printint(ret);
  printint(sigset);



	return 0;
}
