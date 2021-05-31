#include "libmini.h"

void signal_handler (int signum) {
  write(1, "hello\n", 6);
}

int main() {

  struct sigaction new_action, old_action;

  new_action.sa_handler = signal_handler;
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;

  sigaction (SIGALRM, &new_action, &old_action);

	alarm(1);
	pause();

  write(1, "finish\n", 7);
	return 0;
}
