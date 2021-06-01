#include "libmini.h"

// extern void restorer();
// asm volatile("restorer:mov $15,%rax\nsyscall");

long errno;

#define __set_errno(val) (errno = (val))
#define WRAPPER_RETval(type)                                                   \
  errno = 0;                                                                   \
  if (ret < 0) {                                                               \
    errno = -ret;                                                              \
    return -1;                                                                 \
  }                                                                            \
  return ((type)ret);
#define WRAPPER_RETptr(type)                                                   \
  errno = 0;                                                                   \
  if (ret < 0) {                                                               \
    errno = -ret;                                                              \
    return NULL;                                                               \
  }                                                                            \
  return ((type)ret);

#define SET_SA_RESTORER(kact, act)                                             \
  (kact)->sa_flags = (act)->sa_flags | SA_RESTORER;                            \
  (kact)->sa_restorer = sys_rt_sigreturn
#define RESET_SA_RESTORER(act, kact) (act)->sa_restorer = (kact)->sa_restorer

#define __sigmask(sig)                                                         \
  (((unsigned long int)1) << (((sig)-1) % (8 * sizeof(unsigned long int))))

static inline int __is_internal_signal(int sig) {
  return (sig == SIGCANCEL) || (sig == SIGSETXID);
}

/* HW3 */

unsigned int alarm(unsigned int seconds) {
  long ret = sys_alarm(seconds);
  WRAPPER_RETval(unsigned int);
}

sighandler_t signal(int sig, sighandler_t handler) {
  struct sigaction act, oact;
  /* Check signal extents to protect __sigismember.  */
  if (handler == SIG_ERR || sig < 1 || sig >= NSIG
      || __is_internal_signal (sig))
    {
      __set_errno (EINVAL);
      return SIG_ERR;
    }
  act.sa_handler = handler;
  sigemptyset (&act.sa_mask);
  sigaddset (&act.sa_mask, sig);
  // act.sa_flags = __sigismember (&_sigintr, sig) ? 0 : SA_RESTART;
  if (sigaction (sig, &act, &oact) < 0)
    return SIG_ERR;
  return oact.sa_handler;
}


int sigaction(int sig, const struct sigaction *act, struct sigaction *oact) {
  int ret;
  struct kernel_sigaction kact, koact;
  if (act) {
    kact.k_sa_handler = act->sa_handler;
    memcpy(&kact.sa_mask, &act->sa_mask, sizeof(sigset_t));
    kact.sa_flags = act->sa_flags;
    SET_SA_RESTORER(&kact, act);
  }
  /* XXX The size argument hopefully will have to be changed to the
     real size of the user-level sigset_t.  */
  /*
  ret = INLINE_SYSCALL_CALL (rt_sigaction, sig,
                                act ? &kact : NULL,
                                oact ? &koact : NULL, STUB (act, _NSIG / 8));
  */
  ret = sys_rt_sigaction(sig, act ? &kact : NULL, oact ? &koact : NULL,
                         sizeof(sigset_t));
  if (oact && ret >= 0) {
    oact->sa_handler = koact.k_sa_handler;
    memcpy(&oact->sa_mask, &koact.sa_mask, sizeof(sigset_t));
    oact->sa_flags = koact.sa_flags;
    RESET_SA_RESTORER(oact, &koact);
  }
  WRAPPER_RETval(int);
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  sigset_t _set;
  memcpy(&_set, set, sizeof(_set));
  long ret = sys_rt_sigprocmask(how, &_set, oldset, sizeof(sigset_t));
  WRAPPER_RETval(int);
}



int sigpending(sigset_t *set) {
  long ret = sys_rt_sigpending(set, sizeof(sigset_t));
  WRAPPER_RETval(int);
}

int sigemptyset(sigset_t *set) {
  if (set == NULL) {
    __set_errno(EINVAL);
    return -1;
  }
  memset(set, 0, sizeof(sigset_t));
  return 0;
}

int sigfillset(sigset_t *set) {
  if (set == NULL) {
    __set_errno(EINVAL);
    return -1;
  }
  memset(set, 0xff, sizeof(sigset_t));
  sigdelset(set, SIGCANCEL);
  sigdelset(set, SIGSETXID);
  return 0;
}

int sigaddset(sigset_t *set, int signo) {
  if (set == NULL || signo <= 0 || signo >= NSIG ||
      __is_internal_signal(signo)) {
    __set_errno(EINVAL);
    return -1;
  }
  // __sigaddset(set, signo);
  (*set) |= __sigmask(signo);
  return 0;
}

int sigdelset(sigset_t *set, int signo) {
  if (set == NULL || signo <= 0 || signo >= NSIG ||
      __is_internal_signal(signo)) {
    __set_errno(EINVAL);
    return -1;
  }
  (*set) &= ~__sigmask(signo);
  // __sigdelset(set, signo);
  return 0;
}

int sigismember(const sigset_t *set, int signo) {
  if (set == NULL || signo <= 0 || signo >= NSIG) {
    __set_errno(EINVAL);
    return -1;
  }
  return ((*set) & signo) ? 1 : 0;
}


void sigreturn(void) { sys_rt_sigreturn(); }

/* utils */

void *memset(void *dest, int val, size_t len) {
  unsigned char *ptr = dest;
  while (len-- > 0)
    *ptr++ = val;
  return dest;
}

void *memcpy(void *dest, const void *src, size_t len) {
  char *d = dest;
  const char *s = src;
  while (len--)
    *d++ = *s++;
  return dest;
}

/* rest */

ssize_t read(int fd, char *buf, size_t count) {
  long ret = sys_read(fd, buf, count);
  WRAPPER_RETval(ssize_t);
}

ssize_t write(int fd, const void *buf, size_t count) {
  long ret = sys_write(fd, buf, count);
  WRAPPER_RETval(ssize_t);
}

/* open is implemented in assembly, because of variable length arguments */

int close(unsigned int fd) {
  long ret = sys_close(fd);
  WRAPPER_RETval(int);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
  long ret = sys_mmap(addr, len, prot, flags, fd, off);
  WRAPPER_RETptr(void *);
}

int mprotect(void *addr, size_t len, int prot) {
  long ret = sys_mprotect(addr, len, prot);
  WRAPPER_RETval(int);
}

int munmap(void *addr, size_t len) {
  long ret = sys_munmap(addr, len);
  WRAPPER_RETval(int);
}

int pipe(int *filedes) {
  long ret = sys_pipe(filedes);
  WRAPPER_RETval(int);
}

int dup(int filedes) {
  long ret = sys_dup(filedes);
  WRAPPER_RETval(int);
}

int dup2(int oldfd, int newfd) {
  long ret = sys_dup2(oldfd, newfd);
  WRAPPER_RETval(int);
}

int pause() {
  long ret = sys_pause();
  WRAPPER_RETval(int);
}

int nanosleep(struct timespec *rqtp, struct timespec *rmtp) {
  long ret = sys_nanosleep(rqtp, rmtp);
  WRAPPER_RETval(int);
}

pid_t fork(void) {
  long ret = sys_fork();
  WRAPPER_RETval(pid_t);
}

void exit(int error_code) {
  sys_exit(error_code);
  /* never returns? */
}

char *getcwd(char *buf, size_t size) {
  long ret = sys_getcwd(buf, size);
  WRAPPER_RETptr(char *);
}

int chdir(const char *pathname) {
  long ret = sys_chdir(pathname);
  WRAPPER_RETval(int);
}

int rename(const char *oldname, const char *newname) {
  long ret = sys_rename(oldname, newname);
  WRAPPER_RETval(int);
}

int mkdir(const char *pathname, int mode) {
  long ret = sys_mkdir(pathname, mode);
  WRAPPER_RETval(int);
}

int rmdir(const char *pathname) {
  long ret = sys_rmdir(pathname);
  WRAPPER_RETval(int);
}

int creat(const char *pathname, int mode) {
  long ret = sys_creat(pathname, mode);
  WRAPPER_RETval(int);
}

int link(const char *oldname, const char *newname) {
  long ret = sys_link(oldname, newname);
  WRAPPER_RETval(int);
}

int unlink(const char *pathname) {
  long ret = sys_unlink(pathname);
  WRAPPER_RETval(int);
}

ssize_t readlink(const char *path, char *buf, size_t bufsz) {
  long ret = sys_readlink(path, buf, bufsz);
  WRAPPER_RETval(ssize_t);
}

int chmod(const char *filename, mode_t mode) {
  long ret = sys_chmod(filename, mode);
  WRAPPER_RETval(int);
}

int chown(const char *filename, uid_t user, gid_t group) {
  long ret = sys_chown(filename, user, group);
  WRAPPER_RETval(int);
}

int umask(int mask) {
  long ret = sys_umask(mask);
  WRAPPER_RETval(int);
}

int gettimeofday(struct timeval *tv, struct timezone *tz) {
  long ret = sys_gettimeofday(tv, tz);
  WRAPPER_RETval(int);
}

uid_t getuid() {
  long ret = sys_getuid();
  WRAPPER_RETval(uid_t);
}

gid_t getgid() {
  long ret = sys_getgid();
  WRAPPER_RETval(uid_t);
}

int setuid(uid_t uid) {
  long ret = sys_setuid(uid);
  WRAPPER_RETval(int);
}

int setgid(gid_t gid) {
  long ret = sys_setgid(gid);
  WRAPPER_RETval(int);
}

uid_t geteuid() {
  long ret = sys_geteuid();
  WRAPPER_RETval(uid_t);
}

gid_t getegid() {
  long ret = sys_getegid();
  WRAPPER_RETval(uid_t);
}

void bzero(void *s, size_t size) {
  char *ptr = (char *)s;
  while (size-- > 0)
    *ptr++ = '\0';
}

size_t strlen(const char *s) {
  size_t count = 0;
  while (*s++)
    count++;
  return count;
}

#define PERRMSG_MIN 0
#define PERRMSG_MAX 34

static const char *errmsg[] = {"Success",
                               "Operation not permitted",
                               "No such file or directory",
                               "No such process",
                               "Interrupted system call",
                               "I/O error",
                               "No such device or address",
                               "Argument list too long",
                               "Exec format error",
                               "Bad file number",
                               "No child processes",
                               "Try again",
                               "Out of memory",
                               "Permission denied",
                               "Bad address",
                               "Block device required",
                               "Device or resource busy",
                               "File exists",
                               "Cross-device link",
                               "No such device",
                               "Not a directory",
                               "Is a directory",
                               "Invalid argument",
                               "File table overflow",
                               "Too many open files",
                               "Not a typewriter",
                               "Text file busy",
                               "File too large",
                               "No space left on device",
                               "Illegal seek",
                               "Read-only file system",
                               "Too many links",
                               "Broken pipe",
                               "Math argument out of domain of func",
                               "Math result not representable"};

void perror(const char *prefix) {
  const char *unknown = "Unknown";
  long backup = errno;
  if (prefix) {
    write(2, prefix, strlen(prefix));
    write(2, ": ", 2);
  }
  if (errno < PERRMSG_MIN || errno > PERRMSG_MAX)
    write(2, unknown, strlen(unknown));
  else
    write(2, errmsg[backup], strlen(errmsg[backup]));
  write(2, "\n", 1);
  return;
}

#if 0 /* we have an equivalent implementation in assembly */
unsigned int sleep(unsigned int seconds) {
	long ret;
	struct timespec req, rem;
	req.tv_sec = seconds;
	req.tv_nsec = 0;
	ret = sys_nanosleep(&req, &rem);
	if(ret >= 0) return ret;
	if(ret == -EINTR) {
		return rem.tv_sec;
	}
	return 0;
}
#endif
