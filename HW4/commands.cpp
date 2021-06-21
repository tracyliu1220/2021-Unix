#include "commands.h"
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  uint8_t e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} Elf32Hdr;

typedef struct {
  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  uint64_t sh_addr;
  uint64_t sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;
} Elf32SectHdr;

int loaded = 0;
int running = 0;
string program_name;
string program_exec;
int program_pid = -1;
map<string, int> reg_offset;
unsigned long text_offset;
unsigned long text_size;

void wait_tracee() {
  int status;
  waitpid(program_pid, &status, 0);
  if (WTERMSIG(status) == SIGTRAP) { // TODO
    cout << "** break point" << endl;
  }
  if (WIFEXITED(status)) {
    cout << "** child process " << dec << program_pid << " terminiated (code "
         << WEXITSTATUS(status) << ")" << endl;
  }
}

void get_text_info(unsigned long *offset, unsigned long *size) {
  FILE *ElfFile = NULL;
  char *SectNames = NULL;
  Elf32Hdr elfHdr;
  Elf32SectHdr sectHdr;
  uint idx;

  ElfFile = fopen(program_name.c_str(), "r");

  // read ELF header
  fread(&elfHdr, 1, sizeof elfHdr, ElfFile);

  // read section name string table
  // first, read its header
  fseek(ElfFile, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof sectHdr, SEEK_SET);
  fread(&sectHdr, 1, sizeof sectHdr, ElfFile);

  // next, read the section, string data
  SectNames = (char *)malloc(sectHdr.sh_size);
  fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
  fread(SectNames, 1, sectHdr.sh_size, ElfFile);

  // read all section headers
  for (idx = 0; idx < elfHdr.e_shnum; idx++) {
    const char *name = "";

    fseek(ElfFile, elfHdr.e_shoff + idx * sizeof sectHdr, SEEK_SET);
    fread(&sectHdr, 1, sizeof sectHdr, ElfFile);

    // print section name
    if (!sectHdr.sh_name)
      continue;
    name = SectNames + sectHdr.sh_name;
    if (strncmp(name, ".text", 5) == 0) {
      *offset = sectHdr.sh_addr;
      *size = sectHdr.sh_size;
      break;
    }
  }
}

// void cmd_break(string input);
void cmd_cont(string input) {
  if (!running) {
    cout << "** program " << program_name << " is not running." << endl;
    return;
  }

  int status;
  ptrace(PTRACE_CONT, program_pid, 0, 0);
  // waitpid(program_pid, &status, 0);
  wait_tracee();
}

// void cmd_delete(string input);
// void cmd_disasm(string input);

void cmd_dump(string input) {
  stringstream ss;
  ss << input;
  string cmd;
  ss >> cmd;
  unsigned long addr;
  if (!(ss >> hex >> addr)) {
    cout << "** no addr is given." << endl;
    return;
  }

  for (int i = 0; i < 5; i++) {
      if (addr + 16 * i + 15 < text_offset || addr + 16 * i >= text_offset + text_size) continue;
      
      cout << hex << addr + 16 * i << ": ";

      unsigned long text_val1 = ptrace(PTRACE_PEEKTEXT, program_pid, addr + 16 * i, 0);
      unsigned char *ptr1 = (unsigned char*)&text_val1;
      for (int j = 0; j < 8; j++) {
        unsigned long _addr = addr + 16 * i + j;
        if (_addr < text_offset || _addr >= text_offset + text_size) cout << "   ";
        else cout << hex << setfill('0') << setw(2) << (int)ptr1[j] << ' ';
      }

      unsigned long text_val2 = ptrace(PTRACE_PEEKTEXT, program_pid, addr + 16 * i + 8, 0);
      unsigned char *ptr2 = (unsigned char*)&text_val2;
      for (int j = 0; j < 8; j++) {
        unsigned long _addr = addr + 16 * i + 8 + j;
        if (_addr < text_offset || _addr >= text_offset + text_size) cout << "   ";
        else cout << hex << setfill('0') << setw(2) << (int)ptr2[j] << ' ';
      }

      cout << '|';
      for (int j = 0; j < 8; j++) {
          unsigned long _addr = addr + 16 * i + j;
          if (_addr < text_offset || _addr >= text_offset + text_size) {
              cout << ' ';
              continue;
          }
          if (isprint(ptr1[j])) cout << ptr1[j];
          else cout << '.';
      }
      for (int j = 0; j < 8; j++) {
          unsigned long _addr = addr + 16 * i + 8 + j;
          if (_addr < text_offset || _addr >= text_offset + text_size) {
              cout << ' ';
              continue;
          }
          if (isprint(ptr2[j])) cout << ptr2[j];
          else cout << '.';
      }
      cout << '|';

      cout << endl;
  }

}

void cmd_getreg(string input) {
  stringstream ss;
  ss << input;
  string cmd, tar_reg;
  ss >> cmd;
  ss >> tar_reg;
  unsigned long reg_val = ptrace(PTRACE_PEEKUSER, program_pid,
                                 reg_offset[tar_reg] * sizeof(long), 0);
  cout << tar_reg << " = " << dec << reg_val << " (0x" << hex << reg_val << ")"
       << endl;
}

void cmd_getregs(string input) {
  struct user_regs_struct data;
  int ret = ptrace(PTRACE_GETREGS, program_pid, 0, &data);
  cout << "RAX " << hex << data.rax << "\t";
  cout << "RBX " << hex << data.rbx << "\t";
  cout << "RCX " << hex << data.rcx << "\t";
  cout << "RDX " << hex << data.rdx << endl;
  cout << "R8  " << hex << data.r8 << "\t";
  cout << "R9  " << hex << data.r9 << "\t";
  cout << "R10 " << hex << data.r10 << "\t";
  cout << "R11 " << hex << data.r11 << endl;
  cout << "R12 " << hex << data.r12 << "\t";
  cout << "R13 " << hex << data.r13 << "\t";
  cout << "R14 " << hex << data.r14 << "\t";
  cout << "R15 " << hex << data.r15 << endl;
  cout << "RDI " << hex << data.rdi << "\t";
  cout << "RSI " << hex << data.rsi << "\t";
  cout << "RBP " << hex << data.rbp << "\t";
  cout << "RSP " << hex << data.rsp << endl;
  cout << "RIP " << hex << data.rip << "\t";
  cout << "FLAGS " << setfill('0') << setw(16) << hex << data.eflags << endl;
}

void cmd_help(string input) {
  cout << "- break {instruction-address}: add a break point\n";
  cout << "- cont: continue execution\n";
  cout << "- delete {break-point-id}: remove a break point\n";
  cout << "- disasm addr: disassemble instructions in a file or a memory "
          "region\n";
  cout << "- dump addr [length]: dump memory content\n";
  cout << "- exit: terminate the debugger\n";
  cout << "- get reg: get a single value from a register\n";
  cout << "- getregs: show registers\n";
  cout << "- help: show this message\n";
  cout << "- list: list break points\n";
  cout << "- load {path/to/a/program}: load a program\n";
  cout << "- run: run the program\n";
  cout << "- vmmap: show memory layout\n";
  cout << "- set reg val: get a single value to a register\n";
  cout << "- si: step into instruction\n";
  cout << "- start: start the program and stop at the first instruction"
       << endl;
}
// void cmd_list(string input);

void cmd_load(string input) {
  if (loaded) {
    cout << "** program already loaded." << endl;
    return;
  }
  stringstream ss;
  ss << input;
  string cmd;
  ss >> cmd;
  if (!(ss >> program_name)) {
    cout << "** no program given." << endl;
    return;
  }
  if (program_name[0] != '/')
    program_exec = "./" + program_name;
  else
    program_exec = program_name;
  int fd = open(program_name.c_str(), O_RDONLY);
  lseek(fd, 24, SEEK_SET);
  long entry;
  read(fd, &entry, 8);
  close(fd);
  get_text_info(&text_offset, &text_size);
  // cout << "** text: " << hex << "0x" << text_offset << " 0x" << text_size
  //      << endl;
  cout << "** program '" << program_name << "' loaded. entry point 0x" << hex
       << entry << endl;
  loaded = 1;
}

void cmd_run(string) {
  if (running) {
    cout << "** program " << program_name << " is already running." << endl;
    return;
  }
  running = 1;
  int child = fork();
  if (child == 0) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execlp(program_exec.c_str(), program_exec.c_str(), NULL);
  } else {
    int status;
    program_pid = child;
    cout << "** pid " << dec << program_pid << endl;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
    ptrace(PTRACE_CONT, child, 0, 0);
    wait_tracee();
  }
}
void cmd_vmmap(string input) {
  string str_pid;
  stringstream ss;
  ss << program_pid;
  ss >> str_pid;
  ifstream fin("/proc/" + str_pid + "/maps");
  string line;
  while (getline(fin, line)) {
    stringstream ss;
    ss << line;
    string tmp;
    ss >> tmp;
    cout << tmp << '\t';
    ss >> tmp;
    cout << tmp << '\t';
    ss >> tmp;
    ss >> tmp;
    ss >> tmp;
    cout << tmp << '\t';
    ss >> tmp;
    cout << tmp << endl;
    ;
  }
}

void cmd_setreg(string input) {
  stringstream ss;
  ss << input;
  string cmd, tar_reg;
  unsigned long val;
  ss >> cmd;
  ss >> tar_reg;
  ss >> val;
  ptrace(PTRACE_POKEUSER, program_pid, reg_offset[tar_reg] * sizeof(long), val);
}
// void cmd_si(string input);

void cmd_start(string input) {
  running = 1;
  int child = fork();
  if (child == 0) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execlp(program_exec.c_str(), program_exec.c_str(), NULL);
  } else {
    int status;
    program_pid = child;
    cout << "** pid " << dec << program_pid << endl;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
  }
}
