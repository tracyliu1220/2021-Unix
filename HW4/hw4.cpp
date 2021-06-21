#include <fstream>
#include <iostream>
#include <sstream>
#include <unistd.h>

#include "commands.h"

using namespace std;

ifstream fin;
string input_source;
map<string, int> cmd_id;

void init(int argc, char *argv[]) {
  input_source = "/dev/stdin";
  char ch;
  while ((ch = getopt(argc, argv, "s:")) != -1) {
    switch (ch) {
    case 's':
      input_source = optarg;
      break;
    }
  }
  if (optind < argc)
    program_name = argv[optind];
  fin.open(input_source.c_str(), ios::in);

  cmd_id["break"] = cmd_id["b"] = CMD_BREAK;
  cmd_id["cont"] = cmd_id["c"] = CMD_CONT;
  cmd_id["delete"] = CMD_DELETE;
  cmd_id["disasm"] = cmd_id["d"] = CMD_DISASM;
  cmd_id["dump"] = cmd_id["x"] = CMD_DUMP;
  cmd_id["exit"] = cmd_id["q"] = CMD_EXIT;
  cmd_id["get"] = cmd_id["g"] = CMD_GETREG;
  cmd_id["getregs"] = CMD_GETREGS;
  cmd_id["help"] = cmd_id["h"] = CMD_HELP;
  cmd_id["list"] = cmd_id["l"] = CMD_LIST;
  cmd_id["load"] = CMD_LOAD;
  cmd_id["run"] = cmd_id["r"] = CMD_RUN;
  cmd_id["vmmap"] = cmd_id["m"] = CMD_VMMAP;
  cmd_id["set"] = cmd_id["s"] = CMD_SETREG;
  cmd_id["si"] = CMD_SI;
  cmd_id["start"] = CMD_START;

  reg_offset["r15"] = 0;
  reg_offset["r14"] = 1;
  reg_offset["r13"] = 2;
  reg_offset["r12"] = 3;
  reg_offset["rbp"] = 4;
  reg_offset["rbx"] = 5;
  reg_offset["r11"] = 6;
  reg_offset["r10"] = 7;
  reg_offset["r9"] = 8;
  reg_offset["r8"] = 9;
  reg_offset["rax"] = 10;
  reg_offset["rcx"] = 11;
  reg_offset["rdx"] = 12;
  reg_offset["rsi"] = 13;
  reg_offset["rdi"] = 14;
  reg_offset["orig_rax"] = 15;
  reg_offset["rip"] = 16;
  reg_offset["cs"] = 17;
  reg_offset["eflags"] = 18;
  reg_offset["rsp"] = 19;
  reg_offset["fs_base"] = 20;
  reg_offset["gs_base"] = 21;
  reg_offset["ds"] = 22;
  reg_offset["es"] = 23;
  reg_offset["fs"] = 24;
  reg_offset["gs"] = 25;
}

int main(int argc, char *argv[]) {
  init(argc, argv);
  bool exit_flag = false;
  while (1) {
    cout << "sdb> ";
    cout.flush();
    string user_input, user_cmd;
    getline(fin, user_input);
    stringstream ss;
    ss << user_input;
    ss >> user_cmd;
    int user_cmd_id = -1;
    if (cmd_id.count(user_cmd))
      user_cmd_id = cmd_id[user_cmd];
    switch (user_cmd_id) {
    case CMD_BREAK:
      cmd_break(user_input);
      break;
    case CMD_CONT:
      cmd_cont(user_input);
      break;
    case CMD_DELETE:
      cmd_delete(user_input);
      break;
    case CMD_DISASM:
      cmd_disasm(user_input);
      break;
    case CMD_DUMP:
      cmd_dump(user_input);
      break;
    case CMD_EXIT:
      exit_flag = 1;
      break;
    case CMD_GETREG:
      cmd_getreg(user_input);
      break;
    case CMD_GETREGS:
      cmd_getregs(user_input);
      break;
    case CMD_HELP:
      cmd_help(user_input);
      break;
    case CMD_LIST:
      cmd_list(user_input);
      break;
    case CMD_LOAD:
      cmd_load(user_input);
      break;
    case CMD_RUN:
      cmd_run(user_input);
      break;
    case CMD_VMMAP:
      cmd_vmmap(user_input);
      break;
    case CMD_SETREG:
      cmd_setreg(user_input);
      break;
    case CMD_SI:
      cmd_si(user_input);
      break;
    case CMD_START:
      cmd_start(user_input);
      break;
    }
    if (exit_flag)
      break;
  }
}
