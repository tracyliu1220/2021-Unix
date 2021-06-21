#ifndef COMMANDS_H
#define COMMANDS_H
#include <map>
using namespace std;

#define CMD_BREAK 0
#define CMD_CONT 1
#define CMD_DELETE 2
#define CMD_DISASM 3
#define CMD_DUMP 4
#define CMD_EXIT 5
#define CMD_GETREG 6
#define CMD_GETREGS 7
#define CMD_HELP 8
#define CMD_LIST 9
#define CMD_LOAD 10
#define CMD_RUN 11
#define CMD_VMMAP 12
#define CMD_SETREG 13
#define CMD_SI 14
#define CMD_START 15

extern map<string, int> cmd_id;
extern map<string, int> reg_offset;
extern string program_name;

void cmd_break(string);
void cmd_cont(string);
void cmd_delete(string);
void cmd_disasm(string);
void cmd_dump(string);
void cmd_exit(string);
void cmd_getreg(string);
void cmd_getregs(string);
void cmd_help(string);
void cmd_list(string);
void cmd_load(string);
void cmd_run(string);
void cmd_vmmap(string);
void cmd_setreg(string);
void cmd_si(string);
void cmd_start(string);


#endif
