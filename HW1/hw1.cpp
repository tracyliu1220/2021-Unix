#include <iostream>
#include <fstream>
#include <climits>
#include <cstdlib>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <string>
#include <regex>
#include <set>
using namespace std;

struct S {
    string cmd;
    string pid;
    string user;
    string fd;
    string type;
    long long node;
    string name;
    string append;
    S() {
        type = "unknown";
        node = -1;
    }
};

int cmd_regex_flag = 0;
string cmd_regex;
regex arg_regex_cmd;
int file_regex_flag = 0;
string file_regex;
regex arg_regex_file;
int type_filter_flag = 0;
string type_filter;

string global_cmd;
string global_pid;
string global_user;

vector<S> output;

bool isnumber(char *str) {
    char *ptr = str;
    while (*ptr != '\0') {
        if (!isdigit(*ptr)) return false;
        ptr++;
    }
    return true;
}

string lltostr(long long x) {
    if (x <= 0) return string();
    return lltostr(x / 10) + (char)('0' + x % 10);
}

bool check_cmd(string cmdline) {
    if (!cmd_regex_flag) return true;
    return regex_match(cmdline, arg_regex_cmd);
}

bool check_file(string file) {
    if (!file_regex_flag) return true;
    return regex_match(file, arg_regex_file);
}

bool check_type(string type) {
    if (!type_filter_flag) return true;
    return (type_filter == type);
}

string getcmdline(string pid) {
    string ret;
    ifstream in;
    in.open(("/proc/" + pid + "/comm").c_str(), ios::in);
    in >> ret;
    in.close();
    return ret;
}

string getuid(string pid) {
    struct stat buf_stat;
    stat(("/proc/" + pid).c_str(), &buf_stat);
    uid_t _uid = buf_stat.st_uid;
    string uid = to_string(_uid);
    return uid;
}

string getuser(string uid) {
    string user;
    string tmp_user_id;
    string str, tmp;
    ifstream in;
    in.open("/etc/passwd", ios::in);
    while (getline(in, str)) {
        for (int i = 0; i < str.size(); i++)
            if (str[i] == ':') str[i] = ' ';
        stringstream ss;
        ss << str;
        ss >> user;
        ss >> tmp;
        ss >> tmp_user_id;
        if (tmp_user_id == uid)
            break;
    }
    in.close();
    return user;
}

void initS(S & cur) {
    cur.cmd = global_cmd;
    cur.pid = global_pid;
    cur.user = global_user;
}

string getlinkname(string path) {
    char buf_readlink[500];
    buf_readlink[0] = '\0';
    int ret_size = readlink(path.c_str(), buf_readlink, 500);
    buf_readlink[ret_size] = '\0';
    return string(buf_readlink);
}

void gettype(struct stat buf_stat, S & cur) {
    if (S_ISREG(buf_stat.st_mode)) cur.type = "REG";
    if (S_ISDIR(buf_stat.st_mode)) cur.type = "DIR";
    if (S_ISCHR(buf_stat.st_mode)) cur.type = "CHR";
    if (S_ISFIFO(buf_stat.st_mode)) cur.type = "FIFO";
    if (S_ISSOCK(buf_stat.st_mode)) cur.type = "SOCK";
}

void getnode(struct stat buf_stat, S & cur) {
    cur.node = buf_stat.st_ino;
}

void getlinkstat(string pid, string target) {
    S cur;
    initS(cur);
    cur.fd = target;
    string name = getlinkname("/proc/" + pid + "/" + target);
    if (name.size() == 0) {
        cur.name = "/proc/" + pid + "/" + target;
        cur.append = " (readlink: Permission denied)";
        output.push_back(cur);
        return;
    }
    cur.name = name;
    struct stat buf_stat;
    bool flag = stat(("/proc/" + pid + "/" + target).c_str(), &buf_stat);
    if (flag == 0) { // success
        gettype(buf_stat, cur);
        getnode(buf_stat, cur);
    } else {
        cur.fd = "del";
    }
    output.push_back(cur);
}

void getmemstat(string path, string node, bool deleted) {
    S cur;
    initS(cur);
    cur.fd = "mem";
    cur.name = path;
    cur.node = atoll(node.c_str());
    cur.type = "REG";
    if (deleted) cur.fd = "del";
    output.push_back(cur);
}

void getfd(string pid, string fdidx, S & cur) {
    cur.fd = fdidx;
    string tmp, tmp2;
    ifstream in;
    in.open(("/proc/" + pid + "/fdinfo/" + fdidx).c_str(), ios::in);
    long long mode;
    while (in >> tmp) {
        if (tmp == "flags:") {
            in >> oct >> mode;
            break;
        } else {
            in >> tmp2;
        }
    }
    if (mode & O_WRONLY) cur.fd += 'w';
    else if (mode & O_RDWR) cur.fd += 'u';
    else /* if (mode & O_RDONLY) */ cur.fd += 'r';
    in.close();
}

void getfdstat(string pid, string fdidx) {
    S cur;
    initS(cur);
    
    string name = getlinkname("/proc/" + pid + "/fd/" + fdidx);
    cur.name = name;
    struct stat buf_stat;
    bool flag = stat(("/proc/" + pid + "/fd/" + fdidx).c_str(), &buf_stat);
    if (flag == 0) {
        gettype(buf_stat, cur);
        getnode(buf_stat, cur);
        getfd(pid, fdidx, cur);
    } else {
        cur.fd = "del";
    }
    output.push_back(cur);
}

void parsemem(string pid) {
    ifstream in;
    in.open(("/proc/" + pid + "/maps").c_str(), ios::in);
    string str;
    set<string> st;

    while (getline(in, str)) {
        stringstream ss;
        ss << str;
        string tmp, node, path;
        ss >> tmp;
        ss >> tmp;
        ss >> tmp;
        ss >> tmp;
        ss >> node;
        if (node == "0") continue;
        if (st.count(node)) continue;
        st.insert(node);
        ss >> path;
        bool deleted = 0;
        while (ss >> tmp) {
            if (tmp == "(deleted)") {
                deleted = 1;
                break;
            }
            path += " " + tmp;
        }
        getmemstat(path, node, deleted);
    }

    in.close();
}

void parsefd(string pid) {
    DIR *dir = opendir(("/proc/" + pid + "/fd").c_str());
    if (dir == NULL) {
        S cur;
        initS(cur);
        cur.fd = "NOFD";
        cur.name = "/proc/" + pid + "/fd";
        cur.append = " (opendir: Permission denied)";
        output.push_back(cur);
        return;
    }

    struct dirent *file;
    while ((file = readdir(dir)) != NULL) {
        string fdidx = file->d_name;
        if (fdidx == "." || fdidx == "..") continue;
        getfdstat(pid, fdidx);
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    
    // arguments
    char c;
    while ((c = getopt(argc, argv, "c:t:f:")) != -1) {
        switch (c) {
            case 'c':
                cmd_regex_flag = 1;
                cmd_regex = optarg;
                arg_regex_cmd = ".*" + cmd_regex + ".*";
                break;
            case 't':
                type_filter_flag = 1;
                type_filter = optarg;
                break;
            case 'f':
                file_regex_flag = 1;
                file_regex = optarg;
                arg_regex_file = ".*" + file_regex + ".*";
                break;
            case ':':
                break;
            case '?':
                break;
        }
    }

    if (type_filter_flag) {
        string types[] = {"REG", "CHR", "DIR", "FIFO", "SOCK", "unknown"};
        int found = 0;
        for (int i = 0; i < 6; i++)
            if (types[i] == type_filter) found = 1;
        if (!found) {
            cerr << "Invalid TYPE option.\n";
            exit(1);
        }
    }
    
    // header
    cout << "COMMAND\tPID\tUSER\tFD\tTYPE\tNODE\tNAME" << endl;

    DIR *dir = opendir("/proc");
    struct dirent *process;
    
    while ((process = readdir(dir)) != NULL) {
        if (!isnumber(process->d_name)) continue;

        // pid
        string pid = process->d_name;
        global_pid = pid;
        
        // cmdline
        string cmd = getcmdline(pid);
        if (cmd.size() == 0) continue;
        if (!check_cmd(cmd)) continue;
        global_cmd = cmd;

        // user
        string user = getuser(getuid(pid));
        global_user = user;

        // cout << pid << '\t' << cmd << '\t' << user << endl;

        // link
        getlinkstat(pid, "cwd");
        getlinkstat(pid, "root");
        getlinkstat(pid, "exe");

        // mem
        parsemem(pid);

        // fd
        parsefd(pid);
    }

    closedir(dir);

    // output
    for (int i = 0; i < output.size(); i++) {
        S cur = output[i];
        
        // (deleted) in name -> append
        if (cur.name.size() >= 10 && 
            cur.name.substr(cur.name.size() - 10, cur.name.size()) == " (deleted)") {
            cur.name = cur.name.substr(0, cur.name.size() - 10);
            cur.append = " (deleted)";
        }
        
        // del -> append (deleted)
        if (cur.fd == "del")
            cur.append = " (deleted)";

        // deleted -> unknown
        if (cur.append == " (deleted)")
            cur.type = "unknown";

        // anon_inode
        if (cur.name.size() >= 10 && cur.name.substr(0, 10) == "anon_inode")
            cur.name = "anon_inode:[" + lltostr(cur.node) + "]";

        // NOFD -> no type
        if (cur.fd == "NOFD")
            cur.type = "";
        
        // file regex
        if (!check_file(cur.name)) continue;
        
        // type filter
        if (!check_type(cur.type)) continue;

        cout << cur.cmd << '\t';
        cout << cur.pid << '\t';
        cout << cur.user << '\t';
        cout << cur.fd << '\t';
        cout << cur.type << '\t';
        if (cur.node != -1) cout << cur.node << '\t';
        cout << cur.name << cur.append << '\n';
    }

}
