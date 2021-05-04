#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
using namespace std;

string so_path = "./logger.so";
string output_path = "/dev/fd/2";

void usage() {
    cout << "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]" << endl;
    cout << "    -p: set the path to logger.so, default = ./logger.so" << endl;
    cout << "    -o: print output to file, print to \"stderr\" if no file specified" << endl;
    cout << "    --: separate the arguments for logger and for the command" << endl;
    exit(0);
}

int main(int argc, char *argv[], char *envp[]) {
    char opt;
    FILE *fp;
    while ((opt = getopt(argc, argv, "o:p:")) != -1) {
        switch (opt) {
            case 'p':
                so_path = optarg;
                break;
            case 'o':
                output_path = optarg;
                fp = fopen(optarg, "w");
                fwrite("", 1, 0, fp);
                fclose(fp);
                break;
            default:
                usage();
        }
    }

    if (optind == argc) usage();

    setenv("LD_PRELOAD", so_path.c_str(), 1);
    setenv("OUTPUT_PATH", output_path.c_str(), 1);

    execvp(argv[optind], argv + optind);
}
