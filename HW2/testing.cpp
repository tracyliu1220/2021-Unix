#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdio>
#include <ctype.h>
#include <iostream>
using namespace std;

char write_buf[1000] = "Hello this is write buffer!\nHello this is write buffer!\n";
char read_buf[1000];

// chmod chown close creat fclose fopen fread fwrite open read remove rename
// tmpfile write

int main() {
    int ret, fd;

    // creat
    cout << "=== creat ===\n";
    fd = creat("file1", 511);
    
    // chown
    cout << "=== chown ===\n";
    ret = chown("file1", 1000, 1000);

    // chmod
    cout << "=== chmod ===\n";
    ret = chmod("file1", 511);

    // close
    cout << "=== close ===\n";
    ret = close(fd);

    // creat64
    cout << "=== creat64 ===\n";
    fd = creat64("file2", 420);
    ret = close(fd);
    
    // === open and open64 ===

    cout << "=== open ===\n";
    fd = open("file1", O_RDONLY, 511);
    ret = close(fd);
    
    fd = open("file1", O_RDONLY | O_CREAT, 511);
    ret = close(fd);
    
    fd = open("file1", O_WRONLY);
    ret = close(fd);

    cout << "=== open64 ===\n";
    fd = open64("file1", O_RDONLY, 511);
    ret = close(fd);
    
    fd = open64("file1", O_RDONLY | O_CREAT, 511);
    ret = close(fd);
    
    fd = open64("file1", O_WRONLY);
    ret = close(fd);

    // === read and write ===
    cout << "=== read and write ===\n";
    fd = creat("file3", 420);
    write(fd, write_buf, 10);
    write(fd, write_buf, 50);
    close(fd);
    fd = open("file3", O_RDONLY);
    read(fd, read_buf, 10);
    read(fd, read_buf, 40);
    close(fd);

    // === fopen fopen64 and fclose ===
    
    cout << "=== fopen fopen64 and fclose ===\n";
    FILE *fp;
    fp = fopen("file1", "r+");
    fclose(fp);
    
    fp = fopen64("file1", "w+");
    fclose(fp);

    // === fread and fwrite ===

    cout << "=== fread and fwrite ===\n";

    fp = fopen("file1", "w");
    fwrite(write_buf, 1, 10, fp);
    fwrite(write_buf, 1, 60, fp);
    fclose(fp);

    fp = fopen("file1", "rw");
    fread(read_buf, 1, 10, fp);
    // cout << read_buf << endl;
    // cout << "---\n";
    fread(read_buf, 1, 40, fp);
    // cout << read_buf << endl;
    fclose(fp);

    // === remove and rename ===
    
    cout << "=== remove and rename ===\n";
    rename("file1", "new_file1");
    remove("file2");

    // === tmpfile and tmpfile64 ===
    cout << "=== tmpfile and tmpfile64 ===\n";
    fp = tmpfile();
    fclose(fp);
    fp = tmpfile64();
    fclose(fp);

    // === close stderr ===
    cout << "=== close stderr ===\n";
    cerr << "before closing stderr!!\n";
    close(2);
    cerr << "after closing stderr!!!!!!!\n";


    
    // fd = open64("aaa", O_RDONLY, 511);
    // ret = close(fd);

}
