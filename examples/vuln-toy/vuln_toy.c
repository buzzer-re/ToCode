#include <stdio.h>
#include <string.h>

__attribute__((noinline))
static int copy_name(const char *input) {
    char name[16];
    strcpy(name, input);
    return puts(name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    return copy_name(argv[1]);
}
