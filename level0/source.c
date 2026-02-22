#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    int value;

    if (argc < 2)
    {
        printf("Usage: ./level0 <number>\n");
        return (1);
    }

    value = atoi(argv[1]);

    if (value == 423)
    {
        gid_t gid = getegid();
        uid_t uid = geteuid();

        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);

        system("/bin/sh");
    }
    else
    {
        printf("No!\n");
    }

    return (0);
}