#include <stdio.h>
#include <string.h>
int main(int c,char**v){char b[64];strcpy(b,c>1?v[1]:"hi");puts(b);return 0;}
