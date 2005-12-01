#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <stdlib.h>
int main (int argc, char **argv) {
	truncate(argv[1], 4ll<<30);
}
