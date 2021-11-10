#include "filter_gen.h"

int main(int argc, char** argv)
{
	char *file_name = argv[1];
	char *section_name = argv[2];
	printf("object file name: %s\n", file_name);
	printf("section name: %s\n", section_name);
	generate_hex_dump(file_name, section_name);
	return 0;
}
