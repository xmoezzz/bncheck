int main(int argc, char ** argv) {
	char * path = get_current_dir_name();
	printf("a: %s\n", path);
	printf("a: %s %s\n", path, path);
}
