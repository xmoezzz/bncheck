#include <unistd.h>
int main(int argc, char ** argv) {
	int a = 100;
	long long b;

	if (argc > 1000) {
		b = 1;
	}
	else if (argc > 100) {
		b = 4;
	}
	else {
		b = 19;
	}

	if (argc < 100) {
		a = b * 2;
	}
	write(1, &b, (int)a);

	return a;
}
