#include <stdint.h>

void main() {
	int64_t factorial = 5;
	int64_t result = 0;

	while (factorial > (int64_t)1) {
		result = factorial * (factorial - (int64_t)1);
		factorial = factorial - (int64_t)1;
	}
}
