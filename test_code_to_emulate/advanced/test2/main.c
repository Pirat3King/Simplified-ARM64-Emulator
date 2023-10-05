#include <stdint.h>

int main() {
	char src[16];
	char dst[16];
	for (int64_t i = 0; i < 16; i++) {
		src[i] = i;
	}
	for (int64_t i = 0; i < 16; i++) {
		dst[i] = src[i];
	}
}
