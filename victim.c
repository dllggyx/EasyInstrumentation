#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void bar(int x) {
    if (x > 5) {
        printf("  -> In bar(), x is large.\n");
    } else {
        printf("  -> In bar(), x is small.\n");
    }
}

int main() {
    srand(time(NULL));
    printf("Program start.\n");
    for (int i = 0; i < 3; ++i) {
        printf("Loop iteration: %d\n", i);
        bar(i + (rand()%5));
    }
    printf("Program end.\n");
    return 0;
}