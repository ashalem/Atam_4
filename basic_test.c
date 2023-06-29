#include <stdio.h>

int foo(int a, int b) {
	printf("in foo\n");
	 return a+b;
}
int main () {
	printf("before foo\n");
	 foo(3,4);
	  foo(0,0);
	   return 0;
}

