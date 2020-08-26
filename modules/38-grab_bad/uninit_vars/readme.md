# Uninitialized Variable Explanation

This is a well document C file that explains an uninitialized variable bug. 

Here is the source code:

```
#include <stdio.h>

void trashed(void)
{
    int x = 0xfacade;
    printf("Integer 0 Declared at:\t%p\n", &x);
    printf("Integer 0 Value:\t\t0x%x\n\n", x);
}

void scatterd(void)
{
	int y;
    printf("Integer 1 Declared at:\t%p\n", &y);
    printf("Integer 1 Value:\t\t0x%x\n\n", y);

	if (y == 0xfacade)
	{
		puts("Play your game, and walk away.\n");
	}
}

int main()
{
	puts("Let's talk about uninitialized variables.");
	puts("An uninitialized variable is one that is declared, but not assigned a value.");
	puts("Thing is an uninitialized variable has the value of the last thing previously placed there in memory.");
	puts("This can be beneficial when an uninitialized variable is referenced such as a read or a comparison.");
	puts("We will run a function that will declare and initialize a variable.\n");

	puts("After that, we will run another function which will declare a variable and not initialize it.");
	puts("Let's see where the second variable ends up in memory, and what it's value is.\n");

	trashed();

	scatterd();

	puts("As you can see, the memory location for the variable in the second function overlapped directly with the memory location for the variable in the first function.");
	puts("Since the second variable was not initialized with a value, it had the value that was previously stored there, which was the value of the variable from the first function.");
	puts("This is just one example of an uninitialized variables bug.");
	puts("However there are a lot of scenarios where this bug can be helpful.");
}
```

When it runs:

```
$	./uninit_vars 
Let's talk about uninitialized variables.
An uninitialized variable is one that is declared, but not assigned a value.
Thing is an uninitialized variable has the value of the last thing previously placed there in memory.
This can be beneficial when an uninitialized variable is referenced such as a read or a comparison.
We will run a function that will declare and initialize a variable.

After that, we will run another function which will declare a variable and not initialize it.
Let's see where the second variable ends up in memory, and what it's value is.

Integer 0 Declared at:	0x7ffcea5edff4
Integer 0 Value:		0xfacade

Integer 1 Declared at:	0x7ffcea5edff4
Integer 1 Value:		0xfacade

Play your game, and walk away.

As you can see, the memory location for the variable in the second function overlapped directly with the memory location for the variable in the first function.
Since the second variable was not initialized with a value, it had the value that was previously stored there, which was the value of the variable from the first function.
This is just one example of an uninitialized variables bug.
However there are a lot of scenarios where this bug can be helpful.
```