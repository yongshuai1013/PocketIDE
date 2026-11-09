typedef signed int intptr_t;

volatile int ginger_copy_value = 42;
volatile int *ginger_relative_pointer = &ginger_copy_value;

int ginger_check_relative_pointer(void) {
    volatile int *resolved = (volatile int *)((char *)&ginger_relative_pointer +
                                               (intptr_t)ginger_relative_pointer);
    return *resolved;
}
