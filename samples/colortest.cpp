#include <iostream>

int main()
{
    int a = 42;
    while (a != 52)
        std::cout << "\x1B[38;5;" << a++ << "mHello World!\n\x1B[0msomthing\n";
    return 0;
}