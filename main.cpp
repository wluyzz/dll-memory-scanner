#include <iostream>

#ifdef _WIN32
void RunWindowsScanner();
#else
void RunLinuxScanner();
#endif

int main() {
#ifdef _WIN32
    std::cout << "Running Windows Scanner...\n\n";
    RunWindowsScanner();
#else
    std::cout << "Running Linux Scanner...\n\n";
    RunLinuxScanner();
#endif

    std::cout << "\nScan complete.\n";
    return 0;
}