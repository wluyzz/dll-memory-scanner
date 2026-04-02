#ifndef _WIN32

#include <iostream>
#include <fstream>
#include <string>
#include <dirent.h>
#include <cctype>

bool isNumber(const std::string& s) {
    for (char c : s)
        if (!isdigit(c)) return false;
    return true;
}

void scanProcess(const std::string& pid) {
    std::string path = "/proc/" + pid + "/maps";
    std::ifstream file(path);

    if (!file.is_open())
        return;

    std::string line;

    while (std::getline(file, line)) {

        if (line.find("rwx") != std::string::npos) {
            std::cout << "[RWX] PID " << pid << ": " << line << std::endl;
        }

        if (line.find("xp") != std::string::npos &&
            line.find("/") == std::string::npos) {
            std::cout << "[PRIVATE EXEC] PID " << pid << ": " << line << std::endl;
        }

        if (line.find(".so") != std::string::npos) {
            if (line.find("/usr/lib") == std::string::npos &&
                line.find("/lib") == std::string::npos) {
                std::cout << "[SUSPICIOUS LIB] PID " << pid << ": " << line << std::endl;
            }
        }
    }
}

void RunLinuxScanner() {
    DIR* dir = opendir("/proc");
    struct dirent* entry;

    if (!dir) {
        std::cout << "Failed to open /proc\n";
        return;
    }

    while ((entry = readdir(dir)) != nullptr) {
        if (isNumber(entry->d_name)) {
            scanProcess(entry->d_name);
        }
    }

    closedir(dir);
}

#endif