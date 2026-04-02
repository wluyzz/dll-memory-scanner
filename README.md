# DLL & Memory Scanner
fully open source
A lightweight cross-platform C++ tool designed to analyze running processes and detect potentially suspicious behavior in memory and loaded modules.

## 🔍 Features

### 🪟 Windows
- Detects unsigned DLLs loaded in processes
- Scans memory regions using VirtualQueryEx
- Flags:
  - RWX (Read-Write-Execute) memory
  - Private executable memory (possible manual mapping)

### 🐧 Linux
- Scans `/proc` memory maps
- Detects:
  - RWX memory regions
  - Anonymous executable memory
  - Suspicious shared libraries outside standard system paths

## ⚙️ How it works
The scanner enumerates all running processes and analyzes:
- Loaded modules (DLL / shared objects)
- Memory protections and regions
- Execution permissions

It highlights unusual patterns commonly associated with:
- Code injection
- Manual mapping
- Suspicious runtime behavior

## 🚀 Usage

### Windows
- Build with Visual Studio
- Run as Administrator

### Linux
```bash
g++ main.cpp linux_scanner.cpp -o scanner
sudo ./scanner
