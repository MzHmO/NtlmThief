#define SECURITY_WIN32
#include <Windows.h>
#include <SubAuth.h>
#include <sspi.h>
#include <sddl.h>
#include <iostream>
#pragma comment(lib, "Secur32.lib")
#include <vector>
#include <locale>
#include <TlHelp32.h>
#include <algorithm>