//encryption.h
// FUNCTIONS
#ifndef _WIN_H
#define _WIN_H
#define WIN32_LEAN_AND_MEAN
#include "Windows.h"
#endif
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

namespace Encryption {
    int Keys(LPVOID*, LPDWORD, LPVOID*, LPDWORD);
    LPVOID Encrypt(LPVOID, DWORD, LPVOID, DWORD, LPDWORD);
    int Decrypt(LPVOID, DWORD, LPVOID, LPDWORD);
}
#endif