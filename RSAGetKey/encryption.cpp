

#include "encryption.h"
#include <wincrypt.h>
#include <stdio.h>
#include <conio.h>

#include <tchar.h>

#ifndef ENCRYPTION_C
#define ENCRYPTION_C
int Encryption::Keys(LPVOID* pub_key_address, LPDWORD pub_key_size, LPVOID* priv_key_address, LPDWORD priv_key_size)
{
    // Variables
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;


    // Acquire access to key container
    _tprintf(_T("CryptAcquireContext...\n"));
    if (!CryptAcquireContext(&hCryptProv, 0, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        // Error
        _tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());

        // Try to create a new key container
        if (!CryptAcquireContext(&hCryptProv, 0/*_T("AlejaCMa.EncryptDecrypt"*/, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
        {
            // Error
            _tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());
            return 0;
        }
    }

    // Generate new key pair
    _tprintf(_T("CryptGenKey...\n"));
    if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_ARCHIVABLE, &hKey))
    {
        // Error
        _tprintf(_T("CryptGenKey error 0x%x\n"), GetLastError());
        return 0;
    }

    // Get public key size
    _tprintf(_T("CryptExportKey...\n"));
    if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL, pub_key_size))
    {
        // Error
        _tprintf(_T("CryptExportKey error 0x%x\n"), GetLastError());
        return 0;
    }

    // Create a buffer for the public key
    _tprintf(_T("malloc...\n"));
    if (!(*pub_key_address = VirtualAlloc(0, *pub_key_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    {
        // Error
        _tprintf(_T("malloc error 0x%x\n"), GetLastError());
        return 0;
    }
    if (!(*pub_key_address = VirtualAlloc(0, *pub_key_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        RtlSecureZeroMemory(*pub_key_address, *pub_key_size);
    // Get public key
    _tprintf(_T("CryptExportKey...\n"));
    if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, (LPBYTE)*pub_key_address, pub_key_size))
    {
        // Error
        _tprintf(_T("CryptExportKey error 0x%x\n"), GetLastError());
        return 0;
    }

    // Get private key size
    _tprintf(_T("CryptExportKey...\n"));
    if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, priv_key_size))
    {
        // Error
        _tprintf(_T("CryptExportKey error 0x%x\n"), GetLastError());
        return 1;
    }

    // Create a buffer for the private key
    _tprintf(_T("malloc...\n"));
    if (!(*priv_key_address = VirtualAlloc(0, *priv_key_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    {
        // Error
        _tprintf(_T("malloc error 0x%x\n"), GetLastError());
        return 0;
    }
    RtlSecureZeroMemory(*priv_key_address, *priv_key_size);
    // Get private key
    _tprintf(_T("CryptExportKey...\n"));
    if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, (LPBYTE)*priv_key_address, priv_key_size))
    {
        // Error
        _tprintf(_T("CryptExportKey error 0x%x\n"), GetLastError());
        return 0;
    }

    // Clean up       

    if (hKey) {
        _tprintf(_T("CryptDestroyKey...\n"));
        CryptDestroyKey(hKey);
    }
    if (hCryptProv) {
        _tprintf(_T("CryptReleaseContext...\n"));
        CryptReleaseContext(hCryptProv, 0);
    }
    return 1;
}
// End of Keys

// Encrypt
LPVOID Encryption::Encrypt(LPVOID strPublicKeyFile, DWORD public_key_size, LPVOID strPlainFile, DWORD Plain_size, LPDWORD enc_msg_size)
{
    // Variables
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    DWORD dwDataLen = 0;
    DWORD dwEncryptedLen = 0;

    // Acquire access to key container
    _tprintf(_T("CryptAcquireContext...\n"));
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        // Error
        _tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());
        return 0;
    }

    // Import public key
    _tprintf(_T("CryptImportKey...\n"));
    if (!CryptImportKey(hCryptProv, (LPBYTE)strPublicKeyFile, public_key_size, 0, 0, &hKey))
    {
        // Error
        _tprintf(_T("CryptImportKey error 0x%x\n"), GetLastError());
        return 0;
    }

    // Get lenght for encrypted data
    if (!CryptEncrypt(hKey, NULL, TRUE, 0, NULL, &dwEncryptedLen, 0))
    {
        // Error
        _tprintf(_T("CryptEncrypt error 0x%x\n"), GetLastError());
        return 0;
    }

    // Create a buffer for encrypted data
    _tprintf(_T("VirtualAlloc...\n"));
    LPVOID new_pbData = NULL;
    if (!(new_pbData = (BYTE*)VirtualAlloc(0, dwEncryptedLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    {
        // Error
        _tprintf(_T("malloc error 0x%x\n"), GetLastError());

        return 0;
    }

    if (!CopyMemory(new_pbData, strPlainFile, Plain_size)) {
        // Error
        _tprintf(_T("Copy Memory error 0x%x\n"), GetLastError());
        VirtualFree(new_pbData, dwEncryptedLen, MEM_RELEASE);
        return 0;
    }

    // Encrypt data
    if (!CryptEncrypt(hKey, NULL, TRUE, 0, (LPBYTE)new_pbData, &dwDataLen, dwEncryptedLen))
    {
        // Error
        _tprintf(_T("CryptEncrypt error 0x%x\n"), GetLastError());
        RtlSecureZeroMemory(new_pbData, dwEncryptedLen);
        VirtualFree(new_pbData, dwEncryptedLen, MEM_RELEASE);
        return 0;
    }
    *enc_msg_size = dwDataLen;
    // Clean up

    if (hKey) {
        _tprintf(_T("CryptDestroyKey...\n"));
        CryptDestroyKey(hKey);
    }
    if (hCryptProv) {
        _tprintf(_T("CryptReleaseContext...\n"));
        CryptReleaseContext(hCryptProv, 0);
    }
    return new_pbData;
}
// End of Encrypt

// Decrypt
int Encryption::Decrypt(LPVOID PrivateKey, DWORD private_key_size, LPVOID Encrypted_Data, LPDWORD enc_data_size)
{
    // Variables
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;


    // Acquire access to key container
    _tprintf(_T("CryptAcquireContext...\n"));
    if (!CryptAcquireContext(&hCryptProv, _T("AlejaCMa.EncryptDecrypt"), NULL, PROV_RSA_FULL, 0))
    {
        // Error
        _tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());

        // Try to create a new key container
        if (!CryptAcquireContext(&hCryptProv, _T("AlejaCMa.EncryptDecrypt"), NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
        {
            // Error
            _tprintf(_T("CryptAcquireContext error 0x%x\n"), GetLastError());
            return 0;
        }
    }

    DWORD ret = 0;
    // Import private key
    _tprintf(_T("CryptImportKey...\n"));
    ret = CryptImportKey(hCryptProv, (LPBYTE)PrivateKey, private_key_size, 0, 0, &hKey);
    if (!ret)
    {
        // Error
        _tprintf(_T("CryptImportKey error 0x%x\n"), GetLastError());
        return 0;
    }
    _tprintf(_T("CryptImportKey return 0x%x\n"), ret);
    ret = 0;



    ret = CryptDecrypt(hKey, NULL, TRUE, 0, (LPBYTE)Encrypted_Data, enc_data_size);
    // Get lenght for plain text
    if (!ret)
    {
        // Error
        _tprintf(_T("CryptDecrypt error 0x%x\n"), GetLastError());
        return 0;
    }
    _tprintf(_T("CryptDecrypt return 0x%x\n"), ret);


    // Clean up       

    if (hKey) {
        _tprintf(_T("CryptDestroyKey...\n"));
        CryptDestroyKey(hKey);
    }
    if (hCryptProv) {
        _tprintf(_T("CryptReleaseContext...\n"));
        CryptReleaseContext(hCryptProv, 0);
    }

    return 1;
}
#endif
