//
//#pragma comment(lib, "crypt32.lib")
//
//
//#include <windows.h>
//#include <Wincrypt.h>
//#include <tchar.h>
//#include <stdio.h>
//#include <iostream>
//#include "key.h"
//#include <atlstr.h>
//using namespace std;
//void MyHandleError(char* s);
//void WriteBytesFile(LPTSTR lpFileName, BYTE* content, DWORD dwDataLen);
////-------------------------------------------------------------------
//// Copyright (C) Microsoft.  All rights reserved.
//// Begin main.
//#define KEY_FILE_PUBLIC "C:\\Users\\Anhdz\\Desktop\\RSAGetKey\\RSAGetKey\\publickey.dat"
//#define KEY_FILE_PRIVATE "C:\\Users\\Anhdz\\Desktop\\RSAGetKey\\RSAGetKey\\privatekey.dat"
//#define KEY_FILE_ENCRYPTDATA "C:\\Users\\Anhdz\\Desktop\\RSAGetKey\\RSAGetKey\\encryptdata.dat"
//long file_length(const char* filename);
//void main()
//{
//    HCRYPTPROV hProv = 0;       // CSP handle
//    HCRYPTKEY hSignKey = 0;     // Signature key pair handle
//    HCRYPTKEY hXchgKey = 0;     // Exchange key pair handle
//    HCRYPTKEY hKey = 0;         // Session key handle
//    HCRYPTKEY hRSAKey = 0;
//    BYTE* pbKeyBlob;        // Pointer to a simple key BLOB
//    DWORD dwBlobLen;        // The length of the key BLOB
//    PUBLICKEYSTRUC stBlob;
//
//    if (!CryptAcquireContextW(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
//        cout << "Error CryptAcquireContextW " << GetLastError() << endl;
//    if (!CryptGenKey(hProv, AT_KEYEXCHANGE, RSA1024BIT_KEY | CRYPT_EXPORTABLE | CRYPT_NO_SALT, &hSignKey))//AT_SIGNATURE
//        cout << "Error CryptGenKey " << GetLastError() << endl;
//
//    // PUBLICKEY******************************
//    if (!CryptExportKey(hSignKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen))
//        cout << "Error CryptExportKey 1" << GetLastError() << endl;
//
//    pbKeyBlob = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dwBlobLen);
//
//    if (!CryptExportKey(hSignKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen))
//        cout << "Error CryptExportKey 12" << GetLastError() << endl;
//
//    WriteBytesFile(CString(KEY_FILE_PUBLIC).GetBuffer(), pbKeyBlob, dwBlobLen);
//    FILE* fp;// = fopen(KEY_FILE_PUBLIC, "w+b");
//    //if (fp) {
//    //    fwrite(pbKeyBlob, 1, dwBlobLen, fp);
//    //    fclose(fp);
//    //}
//
//    // PRIVATE ********************
//    if (!CryptExportKey(hSignKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwBlobLen))
//        cout << "Error CryptExportKey 2" << GetLastError() << endl;
//    pbKeyBlob = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dwBlobLen);
//    if (!CryptExportKey(hSignKey, 0, PRIVATEKEYBLOB, 0, pbKeyBlob, &dwBlobLen))
//        cout << "Error CryptExportKey 22" << GetLastError() << endl;
//
//    fp = fopen(KEY_FILE_PRIVATE, "w+b");
//    if (fp) {
//        fwrite(pbKeyBlob, 1, dwBlobLen, fp);
//        fclose(fp);
//    }
//
//    // Destroy the session key.
//    if (hKey)
//        CryptDestroyKey(hKey);
//
//    // Destroy the signature key handle.
//    if (hSignKey)
//        CryptDestroyKey(hSignKey);
//
//    // Destroy the key exchange key handle.
//    if (hXchgKey)
//        CryptDestroyKey(hXchgKey);
//    // Release the provider handle.
//    if (hProv)
//        CryptReleaseContext(hProv, 0);
//
//    //********************************************************************************ENCRYPT
//    HCRYPTKEY hcryptProv;
//    BYTE* bEnData;
//    DWORD dwDataLen = 0;
//    DWORD dwEncryptedLen = 0;
//    BYTE* new_pbData;
//
//    byte* cbKeyEncrypt;
//    DWORD dKeyEnSize;
//    byte* cbKeyDecrypt;
//    DWORD dKeyDeSize;
//
//    dKeyEnSize = file_length(KEY_FILE_PUBLIC);
//    cbKeyEncrypt = (BYTE*)malloc(dKeyEnSize + 1);
//    memset(cbKeyEncrypt, 0, dKeyEnSize + 1);
//
//    fp = fopen(KEY_FILE_PUBLIC, "rb");
//    if (fp) {
//        fread(cbKeyEncrypt, 1, dKeyEnSize, fp);
//        fclose(fp);
//    }
//    else {
//        free(cbKeyEncrypt);
//        cbKeyEncrypt = NULL;
//    }
//    // Encrypt
//    if (!CryptAcquireContext(&hcryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
//    {
//        // Error
//        printf(("CryptAcquireContext error 0x%x\n"), GetLastError());
//    }
//    // ******IMPORT
//
//    if (!CryptImportKey(hcryptProv, cbKeyEncrypt, dKeyEnSize, 0, 0, &hRSAKey))
//        printf("Fail import %x", GetLastError());
//
//
//    if (!CryptEncrypt(hRSAKey, NULL, TRUE, CRYPT_OAEP, NULL, &dwEncryptedLen, 0))
//    {
//        printf(("CryptEncrypt error 0x%x\n"), GetLastError());
//    }
//    // dwEncryptedLen = sizeof("deobasdasdsssssssssssssssssssssssssadsadasdasdasdadwqeqweqwewqeqietasdas");
//    new_pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dwEncryptedLen);
//    //memcpy(new_pbData, "keymahoadeobietluon", dwEncryptedLen);
//
//    if (!CryptEncrypt(hRSAKey, 0, TRUE, CRYPT_OAEP, new_pbData, &dwDataLen, dwEncryptedLen))
//    {
//        cout << "Error Encrypt:" << GetLastError() << endl;
//        cout << ERROR_INVALID_HANDLE << endl;
//        cout << ERROR_INVALID_PARAMETER << endl;
//        cout << NTE_BAD_ALGID << endl;
//        cout << NTE_BAD_DATA << endl;
//        cout << NTE_BAD_FLAGS << endl;
//        cout << NTE_BAD_HASH << endl;
//        cout << NTE_BAD_HASH_STATE << endl;
//        cout << NTE_BAD_KEY << endl;
//        cout << NTE_BAD_LEN << endl;
//        cout << NTE_BAD_UID << endl;
//        cout << NTE_DOUBLE_ENCRYPT << endl;
//        cout << NTE_FAIL << endl;
//        cout << NTE_NO_MEMORY << endl;
//        return;
//    }
//    // Write buffer test
//    fp = fopen(KEY_FILE_ENCRYPTDATA, "w+b");
//    if (fp) {
//        fwrite(new_pbData, 1, dwDataLen, fp);
//        fclose(fp);
//    }
//    //// Destroy the session key.
//    if (hRSAKey)
//        CryptDestroyKey(hRSAKey);
//    //// Release the provider handle.
//    if (hcryptProv)
//        CryptReleaseContext(hcryptProv, 0);
//
//    //********************************************************************************DECRYPT
//    HCRYPTPROV hprovDecrypt = 0;
//
//
//    HCRYPTKEY hDecrypt = 0;
//    dKeyDeSize = file_length(KEY_FILE_PRIVATE);
//    cbKeyDecrypt = (BYTE*)malloc(dKeyDeSize + 1);
//    memset(cbKeyDecrypt, 0, dKeyDeSize + 1);
//
//    fp = fopen(KEY_FILE_PRIVATE, "rb");
//    if (fp) {
//        fread(cbKeyDecrypt, 1, dKeyDeSize, fp);
//        fclose(fp);
//    }
//    else {
//        free(cbKeyDecrypt);
//        cbKeyDecrypt = NULL;
//    }
//    if (!CryptAcquireContext(&hprovDecrypt, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
//    {
//        printf(("CryptAcquireContext error 0x%x\n"), GetLastError());
//    }
//
//
//
//    if (!CryptImportKey(hprovDecrypt, cbKeyDecrypt, dKeyDeSize, 0, 0, &hDecrypt))
//        printf("Fail import %x", GetLastError());
//
//    HCRYPTKEY hpriDecrypt = 0;
//    if (!CryptGetUserKey(hprovDecrypt, AT_KEYEXCHANGE, &hpriDecrypt))
//        cout << GetLastError() << endl;
//    BYTE* inputDecr;
//    inputDecr = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dwDataLen);
//    memcpy(inputDecr, new_pbData, dwDataLen);
//    if (!CryptDecrypt(hpriDecrypt, 0, TRUE, CRYPT_OAEP, new_pbData, &dwDataLen))
//        cout << "Error Decrypt:" << GetLastError() << endl;
//
//
//
//
//    //CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE, &hSessionKey)
//} // End of main.
//void WriteBytesFile(LPTSTR lpFileName, BYTE* content, DWORD dwDataLen)
//{
//    HANDLE hFile = CreateFile(lpFileName, GENERIC_READ | GENERIC_WRITE, 0x7, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
//    DWORD dwBytesWritten = 0;
//    bool result = WriteFile(hFile, content, dwDataLen, &dwBytesWritten, NULL);
//    CloseHandle(hFile);
//}
////-------------------------------------------------------------------
////  This example uses the function MyHandleError, a simple error
////  handling function, to print an error message and exit 
////  the program. 
////  For most applications, replace this function with one 
////  that does more extensive error reporting.
//long file_length(const char* filename)
//{
//    FILE* fp;
//    long fsize = 0;
//
//    fp = fopen(filename, "rb");
//    if (NULL != fp) {
//        fseek(fp, 0L, SEEK_END);
//        fsize = ftell(fp);
//        fclose(fp);
//    }
//    return fsize;
//}
//void MyHandleError(char* s)
//{
//    printf("An error occurred in running the program.\n");
//    printf("%s\n", s);
//    printf("Error number %x\n.", GetLastError());
//    printf("Program terminating.\n");
//    exit(1);
//}