#pragma comment(lib, "crypt32.lib")


#include <windows.h>
#include <Wincrypt.h>
#include <stdio.h>
#include <iostream>
#include "RSAGetKey.h"

using namespace std;
HCRYPTKEY hKey;
HCRYPTPROV hProvider;
BYTE* g_EncryptedBuffer;
DWORD g_SimpleDataToEncryptLength;
void main()
{
    Acqired();
    Generate2048BitKeys();
    //ExportPrivateKey((LPTSTR)L"privateKey.txt");
    //ExportPublicKey((LPTSTR)L"publicKey.txt");
    // Encrypt
    ImportKey((LPTSTR)L"publicKey.txt");
    EncryptDataWriteToFile((LPCSTR)"Sokytu_congthem_1", (LPTSTR)L"encryptedData.txt");
    DestroyKeys();

    // Decrypt
    Acqired();
    ImportKey((LPTSTR)L"privateKey.txt");
    LPBYTE lpDecryptedData = NULL;
    DWORD dwDataLen = 0;
    DecryptDataFromFile(&lpDecryptedData, (LPTSTR)L"encryptedData.txt", &dwDataLen);
    WriteBytesFile((LPTSTR)L"decryptedData.txt", lpDecryptedData, dwDataLen);
}
void DestroyKeys()
{
    if (hKey != NULL)
    {
        CryptDestroyKey(hKey);
        hKey = NULL;
    }

    if (hProvider != NULL)
    {
        CryptReleaseContext(hProvider, 0);
        hProvider = NULL;
    }
}
void Acqired()
{
    BOOL res = CryptAcquireContext(&hProvider, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!res)
    {
        printf("Error Acquiring Key Context\n");
        return;
    }
    printf("Key Context Acquired\n");
}
void Generate2048BitKeys()
{
    //const DWORD RSA2048BIT_KEY = 0x8000000;
    DWORD dwParams;
    dwParams =  CRYPT_EXPORTABLE | CRYPT_NO_SALT; //RSA2048BIT_KEY |  //set the key length to 2048 bits, allow the keys to be exported, no salt
    bool res = CryptGenKey(hProvider, AT_KEYEXCHANGE, dwParams, &hKey);
    if (!res)
    {
        printf("SERVER: Unable to generate exchange keys\n");
        return;
    }
    printf("SERVER: Exchange keys generated\n");
}
void ExportPrivateKey(LPTSTR lpFileName)
{
    if (hKey == NULL)
    {
        printf("Error in function 'ExportPrivateKey', hKey is NULL\n");
        return;
    }

    DWORD dwDataLen = 0;
    bool exportResult = CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwDataLen);
    LPBYTE lpKeyBlob = (LPBYTE)malloc(dwDataLen);
    exportResult = CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, lpKeyBlob, &dwDataLen);
    WriteBytesFile(lpFileName, lpKeyBlob, dwDataLen);
    free(lpKeyBlob);
}
void ExportPublicKey(LPTSTR lpFileName)
{
    if (hKey == NULL)
    {
        printf("Error in function 'ExportPublicKey', hKey is NULL\n");
        return;
    }

    DWORD dwDataLen = 0;
    bool exportResult = CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwDataLen);
    LPBYTE lpKeyBlob = (LPBYTE)malloc(dwDataLen);
    exportResult = CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, lpKeyBlob, &dwDataLen);
    WriteBytesFile(lpFileName, lpKeyBlob, dwDataLen);
    free(lpKeyBlob);
}
void ImportKey(LPTSTR lpFileName)
{
    if (hProvider == NULL)
    {
        printf("Error in function ImportKey, hProvider is NULL\n");
        return;
    }

    if (hKey != NULL)
        CryptDestroyKey(hKey);

    LPBYTE lpKeyContent = NULL;
    DWORD dwDataLen = 0;
    ReadBytesFile(lpFileName, &lpKeyContent, &dwDataLen);
    bool importResult = CryptImportKey(hProvider, lpKeyContent, dwDataLen, 0, CRYPT_OAEP, &hKey);
    if (!importResult)
    {
        printf("Error in function ImportKey, CryptImportKey is failed\n %d", GetLastError());
        return;
    }

    delete[] lpKeyContent;
}
void EncryptDataWriteToFile(LPCSTR lpSimpleDataToEncrypt, LPTSTR lpFileName)
{
    DWORD SimpleDataToEncryptLength = lstrlenA(lpSimpleDataToEncrypt) * sizeof(CHAR);
    g_SimpleDataToEncryptLength = lstrlenA(lpSimpleDataToEncrypt) * sizeof(CHAR)+1;
    DWORD BufferLength = g_SimpleDataToEncryptLength * 10;
    BYTE* EncryptedBuffer = new BYTE[BufferLength];
    g_EncryptedBuffer = new BYTE[BufferLength];

    SecureZeroMemory(g_EncryptedBuffer, BufferLength);
    CopyMemory(g_EncryptedBuffer, lpSimpleDataToEncrypt,
        SimpleDataToEncryptLength);
    //CRYPT_OAEP
    bool cryptResult = CryptEncrypt(hKey, NULL, TRUE, 0, g_EncryptedBuffer, &g_SimpleDataToEncryptLength, BufferLength);
    if (!cryptResult)
    {
        printf("Error in function EncryptDataWriteToFile, CryptEncrypt is failed\n");
        return;
    }

    WriteBytesFile(lpFileName, g_EncryptedBuffer, SimpleDataToEncryptLength);
    delete[] EncryptedBuffer;

    printf("Encrypt Data Successfully\n");
}
void DecryptDataFromFile(LPBYTE* lpDecryptedData, LPTSTR lpFileName, DWORD* dwDecryptedLen)
{
    if (hKey == NULL)
    {
        printf("Error in function 'DecryptDataFromFile', hKey is NULL.\n");
        return;
    }

    LPBYTE lpEncryptedData = NULL;
    DWORD dwDataLen = 0;
    ReadBytesFile(lpFileName, &lpEncryptedData, &dwDataLen);
    //CRYPT_OAEP
    bool decryptResult = CryptDecrypt(hKey, NULL, TRUE, 0, g_EncryptedBuffer, &g_SimpleDataToEncryptLength);
    if (!decryptResult)
    {
        printf("Error in function 'DecryptDataFromFile', CryptDecrypt cann't be decrypted data.\n");
        return;
    }
    printf("decrypted Successfully ... \n");
    *dwDecryptedLen = dwDataLen;
    *lpDecryptedData = new BYTE[dwDataLen + 1];
    SecureZeroMemory(*lpDecryptedData, dwDataLen + 1);
    CopyMemory(*lpDecryptedData, lpEncryptedData, dwDataLen);

    delete[]lpEncryptedData;
}
void WriteBytesFile(LPTSTR lpFileName, BYTE* content, DWORD dwDataLen)
{
    HANDLE hFile = CreateFile(lpFileName, GENERIC_READ | GENERIC_WRITE, 0x7, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dwBytesWritten = 0;
    bool result = WriteFile(hFile, content, dwDataLen, &dwBytesWritten, NULL);
    CloseHandle(hFile);
}
void ReadBytesFile(LPTSTR lpFileName, BYTE** content, DWORD* dwDataLen)
{
    HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, 0x7, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dwFileLength = 0;
    DWORD dwBytesToRead = GetFileSize(hFile, NULL);
    DWORD dwBytesRead = 0;

    *content = new BYTE[dwBytesToRead + 1];
    SecureZeroMemory(*content, dwBytesToRead + 1);

    if(!ReadFile(hFile, *content, dwBytesToRead, &dwBytesRead, NULL))
        printf("Error readfile");

    *dwDataLen = dwBytesRead;

    CloseHandle(hFile);
}