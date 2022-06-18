#pragma once

void DestroyKeys();

void Acqired();

void Generate2048BitKeys();

void ExportPrivateKey(LPTSTR lpFileName);

void ExportPublicKey(LPTSTR lpFileName);

void ImportKey(LPTSTR lpFileName);

void EncryptDataWriteToFile(LPCSTR lpSimpleDataToEncrypt, LPTSTR lpFileName);

void DecryptDataFromFile(LPBYTE* lpDecryptedData, LPTSTR lpFileName, DWORD* dwDecryptedLen);

void WriteBytesFile(LPTSTR lpFileName, BYTE* content, DWORD dwDataLen);

void ReadBytesFile(LPTSTR lpFileName, BYTE** content, DWORD* dwDataLen);
