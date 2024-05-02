#include <Windows.h>
#include <tchar.h>
#include <sddl.h>
#include <iostream>
#include <string>
#include <bcrypt.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <wininet.h>
#include <thread> // Include the <thread> header for std::this_thread
#include <chrono> // Include the <chrono> header for std::chrono


#pragma comment(lib, "wininet.lib")

// Global variable for directory path
LPCWSTR lpDirectoryName = L"C:\\Users\\yashm\\OneDrive\\Desktop\\SecureFolder-BioSec";

std::string DeleteAPICall() {
    std::string response;

    HINTERNET hInternet = InternetOpen(L"MyApp", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet != NULL) {
        HINTERNET hConnect = InternetOpenUrl(hInternet, L"https://biosec-backend-imtmoxa2zq-el.a.run.app/delete", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect != NULL) {
            // Read the response
            char buffer[4096];
            DWORD bytesRead;
            while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                // Append the response to the string
                response.append(buffer, bytesRead);
            }
            // Close the connection handle
            InternetCloseHandle(hConnect);
        }
        else {
            std::cerr << "Failed to open URL" << std::endl;
        }
        // Close the Internet handle
        InternetCloseHandle(hInternet);
    }
    else {
        std::cerr << "Failed to open Internet" << std::endl;
    }

    return response;
}

void UnLockFolder() {
    // Specify the security descriptor: D:(A;;GRGW;;;WD)
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(_T("D:(A;;GRGW;;;WD)"), SDDL_REVISION_1, &pSD, nullptr)) {
        // Handle error
        std::cerr << _T("Error converting security descriptor.") << std::endl;
        return;
    }

    // Apply the security descriptor to the directory
    if (SetFileSecurity(lpDirectoryName, DACL_SECURITY_INFORMATION, pSD) == 0) {
        // Handle error
        DWORD dwError = GetLastError();
        std::cerr << _T("Failed to set security descriptor for directory. Error Code: ") << dwError << std::endl;
        LocalFree(pSD);
        return;
    }

    std::wcout << _T("Security descriptor applied successfully to the directory.") << std::endl;
    DeleteAPICall();

    // Free the memory allocated for the security descriptor
    LocalFree(pSD);
}

void LockFolder() {
    // Specify the security descriptor: D:(A;;GRGW;;;SY)
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(_T("D:(A;;GRGW;;;SY)"), SDDL_REVISION_1, &pSD, nullptr)) {
        // Handle error
        std::cerr << _T("Error converting security descriptor.") << std::endl;
        return;
    }

    // Apply the security descriptor to the directory
    if (SetFileSecurity(lpDirectoryName, DACL_SECURITY_INFORMATION, pSD) == 0) {
        // Handle error
        DWORD dwError = GetLastError();
        std::cerr << _T("Failed to set security descriptor for directory. Error Code: ") << dwError << std::endl;
        LocalFree(pSD);
        return;
    }

    std::wcout << _T("Security descriptor applied successfully to the directory.") << std::endl;

    // Free the memory allocated for the security descriptor
    LocalFree(pSD);
}

std::string RequestAPICall() {
    std::string response;
    
    HINTERNET hInternet = InternetOpen(L"MyApp", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet != NULL) {
        HINTERNET hConnect = InternetOpenUrl(hInternet, L"https://biosec-backend-imtmoxa2zq-el.a.run.app/request", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect != NULL) {
            // Read the response
            char buffer[4096];
            DWORD bytesRead;
            while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                // Append the response to the string
                response.append(buffer, bytesRead);
            }
            // Close the connection handle
            InternetCloseHandle(hConnect);
        }
        else {
            std::cerr << "Failed to open URL" << std::endl;
        }
        // Close the Internet handle
        InternetCloseHandle(hInternet);
    }
    else {
        std::cerr << "Failed to open Internet" << std::endl;
    }

    return response;
}

std::string BioResponseCall() {
    std::string response;

    HINTERNET hInternet = InternetOpen(L"MyApp", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet != NULL) {
        HINTERNET hConnect = InternetOpenUrl(hInternet, L"https://biosec-backend-imtmoxa2zq-el.a.run.app/check1", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect != NULL) {
            // Read the response
            char buffer[4096];
            DWORD bytesRead;
            while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                // Append the response to the string
                response.append(buffer, bytesRead);
            }
            // Close the connection handle
            InternetCloseHandle(hConnect);
        }
        else {
            std::cerr << "Failed to open URL" << std::endl;
        }
        // Close the Internet handle
        InternetCloseHandle(hInternet);
    }
    else {
        std::cerr << "Failed to open Internet" << std::endl;
    }

    return response;
}


void BioResponseCallCon() {
    while (true) {
        // Call the biometric API
        std::string apiResponse = BioResponseCall();

        // Check the response and execute the appropriate function
        if (!apiResponse.empty() && apiResponse == "{\"status\":\"correct\"}") {

            UnLockFolder();
            //Sleep(3);
            //DeleteAPICall();
            //SendStringOverPipe(hPipe, "BioMetric is correct and Folder is Unlocked");
        }
        else if (!apiResponse.empty() && apiResponse == "wrong") {
            LockFolder();
        }
        else {
            // Wait for 1 second before the next API call
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void SendStringOverPipe(HANDLE hPipe, const std::string& message) {
    DWORD bytesWritten;
    if (!WriteFile(hPipe, message.c_str(), message.size(), &bytesWritten, NULL)) {
        std::cerr << "Error writing to pipe" << std::endl;
    }
    else {
        std::cout << "Message sent over the pipe: " << message << std::endl;
    }
}

std::string generateSHA256HashS(const std::string& input) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error acquiring cryptographic context" << std::endl;
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "Error creating hash object" << std::endl;
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(input.c_str()), input.length(), 0)) {
        std::cerr << "Error hashing data" << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    DWORD hashSize = 0;
    DWORD dataSize = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashSize), &dataSize, 0)) {
        std::cerr << "Error getting hash size" << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::vector<BYTE> hashData(hashSize, 0);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashData.data(), &hashSize, 0)) {
        std::cerr << "Error getting hash value" << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::stringstream ss;
    for (BYTE byte : hashData) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return ss.str();
}


bool verifyPassword(const std::string& inputPassword) {
    // Read stored hash from registry
    HKEY hKey;
    LPCWSTR subKey = L"Software\\PBioword";
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Error opening registry key" << std::endl;
        return false;
    }

    DWORD dataSize = 0;
    if (RegQueryValueEx(hKey, L"PasswordHash", 0, nullptr, nullptr, &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::cerr << "Error querying value size or value not found" << std::endl;
        return false;
    }

    std::vector<BYTE> hashData(dataSize, 0);
    if (RegQueryValueEx(hKey, L"PasswordHash", 0, nullptr, hashData.data(), &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::cerr << "Error reading hash from registry" << std::endl;
        return false;
    }

    RegCloseKey(hKey);

    std::string storedHash(reinterpret_cast<char*>(hashData.data()), dataSize);

    // Hash the input password
    std::string inputHash = generateSHA256HashS(inputPassword);

    std::cout << "Input Hash: " << inputHash << std::endl;
    std::cout << "Stored Hash: " << storedHash << std::endl;

    // Compare the hashes
    return (inputHash == storedHash);
}


int main() {
    DeleteAPICall();

    std::thread bioThread(BioResponseCallCon);
    // Define security descriptor
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    // Define security attributes
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    HANDLE hPipe;

    while (true) {
        // Create named pipe server
        hPipe = CreateNamedPipe(
            L"\\\\.\\pipe\\MyNamedPipe",
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            1024,
            1024,
            NMPWAIT_USE_DEFAULT_WAIT,
            &sa);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create named pipe" << std::endl;
            return 1;
        }

        std::cout << "Named pipe server created and waiting for connections..." << std::endl;

        // Wait for client connection
        if (ConnectNamedPipe(hPipe, NULL) != FALSE || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::cout << "Client connected" << std::endl;

            // Handle communication with client
            while (true) {
                // Receive command from client
                char buffer[1024];
                DWORD bytesRead;
                if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL) != FALSE) {
                    // Check if command is "b" for biometric
                    if (bytesRead > 0 && buffer[0] == 'b') {
                        std::cout << "Biometric authentication received. Request is sent" << std::endl;
                        std::string apiResponse = RequestAPICall();
                        // Call LockFolder() here for biometric authentication
                    }
                    // To lock the folder when lock command is given
                    else if (bytesRead > 0 && buffer[0] == 'l') {
                        std::cout << "Folder has been locked" << std::endl;
                        LockFolder();

                    }
                    else {
                        // Extract the received password (excluding the command character)
                        std::string password(buffer, buffer + bytesRead);
                        // Verify the received password
                        if (verifyPassword(password)) {
                            std::cout << "Password verified. Lock method logic executed." << std::endl;
                            UnLockFolder();
                        }
                        else {
                            std::cerr << "Incorrect password received. Lock method logic not executed." << std::endl;
                            LockFolder();
                        }
                    }
                }
                else {
                    DWORD dwError = GetLastError();
                    if (dwError != ERROR_PIPE_CONNECTED && dwError != ERROR_NO_DATA) {
                        std::cerr << "Error reading from pipe: " << dwError << std::endl;
                    }
                    break; // Break out of the loop and wait for the next client connection
                }
            }

            // Close the named pipe handle after finishing communication with the client
            CloseHandle(hPipe);
        }
        else {
            std::cerr << "Error connecting to client" << std::endl;
        }
    }

    bioThread.join();
    return 0;
}
