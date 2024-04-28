#include <Windows.h>
#include <tchar.h>
#include <sddl.h>
#include <iostream>
#include <string>

// Global variable for directory path
LPCWSTR lpDirectoryName = L"C:\\Users\\public\\SecureFolder-BioSec";

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


int main() {

    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    // Define security attributes
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;


    // Create named pipe server
    HANDLE hPipe = CreateNamedPipe(
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

    while (true) {
        // Wait for client connection
        if (ConnectNamedPipe(hPipe, NULL) != FALSE) {
            std::cout << "Client connected" << std::endl;

            // Receive command from client
            char buffer[1024];
            DWORD bytesRead;
            if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL) != FALSE) {
                // Check if command is "lock" or "unlock"
                std::string command(buffer, bytesRead);
                if (command == "lock") {
                    // Execute lock method logic
                    std::cout << "call recieved" << std::endl;

                    LockFolder();
                }
                else if (command == "unlock") {
                    // Execute unlock method logic
                    UnLockFolder();
                }
                else {
                    std::cerr << "Unknown command received: " << command << std::endl;
                }
            }

            // Disconnect client
            DisconnectNamedPipe(hPipe);
        }
    }

    // Close the named pipe (this code will never be reached)
    CloseHandle(hPipe);

    return 0;
}
