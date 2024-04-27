#include <iostream>
#include <Windows.h>
#include "integrity.hpp"
#include "integrity_thread.hpp"

extern "C" void to_hook(const char* format, ...);

void handler(sln::Integrity::IntegrityResult failedIntegrityCheck) {
    std::cout << failedIntegrityCheck.String() << std::endl;
}

int main()
{
    auto integrity = std::make_shared<sln::IntegrityThread>(handler);
    unsigned char to_hook_bytes[]{ 0xE9, 0x23, 0x1B, 0x00, 0x00 };

    to_hook("example!\n");
    to_hook("test!\n");

    auto request = sln::Integrity::IntegrityRequest(
        sln::Integrity::FUNCTION, &to_hook, sizeof(to_hook_bytes), to_hook_bytes
    );

    integrity->AddCheck(request);

    integrity->Start();

    while (true) {
        if (!integrity->IsRunning()) 
            integrity->Start();

        Sleep(10);
    }
}