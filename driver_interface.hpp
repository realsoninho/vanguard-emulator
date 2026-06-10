#pragma once
#include <windows.h>
#include <iostream>
#include "xorstr.hpp"

// Códigos IOCTL (Padrão genérico de controle customizado, DeviceType = 0x00000022)
#define IOCTL_GET_BASE_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Estruturas de requisição do Driver
struct DRIVER_REQUEST_BASE {
    ULONG process_id;
    ULONGLONG base_address; // Out
};

struct DRIVER_REQUEST_RW {
    ULONG process_id;
    ULONGLONG target_address;
    ULONGLONG buffer_address;
    SIZE_T size;
};

class DriverLink {
private:
    HANDLE hDriver;

public:
    DriverLink() : hDriver(INVALID_HANDLE_VALUE) {}

    ~DriverLink() {
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
        }
    }

    bool Initialize() {
        // Obfuscated symbolic link connection
        std::wstring driver_name = XORW(L"\\\\.\\vgk"); 
        
        hDriver = CreateFileW(
            driver_name.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        return hDriver != INVALID_HANDLE_VALUE;
    }

    ULONGLONG GetBaseAddress(ULONG pid) {
        if (hDriver == INVALID_HANDLE_VALUE) return 0;

        DRIVER_REQUEST_BASE req = { 0 };
        req.process_id = pid;

        DWORD bytes_returned;
        if (DeviceIoControl(hDriver, IOCTL_GET_BASE_ADDRESS, &req, sizeof(req), &req, sizeof(req), &bytes_returned, NULL)) {
            return req.base_address;
        }
        return 0;
    }

    template <typename T>
    T ReadMemory(ULONG pid, ULONGLONG address) {
        T buffer = { 0 };
        if (hDriver == INVALID_HANDLE_VALUE) return buffer;

        DRIVER_REQUEST_RW req = { 0 };
        req.process_id = pid;
        req.target_address = address;
        req.buffer_address = (ULONGLONG)&buffer;
        req.size = sizeof(T);

        DWORD bytes_returned;
        DeviceIoControl(hDriver, IOCTL_READ_MEMORY, &req, sizeof(req), &req, sizeof(req), &bytes_returned, NULL);
        return buffer;
    }

    template <typename T>
    bool WriteMemory(ULONG pid, ULONGLONG address, const T& value) {
        if (hDriver == INVALID_HANDLE_VALUE) return false;

        DRIVER_REQUEST_RW req = { 0 };
        req.process_id = pid;
        req.target_address = address;
        req.buffer_address = (ULONGLONG)&value;
        req.size = sizeof(T);

        DWORD bytes_returned;
        return DeviceIoControl(hDriver, IOCTL_WRITE_MEMORY, &req, sizeof(req), &req, sizeof(req), &bytes_returned, NULL);
    }
};
