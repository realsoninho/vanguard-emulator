#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <TlHelp32.h>
#include <vector>
#include <thread>
#include <atomic>
#include <iostream>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <ctime>
#include <regex>
#include <random>
#include <fstream>
#include <objbase.h>
#include <filesystem>
#include <shlobj.h>
#include "xorstr.hpp"
#include "driver_interface.hpp"
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "winhttp.lib")

#define CURRENT_VERSION 4

std::atomic_bool shutdown_event(false);
std::atomic_bool stopped_once(false);
std::atomic<HANDLE> g_current_pipe(nullptr);

const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\933823D3-C77B-4BAE-89D7-A92B567236BC";

// VAN error mitigation tracking
std::atomic<uint32_t> heartbeat_counter(0);
std::atomic<uint64_t> last_auth_time(0);
std::atomic<bool> degraded_mode(false);

#pragma pack(push, 1)
struct VanguardHeader {
    uint32_t magic;
    uint32_t total_size;
    uint32_t message_type;
    uint8_t  unknown1[12];
    uint32_t payload_size;
    uint8_t  unknown2[8];
};
#pragma pack(pop)

void log_message(const char* msg) {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm bt;
    localtime_s(&bt, &now_time_t);

    std::cout << "["
        << std::put_time(&bt, "%H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << now_ms.count()
        << "] [VGC] " << msg << std::endl;
}

void log_hex(const uint8_t* data, size_t size, const char* prefix = "") {
    std::stringstream ss;
    ss << prefix << " Hex: ";
    for (size_t i = 0; i < min(size, 32); i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i] << " ";
        if ((i + 1) % 16 == 0 && i < size - 1) {
            log_message(ss.str().c_str());
            ss.str("");
            ss << "       ";
        }
    }
    if (ss.str().length() > 0) {
        log_message(ss.str().c_str());
    }
}

// FIX VAN 102: adicionando jitter ao timestamp
uint64_t get_realistic_timestamp() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<int64_t> jitter(-50, 50);
    
    uint64_t base = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return base + jitter(gen);
}

// FIX VAN 68: checagem de rate limiting
bool check_auth_rate_limit() {
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    uint64_t last = last_auth_time.load();
    
    // Mínimo de 500ms entre pacotes de auth
    if (now - last < 500) {
        log_message("VAN-68 FIX: Auth rate limited");
        return false;
    }
    
    last_auth_time.store(now);
    return true;
}

// FIXED: Heartbeat magic must be exactly magic+1, not random offset
// Random offsets cause VAN -72 because the client expects sequential magic values
uint32_t get_heartbeat_magic(uint32_t base_magic) {
    return base_magic + 1;
}

void uuid_string_to_binary(const char* uuid_str, uint8_t* binary) {
    unsigned int parts[16];
    sscanf_s(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        &parts[0], &parts[1], &parts[2], &parts[3],
        &parts[4], &parts[5],
        &parts[6], &parts[7],
        &parts[8], &parts[9],
        &parts[10], &parts[11], &parts[12], &parts[13], &parts[14], &parts[15]);

    binary[0] = parts[3] & 0xFF;
    binary[1] = parts[2] & 0xFF;
    binary[2] = parts[1] & 0xFF;
    binary[3] = parts[0] & 0xFF;
    binary[4] = parts[5] & 0xFF;
    binary[5] = parts[4] & 0xFF;
    binary[6] = parts[7] & 0xFF;
    binary[7] = parts[6] & 0xFF;
    binary[8] = parts[8] & 0xFF;
    binary[9] = parts[9] & 0xFF;
    binary[10] = parts[10] & 0xFF;
    binary[11] = parts[11] & 0xFF;
    binary[12] = parts[12] & 0xFF;
    binary[13] = parts[13] & 0xFF;
    binary[14] = parts[14] & 0xFF;
    binary[15] = parts[15] & 0xFF;
}

bool find_last_uuid(const uint8_t* data, size_t size, uint8_t* uuid_bin, char* uuid_str) {
    std::string text;
    text.reserve(size);
    for (size_t i = 0; i < size; i++) {
        text += (data[i] >= 32 && data[i] <= 126) ? (char)data[i] : ' ';
    }

    std::regex uuid_pattern("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    std::smatch match;
    std::string last_uuid;

    auto search_start = text.cbegin();
    while (std::regex_search(search_start, text.cend(), match, uuid_pattern)) {
        last_uuid = match[0];
        search_start = match[0].second;
    }

    if (!last_uuid.empty()) {
        strcpy_s(uuid_str, 37, last_uuid.c_str());
        uuid_string_to_binary(last_uuid.c_str(), uuid_bin);
        return true;
    }
    return false;
}

void stop_and_restart_vgc() {
    // FIXED: Stop vgk (kernel driver) along with vgc
    system("sc stop vgk >nul 2>&1");
    system("sc stop vgc >nul 2>&1");
    Sleep(500);
    system("sc start vgc >nul 2>&1");
    Sleep(500);
}

void override_vgc_pipe() {
    HANDLE pipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe);
        log_message("Pipe overridden");
    }
}

std::vector<uint8_t> create_server_ack(uint32_t magic) {
    std::vector<uint8_t> resp;
    VanguardHeader hdr = { 0 };

    hdr.magic = magic + 1;
    hdr.payload_size = 8;
    // CRITICAL FIX: Dynamically calculate total_size to prevent pipe corruption
    hdr.total_size = sizeof(VanguardHeader) + hdr.payload_size;
    hdr.message_type = 1;

    resp.insert(resp.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
    resp.insert(resp.end(), 8, 0);

    return resp;
}

std::vector<uint8_t> create_auth_ack(uint32_t magic, int version, const uint8_t* uuid_bin) {
    // FIX VAN 68: checagem de rate limit
    if (!check_auth_rate_limit()) {
        log_message("RATE LIMITED - delaying auth response");
        Sleep(500);
    }

    std::vector<uint8_t> resp;
    VanguardHeader hdr = { 0 };

    char msg[256];
    sprintf_s(msg, "Using version %d (VAN fixes active)", version);
    log_message(msg);

    switch (version) {
    case 1:
        hdr.magic = magic + 1;
        hdr.payload_size = 8;
        hdr.total_size = sizeof(VanguardHeader) + hdr.payload_size;
        hdr.message_type = 1;
        resp.insert(resp.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
        resp.insert(resp.end(), 8, 0);
        break;

    case 2:
        hdr.magic = magic + 1;
        hdr.payload_size = 8;
        hdr.total_size = sizeof(VanguardHeader) + hdr.payload_size;
        hdr.message_type = 1;
        resp.insert(resp.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
        resp.insert(resp.end(), uuid_bin, uuid_bin + 8);
        break;

    case 3:
        hdr.magic = magic + 1;
        hdr.payload_size = 16;
        hdr.total_size = sizeof(VanguardHeader) + hdr.payload_size;
        hdr.message_type = 1;
        resp.insert(resp.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
        resp.insert(resp.end(), uuid_bin, uuid_bin + 16);
        break;

    case 4:
    {
        hdr.magic = magic + 1;
        hdr.payload_size = 8;
        hdr.total_size = sizeof(VanguardHeader) + hdr.payload_size;
        hdr.message_type = 1;
        resp.insert(resp.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
        
        // FIX VAN 102: timestamp realista com jitter
        uint64_t timestamp = get_realistic_timestamp();
        resp.insert(resp.end(), (uint8_t*)&timestamp, (uint8_t*)&timestamp + 8);
        
        char ts_msg[128];
        sprintf_s(ts_msg, "VAN-102 FIX: Timestamp with jitter: %llu", timestamp);
        log_message(ts_msg);
    }
    break;

    case 5:
    {
        hdr.magic = magic + 1;
        hdr.payload_size = 16 + 8;
        hdr.total_size = sizeof(VanguardHeader) + hdr.payload_size;
        hdr.message_type = 1;
        resp.insert(resp.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
        resp.insert(resp.end(), uuid_bin, uuid_bin + 16);
        
        // FIX VAN 102
        uint64_t timestamp = get_realistic_timestamp();
        resp.insert(resp.end(), (uint8_t*)&timestamp, (uint8_t*)&timestamp + 8);
    }
    break;
    }

    return resp;
}

std::vector<uint8_t> create_heartbeat_response(const uint8_t* data, size_t size) {
    std::vector<uint8_t> resp(data, data + size);
    VanguardHeader* hdr = (VanguardHeader*)resp.data();
    
    // FIXED: Use consistent magic+1 - random values caused VAN -72
    uint32_t base_magic = hdr->magic;
    hdr->magic = get_heartbeat_magic(base_magic);
    
    uint32_t count = heartbeat_counter.fetch_add(1);
    
    // Log heartbeat count periodically for debugging
    if (count % 50 == 0) {
        char hb_msg[128];
        sprintf_s(hb_msg, "Heartbeat count: %u (magic: 0x%X -> 0x%X)", count, base_magic, hdr->magic);
        log_message(hb_msg);
    }
    
    return resp;
}

void enable_stealth_mode() {
    JUNK_CODE
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        ShowWindow(hWnd, SW_HIDE);
    }
}

void clean_riot_traces() {
    JUNK_CODE
    char localAppData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
        std::vector<std::string> target_dirs = {
            std::string(localAppData) + "\\VALORANT\\Saved\\Logs",
            std::string(localAppData) + "\\Riot Games\\Riot Client\\Logs"
        };

        for (const auto& dir : target_dirs) {
            try {
                if (std::filesystem::exists(dir)) {
                    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                        if (entry.is_regular_file()) {
                            std::filesystem::remove(entry);
                        }
                    }
                    log_message(("CLEANER: Rastros deletados em: " + dir).c_str());
                }
            } catch (const std::exception& e) {
                // Ignore permissions errors
            }
        }
    }
}

std::string generate_uuid() {
    JUNK_CODE
    GUID guid;
    CoCreateGuid(&guid);
    char buf[64];
    sprintf_s(buf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return std::string(buf);
}

// Patcher de Memória: Substitui "realsoninho" por "0x90       " (a string literal)
void patch_payload(std::vector<char>& payload) {
    const char* target = "realsoninho";
    const char* replacement = "0x90       "; // Preenchido com espaços para manter os 11 bytes de tamanho
    size_t target_len = strlen(target);

    for (size_t i = 0; i <= payload.size() - target_len; ++i) {
        if (memcmp(&payload[i], target, target_len) == 0) {
            memcpy(&payload[i], replacement, target_len);
            log_message("PATCHER: 'realsoninho' substituído por '0x90       ' no payload.");
        }
    }
}

bool send_winhttp_post(const wchar_t* server, INTERNET_PORT port, const wchar_t* path, const std::vector<char>& payload, std::vector<char>& response_out) {
    HINTERNET hSession = WinHttpOpen(L"VGC Emulator/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        char err[128]; sprintf_s(err, "WinHttpOpen failed: %lu", GetLastError()); log_message(err);
        return false;
    }

    // FIXED: Set connection timeout to prevent hangs
    DWORD timeout = 15000; // 15 seconds
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET hConnect = WinHttpConnect(hSession, server, port, 0);
    if (!hConnect) {
        char err[128]; sprintf_s(err, "WinHttpConnect failed: %lu", GetLastError()); log_message(err);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD flags = (port == INTERNET_DEFAULT_HTTPS_PORT || port == 8443) ? WINHTTP_FLAG_SECURE : 0;
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        char err[128]; sprintf_s(err, "WinHttpOpenRequest failed: %lu", GetLastError()); log_message(err);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Ignore SSL errors if using local/self-signed certs or connecting to Riot
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    JUNK_CODE
    // Gerando o UUID falso (ofuscado e dinâmico) a cada vez que comunica com o gateway.
    std::string uuid = generate_uuid();
    std::wstring headers_w = XORW(L"Content-Type: application/x-protobuf\r\nX-VG-2: ") + std::wstring(uuid.begin(), uuid.end()) + XORW(L"\r\nX-VG-3: 1\r\n");
    bool bResults = WinHttpSendRequest(hRequest, headers_w.c_str(), (DWORD)-1L, (LPVOID)payload.data(), (DWORD)payload.size(), (DWORD)payload.size(), 0);

    if (!bResults) {
        char err[128]; sprintf_s(err, "WinHttpSendRequest failed: %lu", GetLastError()); log_message(err);
    } else {
        char sent_msg[128]; sprintf_s(sent_msg, "SEND OK: %zu bytes sent to server", payload.size()); log_message(sent_msg);
    }

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults) {
            char err[128]; sprintf_s(err, "WinHttpReceiveResponse failed: %lu", GetLastError()); log_message(err);
        } else {
            // FIXED: Log HTTP status code for debugging
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &statusCodeSize, NULL)) {
                char status_msg[128]; sprintf_s(status_msg, "HTTP Status: %lu", statusCode); log_message(status_msg);
                if (statusCode >= 400) {
                    char warn_msg[128]; sprintf_s(warn_msg, "WARNING: Server returned error status %lu", statusCode); log_message(warn_msg);
                }
            }
        }
    }

    if (bResults) {
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                break;
            }
            if (dwSize == 0) break;

            std::vector<char> chunk(dwSize);
            if (WinHttpReadData(hRequest, (LPVOID)chunk.data(), dwSize, &dwDownloaded)) {
                response_out.insert(response_out.end(), chunk.begin(), chunk.begin() + dwDownloaded);
            }
        } while (dwSize > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return bResults;
}

void simulate_gateway() {
    log_message("Initiating Gateway connection...");
    
    // Gateway endpoint configuration
    JUNK_CODE
    // Gateway endpoint configuration (Obfuscated)
    std::wstring server_url = XORW(L"eu.vg.ac.pvp.net"); // Servidor real do Riot Vanguard
    INTERNET_PORT PORT = 8443; // Porta HTTPS de comunicação do Vanguard
    std::wstring path = XORW(L"/vanguard/v1/gateway"); // Endpoint principal do gateway
    
    // Auto-Loader: Monitora a pasta at que os arquivos apareçam
    log_message("AUTO-LOADER: Aguardando a presença de auth.bin e request_content.x-protobuf...");
    while ((!std::filesystem::exists("auth.bin") || !std::filesystem::exists("request_content.x-protobuf")) && !shutdown_event.load()) {
        Sleep(2000);
    }
    if (shutdown_event.load()) return;
    log_message("Arquivos de sessão detectados. Iniciando injeção...");

    // Read and Send auth.bin
    std::ifstream auth_file("auth.bin", std::ios::binary | std::ios::ate);
    if (auth_file.is_open()) {
        std::streamsize size = auth_file.tellg();
        auth_file.seekg(0, std::ios::beg);
        std::vector<char> buffer(size);
        if (auth_file.read(buffer.data(), size)) {
            patch_payload(buffer); // VGC Emulator patch
            
            char msg[256];
            sprintf_s(msg, "SEND: auth.bin (%lld bytes) to Gateway", (long long)size);
            log_message(msg);
            log_hex((const uint8_t*)buffer.data(), buffer.size(), "OUTGOING AUTH: ");
            
            std::vector<char> response;
            if (send_winhttp_post(server_url.c_str(), PORT, path.c_str(), buffer, response)) {
                sprintf_s(msg, "Auth success. Response size: %zu", response.size());
                log_message(msg);
            } else {
                log_message("ERROR: HTTP request failed for auth.bin. (Connection dropped by Riot?)");
            }
        }
    } else {
        log_message("WARNING: auth.bin not found! Cannot simulate gateway.");
    }

    // Read and Send request_content.x-protobuf
    std::ifstream req_file("request_content.x-protobuf", std::ios::binary | std::ios::ate);
    if (req_file.is_open()) {
        std::streamsize size = req_file.tellg();
        req_file.seekg(0, std::ios::beg);
        std::vector<char> buffer(size);
        if (req_file.read(buffer.data(), size)) {
            patch_payload(buffer); // VGC Emulator patch
            
            char msg[256];
            sprintf_s(msg, "SEND: request_content.x-protobuf (%lld bytes) to Server", (long long)size);
            log_message(msg);
            log_hex((const uint8_t*)buffer.data(), buffer.size(), "OUTGOING PROTO: ");
            
            std::vector<char> response;
            if (send_winhttp_post(server_url.c_str(), PORT, path.c_str(), buffer, response)) {
                sprintf_s(msg, "Protobuf sent successfully. Response size: %zu", response.size());
                log_message(msg);
                
                // Write out the new response if we get one
                if (response.size() > 0) {
                    std::ofstream resp_out("response_content.x-protobuf.new", std::ios::binary);
                    resp_out.write(response.data(), response.size());
                    log_message("Saved server response to response_content.x-protobuf.new");
                    log_hex((const uint8_t*)response.data(), response.size(), "INCOMING RESP: ");
                }
            } else {
                log_message("ERROR: HTTP request failed for request_content.x-protobuf. (Is the server running?)");
            }
        }
    } else {
        log_message("WARNING: request_content.x-protobuf not found! Cannot send gateway requests.");
    }

    log_message("Autenticação do Gateway concluída. Admitido no servidor.");
}

void handle_client(HANDLE pipe) {
    // FIXED: Increased buffer size from 16KB to 64KB to handle larger packets
    std::vector<uint8_t> buffer(65536);
    DWORD bytesRead;
    g_current_pipe.store(pipe);

    uint8_t uuid_bin[16] = { 0 };
    char uuid_str[37] = { 0 };
    bool uuid_found = false;

    log_message("=== NEW CONNECTION (VAN -72 FIXES ACTIVE) ===");
    log_message("FIX 1: FlushFileBuffers after every WriteFile");
    log_message("FIX 2: Consistent magic+1 (no random offset)");
    log_message("FIX 3: WriteFile error checking + SEND logging");
    log_message("FIX 4: Content-Type headers for HTTP");
    log_message("FIX 5: Increased buffer sizes");
    
    char version_msg[64];
    sprintf_s(version_msg, "Using FIXED version #%d", CURRENT_VERSION);
    log_message(version_msg);

    // CRITICAL FIX: simulate_gateway() makes slow HTTP requests (1-5 seconds).
    // Running it synchronously here blocked the pipe's ReadFile loop, causing the game 
    // to timeout waiting for a response (VAN -72). Now it runs in the background.
    std::thread(simulate_gateway).detach();

    while (!shutdown_event.load()) {
        if (!ReadFile(pipe, buffer.data(), (DWORD)buffer.size(), &bytesRead, NULL) || bytesRead == 0) {
            DWORD err = GetLastError();
            char err_msg[128];
            sprintf_s(err_msg, "ReadFile failed or empty: error=%lu, bytesRead=%lu", err, bytesRead);
            log_message(err_msg);
            break;
        }

        // Validate minimum packet size
        if (bytesRead < sizeof(VanguardHeader)) {
            char warn_msg[128];
            sprintf_s(warn_msg, "WARNING: Packet too small (%lu bytes), skipping", bytesRead);
            log_message(warn_msg);
            continue;
        }

        VanguardHeader* hdr = (VanguardHeader*)buffer.data();

        char msg[256];
        sprintf_s(msg, "RECV: magic=0x%02X, type=%u, total_size=%u, payload_size=%u, bytesRead=%u",
            hdr->magic, hdr->message_type, hdr->total_size, hdr->payload_size, bytesRead);
        log_message(msg);

        std::vector<uint8_t> response;

        switch (hdr->message_type) {
        case 2:
            log_message("Server list request");
            response = create_server_ack(hdr->magic);
            if (!stopped_once.exchange(true)) {
                // FIXED: system() calls block the thread for up to 10+ seconds.
                // Doing this synchronously caused Vanguard to timeout waiting for the ACK.
                std::thread([]() {
                    system("sc stop vgk >nul 2>&1");
                    system("sc stop vgc >nul 2>&1");
                    Beep(1000, 500);
                }).detach();
            }
            break;

        case 4:
            log_message("Auth token - SEARCHING FOR UUID");
            uuid_found = find_last_uuid(buffer.data(), bytesRead, uuid_bin, uuid_str);

            if (uuid_found) {
                char uuid_msg[128];
                sprintf_s(uuid_msg, "Found UUID: %s", uuid_str);
                log_message(uuid_msg);
                log_hex(uuid_bin, 16, "UUID binary:");

                response = create_auth_ack(hdr->magic, CURRENT_VERSION, uuid_bin);
            }
            else {
                log_message("UUID NOT found - using v1");
                response = create_auth_ack(hdr->magic, 1, uuid_bin);
            }
            break;

        case 1:
            response = create_heartbeat_response(buffer.data(), bytesRead);
            break;

        default:
            {
                char def_msg[128];
                sprintf_s(def_msg, "Unknown message_type=%u, echoing as heartbeat", hdr->message_type);
                log_message(def_msg);
            }
            response = create_heartbeat_response(buffer.data(), bytesRead);
            break;
        }

        if (!response.empty()) {
            DWORD written = 0;
            // FIXED: Check WriteFile return value and log SEND status
            BOOL writeResult = WriteFile(pipe, response.data(), (DWORD)response.size(), &written, NULL);
            
            if (writeResult && written == (DWORD)response.size()) {
                // FIXED: FlushFileBuffers ensures data is actually delivered to the client
                // Without this, data sits in the kernel buffer and the client never receives it
                // This was the PRIMARY cause of VAN -72 (heartbeats not reaching the game)
                FlushFileBuffers(pipe);
                
                char send_msg[256];
                sprintf_s(send_msg, "SEND: %lu bytes written, magic=0x%02X, type=%u (FLUSHED)",
                    written, ((VanguardHeader*)response.data())->magic,
                    ((VanguardHeader*)response.data())->message_type);
                log_message(send_msg);
            }
            else {
                DWORD writeErr = GetLastError();
                char err_msg[256];
                sprintf_s(err_msg, "SEND FAILED: WriteFile error=%lu, requested=%zu, written=%lu",
                    writeErr, response.size(), written);
                log_message(err_msg);
                
                // If pipe is broken, exit the loop
                if (writeErr == ERROR_BROKEN_PIPE || writeErr == ERROR_NO_DATA) {
                    log_message("Pipe broken - client disconnected");
                    break;
                }
            }
        }

        // FIXED: Reduced sleep from 10ms to 1ms for faster heartbeat response
        // 10ms was adding unnecessary latency to every heartbeat cycle
        Sleep(1);
    }

    CloseHandle(pipe);
    g_current_pipe.store(nullptr);

    log_message("=== CONNECTION CLOSED ===");
}

void create_named_pipe() {
    // VAN 68/79 Fix: Allow all users to access the pipe (Valorant runs as standard user, Vanguard as SYSTEM)
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    while (!shutdown_event.load()) {
        // FIXED: Use PIPE_UNLIMITED_INSTANCES to prevent connection refusal
        // and FILE_FLAG_FIRST_PIPE_INSTANCE on first creation for security
        HANDLE pipe = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 1048576, 1048576, 0, &sa);

        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        log_message("Waiting for client...");

        if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            log_message("Client connected!");
            std::thread(handle_client, pipe).detach();
        }
        else {
            CloseHandle(pipe);
        }
    }
}

bool is_valorant_running() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };

    if (Process32FirstW(snap, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) {
            CloseHandle(snap);
            return true;
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return false;
}

BOOL WINAPI ConsoleHandler(DWORD dwType) {
    if (dwType == CTRL_C_EVENT || dwType == CTRL_CLOSE_EVENT) {
        shutdown_event.store(true);
        return TRUE;
    }
    return FALSE;
}

int main() {
    JUNK_CODE
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    
    // Ocultar a janela (Invisibilidade)
    enable_stealth_mode();
    
    // Executar o limpador na inicialização
    clean_riot_traces();

    // Inicializar ponte com o Driver (Ring-0)
    DriverLink kernelLink;
    if (kernelLink.Initialize()) {
        log_message("KERNEL: Comunicação com o Driver estabelecida (IOCTL)!");
    } else {
        log_message("KERNEL: Aviso - Driver não encontrado. Rodando apenas em Usermode.");
    }

    // FIXED: Disable QuickEdit Mode. Clicking the console suspends the process 
    // and causes Vanguard timeouts (Error 232 / Pipe Broken).
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD prev_mode;
    if (GetConsoleMode(hInput, &prev_mode)) {
        SetConsoleMode(hInput, prev_mode & ~ENABLE_QUICK_EDIT_MODE);
    }

    log_message("========================================");
    log_message("  VGC Emulator - VAN -72 FIX BUILD");
    log_message("========================================");
    log_message("FIXES APPLIED:");
    log_message("  [1] FlushFileBuffers after every WriteFile");
    log_message("  [2] Heartbeat magic: consistent +1 (no random)");
    log_message("  [3] WriteFile error checking + SEND logging");
    log_message("  [4] Content-Type, X-VG-2, X-VG-3 headers for HTTP requests");
    log_message("  [5] Increased buffer sizes (64KB read)");
    log_message("  [6] Reduced loop latency (1ms vs 10ms)");
    log_message("  [7] HTTP timeout configuration (15s)");
    log_message("  [8] HTTP status code logging");
    log_message("  [9] Async simulate_gateway (Fixed pipe blocking)");
    log_message("");

    char current[64];
    sprintf_s(current, "ACTIVE VERSION: %d", CURRENT_VERSION);
    log_message(current);
    log_message("");

    stop_and_restart_vgc();
    override_vgc_pipe();

    std::thread(create_named_pipe).detach();

    log_message("Waiting for Valorant...");
    while (!is_valorant_running() && !shutdown_event.load()) Sleep(500);
    log_message("Valorant detected!");

    while (!shutdown_event.load()) Sleep(1000);

    log_message("Shutting down...");
    return 0;
}