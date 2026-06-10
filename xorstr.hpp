#pragma once
#include <string>

template<size_t Size>
class XorString {
    char data[Size];
    char key;
public:
    constexpr XorString(const char* str, char k) : key(k), data{} {
        for (size_t i = 0; i < Size; ++i) {
            data[i] = str[i] ^ key;
        }
    }
    std::string decrypt() const {
        std::string dec(Size - 1, '\0');
        for (size_t i = 0; i < Size - 1; ++i) {
            dec[i] = data[i] ^ key;
        }
        return dec;
    }
};

template<size_t Size>
class XorStringW {
    wchar_t data[Size];
    wchar_t key;
public:
    constexpr XorStringW(const wchar_t* str, wchar_t k) : key(k), data{} {
        for (size_t i = 0; i < Size; ++i) {
            data[i] = str[i] ^ key;
        }
    }
    std::wstring decrypt() const {
        std::wstring dec(Size - 1, L'\0');
        for (size_t i = 0; i < Size - 1; ++i) {
            dec[i] = data[i] ^ key;
        }
        return dec;
    }
};

#define XOR(str) (XorString<sizeof(str)/sizeof(char)>(str, __TIME__[0] ^ __TIME__[1] ^ __LINE__).decrypt())
#define XORW(str) (XorStringW<sizeof(str)/sizeof(wchar_t)>(str, __TIME__[0] ^ __TIME__[1] ^ __LINE__).decrypt())

// Macro de Junk Code para alterar as assinaturas (Polimorfismo para x64)
#define JUNK_CODE \
    { \
        volatile long jnk1 = __LINE__; \
        volatile long jnk2 = __COUNTER__; \
        jnk1 = jnk1 ^ jnk2; \
        jnk2 = jnk1 * jnk2; \
    }
