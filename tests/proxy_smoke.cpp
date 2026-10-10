#include <windows.h>
#include <unknwn.h>

#include <cstdio>

using DirectInput8CreateFn = HRESULT(WINAPI *)(HINSTANCE, DWORD, REFIID, LPVOID *, LPUNKNOWN);

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) {
        fwprintf(stderr, L"usage: proxy_smoke <dinput8.dll>\n");
        return 2;
    }
    HMODULE proxy = LoadLibraryW(argv[1]);
    if (proxy == nullptr) {
        fwprintf(stderr, L"LoadLibrary failed: %lu\n", GetLastError());
        return 3;
    }
    wchar_t loadedPath[MAX_PATH]{};
    GetModuleFileNameW(proxy, loadedPath, MAX_PATH);
    wprintf(L"loaded=%ls\n", loadedPath);
    auto create = reinterpret_cast<DirectInput8CreateFn>(GetProcAddress(proxy, "DirectInput8Create"));
    if (create == nullptr) {
        fwprintf(stderr, L"missing DirectInput8Create export\n");
        FreeLibrary(proxy);
        return 4;
    }

    constexpr GUID iidDirectInput8W = {
        0xBF798031, 0x483A, 0x4DA2, {0xAA, 0x99, 0x5D, 0x64, 0xED, 0x36, 0x97, 0x00}
    };
    IUnknown *input = nullptr;
    const HRESULT result = create(GetModuleHandleW(nullptr), 0x0800, iidDirectInput8W,
                                  reinterpret_cast<void **>(&input), nullptr);
    if (input != nullptr) input->Release();
    std::printf("DirectInput8Create HRESULT=0x%08lX\n", static_cast<unsigned long>(result));
    FreeLibrary(proxy);
    return FAILED(result) ? 5 : 0;
}
