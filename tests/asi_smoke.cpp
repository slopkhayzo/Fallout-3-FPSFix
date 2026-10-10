#include <windows.h>

#include <cstdio>

// Loads the ASI plugin the way a loader does and checks that it survives
// being loaded into a process that is not the game: installation runs from
// DllMain, must recognise that the executable is not one it knows, and must
// leave it alone.
int wmain(int argc, wchar_t **argv) {
    if (argc != 2) {
        fwprintf(stderr, L"usage: asi_smoke <Fallout3HFR.asi>\n");
        return 2;
    }
    HMODULE plugin = LoadLibraryW(argv[1]);
    if (plugin == nullptr) {
        fwprintf(stderr, L"LoadLibrary failed: %lu\n", GetLastError());
        return 3;
    }
    wchar_t loadedPath[MAX_PATH]{};
    GetModuleFileNameW(plugin, loadedPath, MAX_PATH);
    wprintf(L"loaded=%ls\n", loadedPath);

    using InitializeFn = void(__cdecl *)();
    const auto initialize =
        reinterpret_cast<InitializeFn>(GetProcAddress(plugin, "InitializeASI"));
    if (initialize == nullptr) {
        fwprintf(stderr, L"missing InitializeASI export\n");
        FreeLibrary(plugin);
        return 4;
    }
    initialize();
    if (GetProcAddress(plugin, "DirectInput8Create") != nullptr) {
        fwprintf(stderr, L"unexpected DirectInput8Create export\n");
        FreeLibrary(plugin);
        return 5;
    }
    FreeLibrary(plugin);
    std::printf("asi smoke ok\n");
    return 0;
}
