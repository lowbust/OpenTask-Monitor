/* MIT License. Tiny Windows launcher for the bundled, unmodified CPython runtime.
 * No shell, downloads, elevation, Python installation or PATH changes.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <wchar.h>
#include <stdlib.h>
#include <bcrypt.h>
#ifdef OPENTASK_SINGLEFILE
#include "singlefile.h"
#endif

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, LPWSTR arguments, int show) {
    (void)instance; (void)previous; (void)show;
    wchar_t path[32768], runtime[32768], python[32768];
    DWORD length = GetModuleFileNameW(NULL, path, 32768);
    if (!length || length >= 32768) return 1;
    SetEnvironmentVariableW(L"OPENTASK_LAUNCHER", path);
    wchar_t *slash = wcsrchr(path, L'\\');
    if (!slash) return 1;
    BOOL randomName = FALSE;
    wchar_t appdata[32768], preference[32768];
    DWORD envLength = GetEnvironmentVariableW(L"LOCALAPPDATA", appdata, 32768);
    if (envLength > 0 && envLength < 32000) {
        swprintf(preference, 32768, L"%ls\\OpenTaskMonitor\\launch.ini", appdata);
        randomName = GetPrivateProfileIntW(L"Launch", L"RandomName", 0, preference) == 1;
    }
    if (_wcsnicmp(arguments, L"--random-name", 13) == 0 &&
        (arguments[13] == L' ' || arguments[13] == L'\0')) {
        randomName = TRUE;
        arguments += 13;
        while (*arguments == L' ') ++arguments;
    }
    if (_wcsnicmp(arguments, L"--normal-name", 13) == 0 &&
        (arguments[13] == L' ' || arguments[13] == L'\0')) {
        randomName = FALSE;
        arguments += 13;
        while (*arguments == L' ') ++arguments;
    }
    *slash = L'\0';
    if (wcslen(path) > 32000) return 1;
    swprintf(runtime, 32768, L"%ls\\runtime", path);
#ifdef OPENTASK_SINGLEFILE
    if (!otm_prepare_runtime(runtime, 32768)) return 1;
#endif
    swprintf(python, 32768, L"%ls\\pythonw.exe", runtime);
    if (GetFileAttributesW(python) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(NULL,
            L"Extract the ENTIRE ZIP first. Keep OpenTaskMonitor.exe and the runtime folder together.\n\n"
            L"Распакуйте ВЕСЬ архив. Рядом с OpenTaskMonitor.exe должна быть папка runtime.",
            L"OpenTask Monitor", MB_OK | MB_ICONERROR);
        return 1;
    }
    wchar_t temporary[32768] = L"";
    if (randomName) {
        unsigned int random[2];
        if (BCryptGenRandom(NULL, (PUCHAR)random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return 1;
        swprintf(temporary, 32768, L"%ls\\otm_%08x%08x.exe", runtime, random[0], random[1]);
        if (!CopyFileW(python, temporary, TRUE)) {
            int fallback = MessageBoxW(NULL,
                        L"Случайное имя требует права записи в папку runtime.\n"
                        L"Запустить в обычном режиме?",
                        L"OpenTask Monitor", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON1);
            if (fallback != IDYES) return 1;
            randomName = FALSE;
            temporary[0] = L'\0';
        }
        if (randomName) wcscpy(python, temporary);
    }
    size_t count = wcslen(python) + wcslen(runtime) + wcslen(arguments) + 96;
    if (count > 32767) return 1;
    wchar_t *command = calloc(count, sizeof(wchar_t));
    if (!command) return 1;
    swprintf(command, count, L"\"%ls\" \"%ls\\bootstrap.py\" %ls %ls", python, runtime, arguments,
             randomName ? L"--random-title" : L"");
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    BOOL ok = CreateProcessW(python, command, NULL, NULL, FALSE,
                            CREATE_UNICODE_ENVIRONMENT, NULL, runtime, &startup, &process);
    free(command);
    if (!ok) {
        DWORD error = GetLastError();
        if (temporary[0]) DeleteFileW(temporary);
        wchar_t message[256];
        swprintf(message, 256, L"Cannot start bundled runtime (Windows error %lu).\n"
                 L"Не удалось запустить приложение. Распакуйте весь архив и проверьте антивирус.", error);
        MessageBoxW(NULL, message, L"OpenTask Monitor", MB_OK | MB_ICONERROR);
        return 1;
    }
    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD status = 1;
    GetExitCodeProcess(process.hProcess, &status);
    CloseHandle(process.hProcess);
    if (temporary[0]) DeleteFileW(temporary);
    return (int)status;
}
