/* MIT License — OpenTask Monitor contributors.
 * One-file deployment, not memory-only execution: on first launch, validated
 * embedded ZIP entries are written into a per-user hash/version-specific cache.
 * Libraries are separate and replaceable in that cache (including LGPL Qt).
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
#include <stdio.h>
#include <string.h>
#include "miniz.h"
#include "payload_info.h"
#include "singlefile.h"

#define PATH_CAP 32768
#define PAYLOAD_RESOURCE 202
#define MAX_EXTRACTED_SIZE (2ULL * 1024 * 1024 * 1024)

static BOOL cancelled = FALSE;
static HWND progress_window = NULL;
static HWND progress_label = NULL;

static LRESULT CALLBACK progress_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_CLOSE) {
        cancelled = TRUE;
        DestroyWindow(window);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

static void pump(void) {
    MSG message;
    while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {
        if (message.message == WM_QUIT) cancelled = TRUE;
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

static void show_progress(void) {
    WNDCLASSW type = {0};
    type.lpfnWndProc = progress_proc;
    type.hInstance = GetModuleHandleW(NULL);
    type.lpszClassName = L"OpenTask.Preparation";
    type.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    type.hCursor = LoadCursorW(NULL, IDC_ARROW);
    RegisterClassW(&type);
    progress_window = CreateWindowExW(0, type.lpszClassName, L"OpenTask Monitor — первый запуск",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        (GetSystemMetrics(SM_CXSCREEN) - 540) / 2, (GetSystemMetrics(SM_CYSCREEN) - 150) / 2,
        540, 150, NULL, NULL, type.hInstance, NULL);
    if (progress_window) {
        progress_label = CreateWindowW(L"STATIC",
            L"Подготовка встроенных компонентов…\r\nЭто нужно только при первом запуске этой сборки.",
            WS_CHILD | WS_VISIBLE, 18, 18, 495, 75, progress_window, NULL, type.hInstance, NULL);
        SendMessageW(progress_label, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        UpdateWindow(progress_window);
    }
    pump();
}

static BOOL directory(wchar_t *path) {
    size_t length = wcslen(path);
    if (!length || length >= PATH_CAP - 1) return FALSE;
    for (size_t i = 3; i <= length; ++i) {
        if (path[i] != L'\\' && path[i] != L'\0') continue;
        wchar_t saved = path[i];
        path[i] = L'\0';
        if (!CreateDirectoryW(path, NULL)) {
            DWORD attributes = GetFileAttributesW(path);
            if (GetLastError() != ERROR_ALREADY_EXISTS && attributes == INVALID_FILE_ATTRIBUTES) {
                path[i] = saved; return FALSE;
            }
            if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                path[i] = saved; SetLastError(ERROR_REPARSE_TAG_INVALID); return FALSE;
            }
        }
        path[i] = saved;
    }
    return TRUE;
}

static BOOL safe_name(const char *name) {
    if (!name[0] || name[0] == '/' || name[0] == '\\' || strchr(name, ':')) return FALSE;
    const char *start = name;
    for (const char *p = name; ; ++p) {
        if (*p != '/' && *p != '\\' && *p != '\0') continue;
        size_t count = (size_t)(p - start);
        if (!count || start[count - 1] == '.' || start[count - 1] == ' ' ||
            (count == 1 && start[0] == '.') ||
            (count == 2 && start[0] == '.' && start[1] == '.')) return FALSE;
        if (*p == '\0') break;
        start = p + 1;
    }
    return TRUE;
}

static BOOL complete(const wchar_t *package) {
    wchar_t marker[PATH_CAP], python[PATH_CAP];
    if (wcslen(package) > PATH_CAP - 100) return FALSE;
    swprintf(marker, PATH_CAP, L"%ls\\.ready", package);
    HANDLE file = CreateFileW(marker, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    char content[100] = {0}; DWORD length = 0;
    BOOL ok = ReadFile(file, content, sizeof(content) - 1, &length, NULL);
    CloseHandle(file);
    if (!ok || length != strlen(OTM_PAYLOAD_HASH) || strcmp(content, OTM_PAYLOAD_HASH)) return FALSE;
    swprintf(python, PATH_CAP, L"%ls\\runtime\\pythonw.exe", package);
    return GetFileAttributesW(python) != INVALID_FILE_ATTRIBUTES;
}

typedef struct { HANDLE file; mz_uint64 written; } Output;
static size_t write_file(void *opaque, mz_uint64 offset, const void *data, size_t length) {
    Output *output = opaque;
    pump();
    if (cancelled || offset != output->written || length > 0xffffffff) return 0;
    DWORD written = 0;
    if (!WriteFile(output->file, data, (DWORD)length, &written, NULL) || written != length) return 0;
    output->written += written;
    return written;
}

static BOOL unpack(const wchar_t *staging) {
    HMODULE module = GetModuleHandleW(NULL);
    HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(PAYLOAD_RESOURCE), RT_RCDATA);
    if (!resource) return FALSE;
    DWORD size = SizeofResource(module, resource);
    HGLOBAL loaded = LoadResource(module, resource);
    const void *bytes = loaded ? LockResource(loaded) : NULL;
    if (!bytes || !size) return FALSE;
    mz_zip_archive archive = {0};
    if (!mz_zip_reader_init_mem(&archive, bytes, size, 0)) { SetLastError(ERROR_BAD_FORMAT); return FALSE; }
    BOOL ok = FALSE;
    mz_uint count = mz_zip_reader_get_num_files(&archive);
    mz_uint64 total = 0;
    if (count == 0 || count > 20000) goto end;
    for (mz_uint i = 0; i < count; ++i) {
        mz_zip_archive_file_stat stat;
        if (!mz_zip_reader_file_stat(&archive, i, &stat) || stat.m_is_encrypted) goto end;
        total += stat.m_uncomp_size;
        if (total > MAX_EXTRACTED_SIZE) goto end;
    }
    ULARGE_INTEGER available;
    if (GetDiskFreeSpaceExW(staging, &available, NULL, NULL) && available.QuadPart < total + 20000000ULL) {
        SetLastError(ERROR_DISK_FULL); goto end;
    }
    for (mz_uint i = 0; i < count; ++i) {
        char name[4096]; wchar_t relative[4096], target[PATH_CAP], parent[PATH_CAP];
        mz_zip_archive_file_stat stat;
        if (!mz_zip_reader_file_stat(&archive, i, &stat)) goto end;
        if (stat.m_is_directory) continue;
        mz_uint needed = mz_zip_reader_get_filename(&archive, i, name, sizeof(name));
        if (!needed || needed > sizeof(name) || !safe_name(name)) goto end;
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1, relative, 4096)) goto end;
        for (wchar_t *p = relative; *p; ++p) if (*p == L'/') *p = L'\\';
        if (wcslen(staging) + wcslen(relative) > PATH_CAP - 2) goto end;
        swprintf(target, PATH_CAP, L"%ls\\%ls", staging, relative);
        wcscpy(parent, target);
        wchar_t *slash = wcsrchr(parent, L'\\');
        if (!slash) goto end;
        *slash = L'\0';
        if (!directory(parent)) goto end;
        HANDLE file = CreateFileW(target, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file == INVALID_HANDLE_VALUE) goto end;
        Output output = {file, 0};
        BOOL extracted = mz_zip_reader_extract_to_callback(&archive, i, write_file, &output, 0);
        CloseHandle(file);
        if (!extracted || output.written != stat.m_uncomp_size) goto end;
        if (i % 20 == 0 && progress_label) {
            wchar_t caption[200];
            swprintf(caption, 200, L"Подготовка встроенных компонентов: %u / %u\r\n"
                     L"Повторные запуски используют готовый кеш.", i + 1, count);
            SetWindowTextW(progress_label, caption);
        }
        pump();
        if (cancelled) goto end;
    }
    ok = TRUE;
end:
    mz_zip_reader_end(&archive);
    if (!ok && !GetLastError()) SetLastError(ERROR_CRC);
    return ok;
}

BOOL otm_prepare_runtime(wchar_t *out, size_t capacity) {
    wchar_t appdata[PATH_CAP], packages[PATH_CAP], package[PATH_CAP], staging[PATH_CAP], marker[PATH_CAP];
    DWORD env = GetEnvironmentVariableW(L"LOCALAPPDATA", appdata, PATH_CAP);
    if (!env || env > PATH_CAP - 300 || appdata[1] != L':' || appdata[2] != L'\\') {
        MessageBoxW(NULL, L"Папка LOCALAPPDATA недоступна. Не удалось подготовить приложение.",
                    L"OpenTask Monitor", MB_OK | MB_ICONERROR); return FALSE;
    }
    swprintf(packages, PATH_CAP, L"%ls\\OpenTaskMonitor\\packages", appdata);
    swprintf(package, PATH_CAP, L"%ls\\%ls", packages, OTM_PAYLOAD_ID);
    HANDLE mutex = NULL;
    BOOL locked = FALSE, ok = FALSE;
    DWORD error = 0;
    if (!complete(package)) {
        show_progress();
        wchar_t mutex_name[256];
        swprintf(mutex_name, 256, L"Local\\OpenTaskMonitor.Unpack.%ls", OTM_PAYLOAD_ID);
        mutex = CreateMutexW(NULL, FALSE, mutex_name);
        if (!mutex) goto done;
        for (unsigned int attempt = 0; attempt < 1200; ++attempt) {
            DWORD result = WaitForSingleObject(mutex, 100);
            if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED) { locked = TRUE; break; }
            if (result != WAIT_TIMEOUT) goto done;
            pump();
            if (cancelled) goto done;
        }
        if (!locked) { SetLastError(ERROR_TIMEOUT); goto done; }
        if (!complete(package)) {
            if (GetFileAttributesW(package) != INVALID_FILE_ATTRIBUTES) {
                SetLastError(ERROR_INVALID_DATA); goto done;
            }
            if (!directory(packages)) goto done;
            swprintf(staging, PATH_CAP, L"%ls\\.staging-%lu-%llu", packages, GetCurrentProcessId(), GetTickCount64());
            if (!CreateDirectoryW(staging, NULL)) goto done;
            if (!unpack(staging)) goto done;
            swprintf(marker, PATH_CAP, L"%ls\\.ready", staging);
            HANDLE file = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
            if (file == INVALID_HANDLE_VALUE) goto done;
            DWORD written = 0;
            BOOL marked = WriteFile(file, OTM_PAYLOAD_HASH, (DWORD)strlen(OTM_PAYLOAD_HASH), &written, NULL);
            FlushFileBuffers(file);
            CloseHandle(file);
            if (!marked || written != strlen(OTM_PAYLOAD_HASH)) goto done;
            if (!MoveFileExW(staging, package, MOVEFILE_WRITE_THROUGH)) goto done;
        }
    }
    if (!complete(package)) { SetLastError(ERROR_INVALID_DATA); goto done; }
    if (wcslen(package) + 10 >= capacity) { SetLastError(ERROR_BUFFER_OVERFLOW); goto done; }
    swprintf(out, capacity, L"%ls\\runtime", package);
    SetEnvironmentVariableW(L"OPENTASK_PACKAGE_DIR", package);
    SetEnvironmentVariableW(L"OPENTASK_SINGLEFILE", L"1");
    ok = TRUE;
done:
    error = GetLastError();
    if (locked) ReleaseMutex(mutex);
    if (mutex) CloseHandle(mutex);
    if (progress_window && IsWindow(progress_window)) DestroyWindow(progress_window);
    if (!ok && !cancelled) {
        wchar_t message[800];
        swprintf(message, 800, L"Не удалось подготовить встроенные компоненты (Windows %lu).\r\n\r\n"
                 L"Нужны доступ к LOCALAPPDATA и свободное место. Проверьте журнал антивируса.\r\n"
                 L"Кеш: %%LOCALAPPDATA%%\\OpenTaskMonitor\\packages\r\n"
                 L"Данные автозагрузки startup-backup.json не удаляйте.", error);
        MessageBoxW(NULL, message, L"OpenTask Monitor", MB_OK | MB_ICONERROR);
    }
    return ok;
}
