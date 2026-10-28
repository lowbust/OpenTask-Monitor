#pragma once
#include <windows.h>
/* Resource-backed, local-only preparation. Shows first-start progress UI.
 * Returns the full runtime directory in out. No runtime downloads or UAC. */
BOOL otm_prepare_runtime(wchar_t *out, size_t capacity);
