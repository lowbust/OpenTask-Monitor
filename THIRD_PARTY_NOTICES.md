# Third-party software

The **original OpenTask Monitor source code** is licensed under MIT. This does
not relicense third-party code. No AnVir code, artwork or trademarks are included.

Runtime dependencies (installed separately, not vendored in this source ZIP):

| Dependency | License / upstream |
| --- | --- |
| psutil | BSD-3-Clause — https://github.com/giampaolo/psutil |
| PySide6 / Shiboken6 | LGPL-3.0 / GPL-3.0 / commercial; individual components may differ — https://doc.qt.io/qtforpython-6/licenses.html |
| Qt libraries and plugins | Component-specific LGPL/GPL/commercial and third-party notices — https://doc.qt.io/qt-6/licensing.html |

PySide6 / Qt are used as **dynamically loaded** dependencies. The current single-file portable build uses a native launcher with an embedded
compressed payload, extracted to a version-specific per-user cache on first run.
Qt is **not statically linked** to the application: its shared libraries remain
separate and replaceable in that cache. A legacy alternative uses PyInstaller onedir. Do not remove the
Qt libraries, bundled license files or notices from the distribution. Users must
be able to replace LGPL-covered libraries with compatible modified versions.
Some Qt modules may have different licensing; the application uses QtCore,
QtGui and QtWidgets. Review the actual build contents and upstream requirements
before distributing binaries. The MIT license of this project does not waive
LGPL obligations, including appropriate notices and access to corresponding
upstream source / relinking or replacement rights as applicable.

Build / development tools include PyInstaller (GPL with bootloader exception),
pytest (MIT), Ruff (MIT). They are not project source dependencies for end users.
Upstream license metadata and source links must be rechecked for the exact
versions included in a release. This notice is not legal advice.

## Embedded portable distribution

The supplied embedded portable ZIP (as opposed to the source ZIP) includes
unmodified official CPython Embedded 3.12.10 x64 and Windows wheels of
PySide6-Essentials / Shiboken6 6.8.3 and psutil 7.2.2. CPython's complete license
is retained in runtime/LICENSE.txt and third_party/Python-LICENSE.txt. Installed
wheel license/metadata files are retained under runtime/Lib/site-packages.

Copyright (C) The Qt Company Ltd. and other Qt/PySide contributors; see upstream
source for detailed copyright notices. Shared Qt/Python/psutil libraries remain
separately replaceable. BUILD-INFO.json records exact input hashes and upstream
source references (including the Qt supermodule for modules beyond QtBase).
No upstream library binaries are modified by the project. The native launcher
source, application source and build scripts are in the separate MIT source ZIP.
Generic license texts and installed third-party notices must be retained. Any
MSVC runtime files included by upstream wheels retain Microsoft's own terms.
Review release-specific legal requirements before further binary distribution.

## Single-file packaging 0.2.2

The ZIP distributed as the program contains only OpenTaskMonitor.exe. License
texts/notices and BUILD-INFO.json are embedded alongside the runtime and extracted
into %LOCALAPPDATA%/OpenTaskMonitor/packages/<build-id>. Use Help / «Справка» →
«Лицензии и сведения о сборке…» to open them. These files must remain in any
redistribution of the payload. The original source ZIP contains the application,
native extractor, miniz source, build scripts, and upstream source references.

The extractor statically includes **miniz 3.0.2 (MIT)** by Rich Geldreich and other
contributors: https://github.com/richgel999/miniz/tree/3.0.2 . Its license and
unmodified upstream sources are in third_party/miniz (static-export header is
project-generated). Shared Qt/Python/psutil libraries are unmodified. Users can
replace ABI-compatible LGPL libraries in the cache after closing the application;
they are not overwritten on warm launches. Older caches are not silently deleted.
An embedded resource/cache marker is not anti-tamper protection and not DRM.
The release-specific license audit remains the distributor's responsibility.
