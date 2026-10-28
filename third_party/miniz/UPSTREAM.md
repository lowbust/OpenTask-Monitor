# miniz 3.0.2

Source: https://github.com/richgel999/miniz/tree/3.0.2
License: MIT, retained in LICENSE and upstream source headers.

miniz.c / .h, miniz_common.h, miniz_zip.c / .h, miniz_tinfl.c / .h,
miniz_tdef.h are unmodified upstream files. miniz_export.h is the project-local
equivalent of the generated static-build export header.

Only ZIP reading / inflate is enabled. No archive writing, zlib-compatible API,
stdio extraction, external DLL, executable loader or network code is used.
The OpenTask native extractor writes through Windows Unicode APIs after path
validation, checks ZIP integrity and uses a version/hash-specific local cache.
