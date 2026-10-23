cmake_minimum_required(VERSION 3.24)
project(WinRARClone VERSION 7.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

if (WIN32)
    add_compile_definitions(UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

if (MSVC)
    add_compile_options(/utf-8 /W3)
else()
    add_compile_options(-Wall -Wextra)
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(ZLIB REQUIRED)
find_package(LibArchive REQUIRED)

# ---------------------------------------------------------------------------
# Core engine (no Qt dependency) — Phase 1 deliverable
# ---------------------------------------------------------------------------
add_library(wrc_core STATIC
    src/core/dictionary_mgr.cpp
    src/core/compressor.cpp
    src/core/decompressor.cpp
    src/core/lzss.cpp
    src/core/progress_tracker.cpp
    src/core/volumes.cpp
    src/core/formats/zip_format.cpp
    src/core/formats/wsar_format.cpp
    src/core/formats/sevenzip_format.cpp
    src/core/formats/libarchive_reader.cpp
    src/utils/file_system.cpp
    src/utils/security.cpp
    src/os_integration/context_menu.cpp
)
target_include_directories(wrc_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(wrc_core PUBLIC ZLIB::ZLIB LibArchive::LibArchive bcrypt shell32 advapi32)

# ---------------------------------------------------------------------------
# CLI front-end (headless core engine)
# ---------------------------------------------------------------------------
add_executable(wrclone
    src/cli/main_cli.cpp
)
target_link_libraries(wrclone PRIVATE wrc_core)

# ---------------------------------------------------------------------------
# Qt 6 desktop GUI — classic WinRAR layout (Phase 2)
# ---------------------------------------------------------------------------
add_executable(wrclone_gui WIN32
    src/ui/main.cpp
    src/ui/main_window.cpp
    src/ui/archive_dialog.cpp
    src/ui/progress_dialog.cpp
    src/ui/extract_dialog.cpp
    src/ui/info_dialog.cpp
)
target_link_libraries(wrclone_gui PRIVATE wrc_core Qt6::Widgets)
