cmake_minimum_required(VERSION 3.10)

# Project Name
project(SilentButDeadly C)

# Ensure we are on Windows
if(NOT WIN32)
    message(FATAL_ERROR "This project is designed for Windows only (Requires WFP).")
endif()

# Create the executable
# Assuming your source file is named SilentButDeadly.c
add_executable(SilentButDeadly SilentButDeadly.c)

# Add Preprocessor Definitions
# _CRT_SECURE_NO_WARNINGS: Suppresses warnings about unsafe C functions
# WIN32_LEAN_AND_MEAN: Excludes rarely-used services from Windows headers
target_compile_definitions(SilentButDeadly PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
)

# Link specific Windows Libraries
# These replace the #pragma comment(lib, ...) directives for better CMake compatibility
target_link_libraries(SilentButDeadly PRIVATE
    Fwpuclnt    # Windows Filtering Platform API
    Ws2_32      # Windows Sockets
    Ole32       # OLE/COM Libraries (for GUIDs)
    Advapi32    # Advanced Windows API (for SID/Admin checks)
    Shlwapi     # Shell Light-weight Utility API (General utility)
)

# Set C Standard (C11 is recommended for modern Windows dev)
set_property(TARGET SilentButDeadly PROPERTY C_STANDARD 11)
