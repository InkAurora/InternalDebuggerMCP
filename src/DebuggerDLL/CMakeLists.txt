set(DEBUGGER_DLL_SOURCES
    src/AccessWatchManager.cpp
    src/dllmain.cpp
    src/DebuggerService.cpp
    src/IpcServer.cpp
    src/MemoryReader.cpp
    src/PatternGenerator.cpp
    src/SignatureGenerator.cpp
    src/PatternScanner.cpp
    src/WatchManager.cpp
    src/Disassembler.cpp
    src/InvokeCallBridge.asm
)

add_library(InternalDebuggerDLL SHARED ${DEBUGGER_DLL_SOURCES})

target_include_directories(InternalDebuggerDLL
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(InternalDebuggerDLL PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

target_link_libraries(InternalDebuggerDLL PRIVATE Psapi)

set_target_properties(InternalDebuggerDLL PROPERTIES
    OUTPUT_NAME "InternalDebuggerDLL"
)
