add_executable(TestTarget main.cpp)

target_compile_definitions(TestTarget PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
