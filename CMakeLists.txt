cmake_minimum_required(VERSION 3.20)
project(Fallout3HFR LANGUAGES CXX)

configure_file(Fallout3HFR.ini Fallout3HFR.ini COPYONLY)

# One source, two ways of loading it.
#   Fallout3HFR.asi  the release form: an ASI plugin for an ASI loader.
#   dinput8.dll      the development form: a DirectInput proxy, used by the
#                    research launchers.
function(fallout3hfr_settings target)
    target_compile_features(${target} PRIVATE cxx_std_20)
    target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
    target_compile_options(${target} PRIVATE /W4 /permissive- /EHsc)
    set_property(TARGET ${target} PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endfunction()

add_library(Fallout3HFR SHARED
    src/dinput8_proxy.cpp
)
fallout3hfr_settings(Fallout3HFR)
target_compile_definitions(Fallout3HFR PRIVATE FALLOUT3HFR_ASI)
set_target_properties(Fallout3HFR PROPERTIES
    OUTPUT_NAME Fallout3HFR
    PREFIX ""
    SUFFIX ".asi"
)

add_library(dinput8 SHARED
    src/dinput8_proxy.cpp
    src/dinput8.def
)
fallout3hfr_settings(dinput8)
set_target_properties(dinput8 PROPERTIES
    OUTPUT_NAME dinput8
    PREFIX ""
)

add_executable(asi_smoke tests/asi_smoke.cpp)
fallout3hfr_settings(asi_smoke)

add_executable(proxy_smoke tests/proxy_smoke.cpp)
target_compile_features(proxy_smoke PRIVATE cxx_std_20)
target_compile_definitions(proxy_smoke PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
target_compile_options(proxy_smoke PRIVATE /W4 /permissive- /EHsc)
set_property(TARGET proxy_smoke PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
