project(libgyroid VERSION 1.0 LANGUAGES CXX)

add_library(gyroid SHARED
    src/gyroid.c
    src/handler_select.c
)

target_include_directories(gyroid PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE_src)

target_compile_options(gyroid
	PRIVATE "-DARCH_x86_64" "-Wno-error=pointer-to-int-cast" "-Wno-unused-variable" "-Wno-unused-parameter" "-ggdb" "-fno-omit-frame-pointer" "-O0"
	PUBLIC "-DARCH_x86_64" "-Wno-error=pointer-to-int-cast" "-Wno-unused-variable" "-Wno-unused-parameter" "-ggdb" "-fno-omit-frame-pointer" "-O0"
	INTERFACE "-DARCH_x86_64" "-Wno-error=pointer-to-int-cast" "-Wno-unused-variable" "-Wno-unused-parameter" "-ggdb" "-fno-omit-frame-pointer" "-O0"

)
