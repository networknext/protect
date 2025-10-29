cmake_minimum_required(VERSION 3.10)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY dist)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY dist)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories(
	"." 
	"lib"
	"sdk/sodium"
)


# sodium

project(sodium)

enable_language(C)

file(GLOB SODIUM_SOURCE sdk/sodium/*.c)
file(GLOB SODIUM_ASSEMBLY sdk/sodium/*.s)
file(GLOB SODIUM_HEADERS sdk/sodium/*.h)

add_library(sodium ${SODIUM_SOURCE} ${SODIUM_ASSEMBLY} ${SODIUM_HEADERS})



# platform

project(platform)

enable_language(C)

file(GLOB PLATFORM_SOURCE lib/platform/*.c)
file(GLOB PLATFORM_HEADERS lib/platform/*.h)

add_library(platform ${PLATFORM_SOURCE} ${PLATFORM_HEADERS})



# shared

project(shared)

enable_language(C)

file(GLOB SHARED_SOURCE lib/shared/*.c)
file(GLOB SHARED_HEADERS lib/shared/*.h)

add_library(shared ${SHARED_SOURCE} ${SHARED_HEADERS})

add_dependencies(shared platform sodium)



# client backend

add_custom_command(
    COMMENT "Generating client_backend_xdp_source.h"
    OUTPUT cmd/client_backend/client_backend_xdp_source.h
    COMMAND bash -c "mkdir -p cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp cmd/client_backend/Makefile cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp cmd/client_backend/client_backend_xdp.c cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp cmd/client_backend/client_backend_shared.h cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp cmd/client_backend/client_backend_constants.h cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "tar -zcvf cmd/client_backend/client_backend_xdp_source.tar.gz -C cmd/client_backend/client_backend_xdp_source ."
    COMMAND bash -c "rm -rf cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "xxd -i cmd/client_backend/client_backend_xdp_source.tar.gz" > cmd/client_backend/client_backend_xdp_source.h
    DEPENDS cmd/client_backend/Makefile cmd/client_backend/client_backend_xdp.c cmd/client_backend/client_backend_shared.h cmd/client_backend/client_backend_constants.h
)

project(client_backend)

file(GLOB CLIENT_BACKEND_SOURCE cmd/client_backend/*.c)
file(GLOB CLIENT_BACKEND_HEADERS cmd/client_backend/*.h)

add_executable(client_backend ${CLIENT_BACKEND_SOURCE} ${CLIENT_BACKEND_HEADERS} cmd/client_backend/client_backend_xdp_source.h)

add_dependencies(client_backend platform shared sodium)

find_package(Threads REQUIRED)

if (APPLE)
	target_link_libraries(client_backend platform shared sodium Threads::Threads)
elseif (UNIX)
	target_link_libraries(client_backend platform shared sodium bpf xdp Threads::Threads)
endif()
