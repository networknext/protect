cmake_minimum_required(VERSION 3.10)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY dist)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY dist)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories(
	"." 
	"lib"
    "sdk/include"
	"sdk/hydrogen"
)


# hydrogen

project(hydrogen)

enable_language(C)

file(GLOB HYDROGEN_SOURCE sdk/hydrogen/*.c)
file(GLOB HYDROGEN_HEADERS sdk/hygrogen/*.h)

add_library(hydrogen ${HYDROGEN_SOURCE} ${HYDROGEN_HEADERS})



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

add_dependencies(shared platform hydrogen)



# next

project(next)

enable_language(CXX)

file(GLOB NEXT_SOURCE sdk/source/*.cpp)
file(GLOB NEXT_HEADERS sdk/include/*.h)

add_library(next ${NEXT_SOURCE} ${NEXT_HEADERS})

add_dependencies(next platform hydrogen)



# client

project(client)

enable_language(CXX)

add_executable(client cmd/client/client.cpp)

add_dependencies(client platform shared hydrogen next)

find_package(Threads REQUIRED)

if (APPLE)
    target_link_libraries(client platform shared hydrogen next Threads::Threads "-framework CoreFoundation" "-framework SystemConfiguration")
else()
    target_link_libraries(client platform shared hydrogen next Threads::Threads)
endif()



# server

project(server)

enable_language(CXX)

add_executable(server cmd/server/server.cpp)

add_dependencies(server platform shared hydrogen next)

find_package(Threads REQUIRED)

if (APPLE)
    target_link_libraries(server platform shared hydrogen next Threads::Threads "-framework CoreFoundation" "-framework SystemConfiguration")
else()
    target_link_libraries(server platform shared hydrogen next Threads::Threads)
endif()



# client backend

add_custom_command(
    COMMENT "Generating client_backend_xdp_source.h"
    OUTPUT cmd/client_backend/client_backend_xdp_source.h
    COMMAND bash -c "mkdir -p cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp cmd/client_backend/Makefile cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp cmd/client_backend/client_backend_xdp.c cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp cmd/client_backend/client_backend_shared.h cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp cmd/client_backend/client_backend_constants.h cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "tar -zcvf cmd/client_backend/client_backend_xdp_source.tar.gz -C cmd/client_backend/client_backend_xdp_source ." >/dev/null 2>&1
    COMMAND bash -c "rm -rf cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "xxd -i cmd/client_backend/client_backend_xdp_source.tar.gz" > cmd/client_backend/client_backend_xdp_source.h
    COMMAND bash -c "rm -f cmd/client_backend/client_backend_xdp_source.tar.gz"
    DEPENDS cmd/client_backend/Makefile cmd/client_backend/client_backend_xdp.c cmd/client_backend/client_backend_shared.h cmd/client_backend/client_backend_constants.h
)

project(client_backend)

file(GLOB CLIENT_BACKEND_SOURCE cmd/client_backend/*.c)
file(GLOB CLIENT_BACKEND_HEADERS cmd/client_backend/*.h)

add_executable(client_backend ${CLIENT_BACKEND_SOURCE} ${CLIENT_BACKEND_HEADERS} cmd/client_backend/client_backend_xdp_source.h)

add_dependencies(client_backend platform shared hydrogen)

find_package(Threads REQUIRED)

if (APPLE)
	target_link_libraries(client_backend platform shared hydrogen Threads::Threads)
elseif (UNIX)
	target_link_libraries(client_backend platform shared hydrogen bpf xdp Threads::Threads)
endif()
