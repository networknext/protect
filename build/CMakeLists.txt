
cmake_minimum_required(VERSION 3.10)
add_compile_definitions(NEXT_DEVELOPMENT=1)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ../dist)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../dist)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include_directories(
	"." 
)


# hydrogen

project(hydrogen)
enable_language(C)
file(GLOB HYDROGEN_SOURCE ../lib/hydrogen/*.c)
file(GLOB HYDROGEN_HEADERS ../lib/hydrogen/*.h)
add_library(hydrogen ${HYDROGEN_SOURCE} ${HYDROGEN_HEADERS})


# platform

project(platform)
enable_language(C)
file(GLOB PLATFORM_SOURCE ../lib/platform/*.c)
file(GLOB PLATFORM_HEADERS ../lib/platform/*.h)
add_library(platform ${PLATFORM_SOURCE} ${PLATFORM_HEADERS})
target_include_directories(platform PRIVATE ../lib)
add_dependencies(platform hydrogen)


# shared

project(shared)
enable_language(C)
file(GLOB SHARED_SOURCE ../lib/shared/*.c)
file(GLOB SHARED_HEADERS ../lib/shared/*.h)
add_library(shared ${SHARED_SOURCE} ${SHARED_HEADERS})
target_include_directories(shared PRIVATE ../lib)
add_dependencies(shared platform)
if (UNIX)
    target_link_libraries(shared hydrogen)
endif()


# client backend

add_custom_command(
    COMMENT "Copying proton.h for client backend"
    OUTPUT ../cmd/client_backend/proton.h
    COMMAND bash -c "cp ../lib/proton/proton.h ../cmd/client_backend/proton.h"
    DEPENDS ../lib/proton/proton.h
)

add_custom_command(
    COMMENT "Generating client_backend_xdp_source.h"
    OUTPUT ../cmd/client_backend/client_backend_xdp_source.h
    COMMAND bash -c "mkdir -p ../cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp ../cmd/client_backend/Makefile ../cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp ../cmd/client_backend/proton.h ../cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp ../cmd/client_backend/client_backend_xdp.c ../cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp ../cmd/client_backend/client_backend_shared.h ../cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "cp ../cmd/client_backend/client_backend_constants.h ../cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "tar -zcvf ../cmd/client_backend/client_backend_xdp_source.tar.gz -C ../cmd/client_backend/client_backend_xdp_source ." >/dev/null 2>&1
    COMMAND bash -c "rm -rf ../cmd/client_backend/client_backend_xdp_source"
    COMMAND bash -c "xxd -i ../cmd/client_backend/client_backend_xdp_source.tar.gz" > ../cmd/client_backend/client_backend_xdp_source.h
    COMMAND bash -c "rm -f ../cmd/client_backend/client_backend_xdp_source.tar.gz"
    DEPENDS ../cmd/client_backend/Makefile ../cmd/client_backend/client_backend_xdp.c ../cmd/client_backend/client_backend_shared.h ../cmd/client_backend/client_backend_constants.h ../cmd/client_backend/proton.h
)

project(client_backend)

file(GLOB CLIENT_BACKEND_SOURCE ../cmd/client_backend/*.c)
file(GLOB CLIENT_BACKEND_HEADERS ../cmd/client_backend/*.h)
add_executable(client_backend ${CLIENT_BACKEND_SOURCE} ${CLIENT_BACKEND_HEADERS} ../cmd/client_backend/client_backend_xdp_source.h)
target_include_directories(client_backend PRIVATE ../lib)
add_dependencies(client_backend platform shared)
find_package(Threads REQUIRED)
if (APPLE)
	target_link_libraries(client_backend platform shared Threads::Threads)
elseif (UNIX)
	target_link_libraries(client_backend platform shared bpf xdp Threads::Threads)
endif()


# server xdp

add_custom_command(
    COMMENT "Generating next_server_xdp.h"
    OUTPUT ../sdk/next_server_xdp.h
    COMMAND bash -c "mkdir -p next_server_xdp"
    COMMAND bash -c "cp ../cmd/server_xdp/Makefile next_server_xdp"
    COMMAND bash -c "cp ../cmd/server_xdp/server_xdp.c next_server_xdp"
    COMMAND bash -c "tar -zcvf next_server_xdp.tar.gz -C next_server_xdp ." >/dev/null 2>&1
    COMMAND bash -c "rm -rf next_server_xdp"
    COMMAND bash -c "xxd -i next_server_xdp.tar.gz" > ../sdk/next_server_xdp.h
    COMMAND bash -c "rm -f next_server_xdp.tar.gz"
    DEPENDS ../cmd/server_xdp/Makefile ../cmd/server_xdp/server_xdp.c
)


# ---------------------------------------------------------------------
#                              SDK BELOW HERE
# ---------------------------------------------------------------------


# next

project(next)
enable_language(CXX)
file(GLOB NEXT_SOURCE ../sdk/*.cpp)
file(GLOB NEXT_HEADERS ../sdk/*.h)
add_library(next ${NEXT_SOURCE} ${NEXT_HEADERS} ../sdk/next_server_xdp.h)
add_dependencies(next)
find_package(Threads REQUIRED)
if (APPLE)
    target_link_libraries(next shared Threads::Threads "-framework CoreFoundation" "-framework SystemConfiguration")
else()
    target_link_libraries(next shared Threads::Threads)
endif()


# client

project(client)
enable_language(CXX)
add_executable(client ../cmd/client/client.cpp)
target_include_directories(client PRIVATE ../sdk)
add_dependencies(client next)
target_link_libraries(client next)


# server

project(server)
enable_language(CXX)
add_executable(server ../cmd/server/server.cpp)
target_include_directories(server PRIVATE ../sdk)
add_dependencies(server next)
if (LINUX)
    target_link_libraries(server next bpf xdp)
else()
    target_link_libraries(server next)
endif()


# test

project(test)
enable_language(CXX)
add_executable(test ../cmd/test/test.cpp)
target_include_directories(test PRIVATE ../sdk)
add_dependencies(test next)
target_link_libraries(test next)


# keygen

project(keygen)
enable_language(CXX)
add_executable(keygen ../cmd/keygen/keygen.cpp)
target_include_directories(keygen PRIVATE ../sdk)
add_dependencies(keygen next)
target_link_libraries(keygen next)
