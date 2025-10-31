
solution "next"
	platforms { "portable", "x86", "x64", "avx", "avx2" }
	configurations { "Debug", "Release", "MemoryCheck" }
	targetdir "bin/"
	rtti "Off"
	warnings "Extra"
	floatingpoint "Fast"
	fatalwarnings { "All" }
	defines { "NEXT_DEVELOPMENT" }
	filter "configurations:Debug"
		symbols "On"
		defines { "_DEBUG", "NEXT_ENABLE_MEMORY_CHECKS=1", "NEXT_ASSERTS=1" }
	filter "configurations:Release"
		optimize "Speed"
		defines { "NDEBUG" }
		editandcontinue "Off"
	filter "system:windows"
		location ("visualstudio")
	filter "platforms:*x86"
		architecture "x86"
	filter "platforms:*x64 or *avx or *avx2"
		architecture "x86_64"

project "next"
	kind "StaticLib"
	files {
		"include/next.h",
		"include/next_*.h",
		"source/next.cpp",
		"source/next_*.cpp",
	}
	includedirs { "include" }
	filter "system:windows"
		linkoptions { "/ignore:4221" }
		disablewarnings { "4324" }

project "hydrogen"
	kind "StaticLib"
	files { 
		"hydrogen/*.c",
		"hydrogen/*.h",
	}
	filter "system:windows"
		disablewarnings { "4324" }
	filter "system:not windows"
		links { "pthread" }

project "test"
	kind "ConsoleApp"
	links { "next" }
	files { "test.cpp" }
	includedirs { "include" }
	filter "system:windows"
		disablewarnings { "4324" }
	filter "system:not windows"
		links { "pthread" }
	filter "system:macosx"
		linkoptions { "-framework SystemConfiguration -framework CoreFoundation" }

project "client"
	kind "ConsoleApp"
	links { "next" }
	files { "client.cpp" }
	includedirs { "include" }
	filter "system:windows"
		disablewarnings { "4324" }
	filter "system:not windows"
		links { "pthread" }
	filter "system:macosx"
		linkoptions { "-framework SystemConfiguration -framework CoreFoundation" }

project "server"
	kind "ConsoleApp"
	links { "next" }
	files { "server.cpp" }
	includedirs { "include" }
	filter "system:windows"
		disablewarnings { "4324" }
	filter "system:not windows"
		links { "pthread" }
	filter "system:macosx"
		linkoptions { "-framework SystemConfiguration -framework CoreFoundation" }
