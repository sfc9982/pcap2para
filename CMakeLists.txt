cmake_minimum_required(VERSION 3.8)
cmake_policy(SET CMP0144 NEW)
cmake_policy(SET CMP0074 NEW)

project("pcap2rsa")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(TARGET_NAME pcap2rsa)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(PcapPlusPlus_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/pcapplusplus-23.09-windows-mingw64-x86_64-gcc-13.2.0)

set(Packet_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/npcap-sdk-1.13)
# set(Packet_INCLUDE_DIR ${Packet_ROOT}/Include)
# set(Packet_LIBRARY ${Packet_ROOT}/Lib/x64/Packet.lib)

set(PCAP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/npcap-sdk-1.13)
# set(PCAP_INCLUDE_DIR ${PCAP_ROOT}/Include/pcap)
# set(PCAP_LIBRARY ${PCAP_ROOT}/Lib/x64/wpcap.lib)

set(BOOST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/boost-1.84.0)
set(Boost_NO_SYSTEM_PATHS ON)

find_package(Boost REQUIRED)
find_package(PcapPlusPlus REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})
include_directories(${Packet_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/args)

# fix CMAKE_C_COMPILER_ARCHITECTURE_ID for gcc/clang
if (NOT CMAKE_C_COMPILER_ARCHITECTURE_ID)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        if (CMAKE_C_COMPILER_PREDEFINES_COMMAND)
            set(_COMPILER_PATH ${CMAKE_C_COMPILER_PREDEFINES_COMMAND})
        elseif (CMAKE_CXX_COMPILER_PREDEFINES_COMMAND)
            set(_COMPILER_PATH ${CMAKE_CXX_COMPILER_PREDEFINES_COMMAND})
        endif()
        if ("-m32" IN_LIST _COMPILER_PATH)
            set(CMAKE_C_COMPILER_ARCHITECTURE_ID x86)
        elseif (_COMPILER_PATH MATCHES ".*[/\\\\]([^-]+)-(.+)-(g\\+\\+|gcc|clang|clang\\+\\+)\\..*")
            set(CMAKE_C_COMPILER_ARCHITECTURE_ID ${CMAKE_MATCH_1})
        endif()

        if (NOT CMAKE_C_COMPILER_ARCHITECTURE_ID)
            execute_process(
                COMMAND ${_COMPILER_PATH} -v
                OUTPUT_VARIABLE  _COMPILER_V_OUTPUT
                ERROR_VARIABLE  _COMPILER_V_OUTPUT
            )
            string(REGEX MATCH "Target:[ \\t]*([^ \t\n]*)" GCC_TARGET "${_COMPILER_V_OUTPUT}")
            string(REGEX MATCH "([^-]*)-([^-]*)-(.*)" CMAKE_C_COMPILER_ARCHITECTURE_ID "${CMAKE_MATCH_1}")
            set(CMAKE_C_COMPILER_ARCHITECTURE_ID ${CMAKE_MATCH_1})
            unset(_COMPILER_V_OUTPUT)
        endif()
        unset(_COMPILER_PATH)
    endif()
endif()
string(REGEX REPLACE "[xX]86_64|X64" "x64" CMAKE_C_COMPILER_ARCHITECTURE_ID ${CMAKE_C_COMPILER_ARCHITECTURE_ID})
string(REGEX REPLACE "[iI][1-7]86|X86" "x86" CMAKE_C_COMPILER_ARCHITECTURE_ID ${CMAKE_C_COMPILER_ARCHITECTURE_ID})

if (MSVC)
    option(MSVC_USE_STATIC_CRT "Build target(s) with static crt library" OFF)
    string(TOUPPER ${CMAKE_BUILD_TYPE} _MSVC_BUILD_CONFIG)
    set(_EDX_ESC "
    if (MSVC_USE_STATIC_CRT)
        message("-- Using ${_EDX_ESC}34mSTATIC${_EDX_ESC}0m linked CRT (/MT)")
        string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_${_MSVC_BUILD_CONFIG} ${CMAKE_C_FLAGS_${_MSVC_BUILD_CONFIG}})
        string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_${_MSVC_BUILD_CONFIG} ${CMAKE_CXX_FLAGS_${_MSVC_BUILD_CONFIG}})
    else()
        message("-- Using ${_EDX_ESC}34mDYNAMIC${_EDX_ESC}0m linked CRT (/MD)")
        string(REPLACE "/MT" "/MD" CMAKE_C_FLAGS_${_MSVC_BUILD_CONFIG} ${CMAKE_C_FLAGS_${_MSVC_BUILD_CONFIG}})
        string(REPLACE "/MT" "/MD" CMAKE_CXX_FLAGS_${_MSVC_BUILD_CONFIG} ${CMAKE_CXX_FLAGS_${_MSVC_BUILD_CONFIG}})
    endif()
else()
    set(MSVC_USE_STATIC_CRT)
endif()

# include_directories(<HEADER_PATH>)

# add_link_options(<LINKER_FLAGS>)

# add_compile_options(<COMPILER_FLAGS>)

aux_source_directory(./ SOURCE_FILES)
add_executable(${TARGET_NAME} ${SOURCE_FILES})
# # target_compile_options(${TARGET_NAME} PRIVATE -stdlib=libstdc++ --target=x86_64-pc-windows-gnu -isystem "C:\\Users\\sfc9982\\Desktop\\EDX\\toolsets\\llvm-mingw-20240308-msvcrt-x86_64\\include\\c++\\v1")
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
	target_compile_options(${TARGET_NAME} PRIVATE -stdlib=libstdc++ --target=x86_64-pc-windows-gnu)
	target_link_options(${TARGET_NAME} PRIVATE -llibstdc++)
endif()
target_link_options(${TARGET_NAME} PRIVATE -static)
target_link_libraries(${TARGET_NAME} PcapPlusPlus::Packet++ PcapPlusPlus::Pcap++ PcapPlusPlus::Common++ Boost::boost)

# target_precompile_headers(${TARGET_NAME} PRIVATE pch_header.h)

# target_link_libraries(${TARGET_NAME}
#    <LIB_NAME>
# )

set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/output/${CMAKE_C_COMPILER_ID}-${CMAKE_C_COMPILER_ARCHITECTURE_ID}-${CMAKE_BUILD_TYPE})

install(TARGETS ${TARGET_NAME}
    RUNTIME_DEPENDENCIES
    PRE_EXCLUDE_REGEXES "system32/|((api-ms-).*\\.dll)|/usr/|/lib/|/lib64/"
    POST_EXCLUDE_REGEXES "system32/|((api-ms-).*\\.dll)|/usr/|/lib/|/lib64/"
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# install(FILES ${SOURCE_FILES}
#    DESTINATION src)
