cmake_minimum_required (VERSION 3.8)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

# 如果支持，请为 MSVC 编译器启用热重载。
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("qt-server")
find_package(Boost 1.83 REQUIRED COMPONENTS system json)
find_package(Threads REQUIRED)

add_executable (qt-server
    "src/main.cpp"
    "src/server/chat_file_store.cpp"
    "src/server/echo_server.cpp"
    "src/server/http_static_server.cpp"
    "src/server/http_static_session.cpp"
    "src/server/upload_token_store.cpp"
    "src/server/session.cpp"
    "src/server/websocket_session.cpp"
    "src/utils/logger.cpp"
)

target_link_libraries(qt-server
PRIVATE
    Boost::system
    Boost::json
    Threads::Threads
)

target_include_directories(qt-server
PRIVATE
    ${Boost_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
