cmake_minimum_required (VERSION 3.13)

set (TARGET boost_api)

add_library (${TARGET} inet.cpp inet.hpp)

set_target_properties (${TARGET}
	PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	CXX_EXTENSIONS OFF
)

target_compile_options (${TARGET}
	PRIVATE -O3 -pthread
)

target_link_options (${TARGET}
	PRIVATE -s
)

target_include_directories (${TARGET}
	PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries (${TARGET}
	Boost::system
	${SSL}
	${Crypto}
	Threads::Threads
)
