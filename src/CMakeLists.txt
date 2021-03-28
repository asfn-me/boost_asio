cmake_minimum_required (VERSION 3.13)

set (TARGET websocket)

add_executable (${TARGET} ${TARGET}.cpp)

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
	PRIVATE -O3 -pthread -s
)

target_link_libraries (${TARGET}
	Boost::system
	${SSL}
	${Crypto}
	boost_api
	Threads::Threads
)
