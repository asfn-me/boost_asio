cmake_minimum_required (VERSION 3.13)

project (BoostAPIWebSocket
	VERSION 0.0.0.0
	DESCRIPTION "Boost API WebSocket"
	LANGUAGES CXX
)

set (CMAKE_CXX_COMPILER g++)

set (CMAKE_VERBOSE_MAKEFILE ON)

find_package (Boost
	COMPONENTS system
	REQUIRED
)

find_library (SSL
	NAMES ssl
	REQUIRED
)

find_library (Crypto
	NAMES crypto
	REQUIRED
)

find_package (Threads
	REQUIRED
)

add_subdirectory (lib)
add_subdirectory (src)
