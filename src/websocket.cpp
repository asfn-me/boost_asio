#include <inet.hpp>

#include <exception>
#include <iostream>

/**************************************************************************************************************************************************************/
template <typename T>
void
show_type() {
	std::cout << __PRETTY_FUNCTION__ << std::endl;
}

/**************************************************************************************************************************************************************/
void
tls(std::string const &host, std::string const &path = "/") {
	inet::tls tls{host};

	std::cout << std::endl;
	std::cout << "Get: host: '" << host << "', path: '" << path << "', answer: " << tls.get(path, {}) << std::endl;
	std::cout << std::endl;
}

/**************************************************************************************************************************************************************/
void
websocket(std::string const &host, std::string const &api) {
	inet::web web{api, host};

	 auto const &msgs = {
		"A braced initializer has no type!",
		"A braced initializer has no type!",
		"A braced initializer has no type!",
		"No type corresponds to a braced initializer!"
	};

	std::cout << std::endl;

	show_type<decltype(msgs)>();

	std::cout << std::endl;

	for (auto const &msg: msgs) {
		std::cout << "Write to websocket: '" << msg << "'" << std::endl;
		web.write(msg);
	}

	std::cout << std::endl;

	for (auto cnt{std::size(msgs)}; cnt; --cnt) {
		std::cout << "Read from websocket: '" << web.read() << "'" << std::endl;
	}

	std::cout << std::endl;
}

/**************************************************************************************************************************************************************/
int
main() try {
	tls("api.ipify.org");
	tls("api.ipify.org", "/?format=json");

	// See https://kaazing.com/demos/echo-test/
	websocket("echo.websocket.org", "/");

	return EXIT_SUCCESS;
} catch (std::exception const &e) {
	std::cout << "Exception: " << e.what() << std::endl;
} catch (...) {
	std::cout << "Unhandled exception!" << std::endl;
}
