#ifndef INET_INCLUDED__
#define INET_INCLUDED__

#include <memory>
#include <string>
#include <map>

/**************************************************************************************************************************************************************/
namespace inet {

/**************************************************************************************************************************************************************/
class tls {
	class proxy;

	std::unique_ptr<proxy> pimpl;

public:
	tls(std::string const &host);

	/******************************/
	~tls();

	/******************************/
	void
	reinit(std::string const &host);

	/******************************/
	std::string
	get(std::string const &path, std::map<std::string, std::string> const &fields);

	/******************************/
	std::string
	post(std::string const &path, std::string const &data, std::map<std::string, std::string> const &fields);
};

/**************************************************************************************************************************************************************/
class web {
	class proxy;

	std::unique_ptr<proxy> pimpl;

public:
	class would_block {
	};

	/******************************/
	web(std::string const &api, std::string const &host);

	/******************************/
	~web();

	/******************************/
	void
	reinit(std::string const &api, std::string const &host);

	/******************************/
	void
	write(std::string const &msg);

	/******************************/
	std::string
	read();

	/******************************/
	void
	ping(std::string const &msg = {});

	/******************************/
	void
	set_non_blocking(bool const value);
};

/**************************************************************************************************************************************************************/
} // namespace inet

#endif // INET_INCLUDED__
