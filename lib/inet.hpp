#ifndef __INET_INCLUDED
#define __INET_INCLUDED

#include <memory>
#include <string>
#include <map>

/**************************************************************************************************************************************************************/
namespace inet {

/**************************************************************************************************************************************************************/
class tls {
	static
	void
	deleter(void *);

	std::unique_ptr<void, decltype(&deleter)> pimpl;

public:
	tls(std::string const &host);

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
	static
	void
	deleter(void *);

	std::unique_ptr<void, decltype(&deleter)> pimpl;

public:
	class would_block {
	};

	/******************************/
	web(std::string const &api, std::string const &host);

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

#endif // __INET_INCLUDED