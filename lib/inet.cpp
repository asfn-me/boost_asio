#include <string>
#include <system_error>

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/http.hpp>

#include "inet.hpp"

/**************************************************************************************************************************************************************/
namespace inet {

/**************************************************************************************************************************************************************/
namespace internal {

/**************************************************************************************************************************************************************/
class resolver {
protected:
	boost::asio::io_context                                             ioc;
	boost::asio::ip::basic_resolver_results<boost::asio::ip::tcp> const resolved;

public:
	resolver(std::string const &host, uint16_t const port)
	: resolved{boost::asio::ip::tcp::resolver{ioc}.resolve(host, std::to_string(port))} {
std::cout << "Resolved" << std::endl;
	}
};

/**************************************************************************************************************************************************************/
class http {
	std::string const host;

	/******************************/
	virtual
	void
	write(boost::beast::http::request<boost::beast::http::string_body> const &req) = 0;

	/******************************/
	virtual
	void
	read(boost::beast::flat_buffer &buf, boost::beast::http::response<boost::beast::http::dynamic_body> &res) = 0;

	/******************************/
	std::string
	perform(
		boost::beast::http::request<boost::beast::http::string_body> &req,
		std::string const &path,
		std::string const &data,
		std::map<std::string, std::string> const &fields = {})
	{
		req.set(boost::beast::http::field::accept, "*/*");

		req.set(boost::beast::http::field::host, host);
		req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

		for (auto const &[key, value]: fields) {
			req.set(key, value);
		}

		write(req);

		boost::beast::flat_buffer buf;
		boost::beast::http::response<boost::beast::http::dynamic_body> res;

		read(buf, res);

		return boost::beast::buffers_to_string(res.body().data());
	}

protected:
	http(std::string const &host)
	: host{host} {
	}

	/******************************/
	http(std::string &&host)
	: host{std::move(host)} {
	}

	/******************************/
	std::string
	post(std::string const &path, std::string const &data, std::map<std::string, std::string> const &fields = {}) {
		boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, path, 11};

		req.set(boost::beast::http::field::content_type, "application/x-www-form-urlencoded");

		req.body() = data;
		req.prepare_payload();

		return perform(req, path, data, fields);
	}

	/******************************/
	std::string
	get(std::string const &path, std::map<std::string, std::string> const &fields = {}) {
		boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::get, path, 11};

		return perform(req, path, {}, fields);
	}
};

/**************************************************************************************************************************************************************/
class pre_web {
protected:
	using const_buffer   = boost::asio::const_buffer;
	using dynamic_buffer = boost::asio::dynamic_string_buffer<char, std::char_traits<char>, std::allocator<char>>;
	using static_string  = boost::beast::websocket::ping_data;
	using error_code     = boost::system::error_code;

	/******************************/
	virtual
	void
	write(const_buffer &&) = 0;

	/******************************/
	virtual
	void
	read(dynamic_buffer &&) = 0;

	/******************************/
	virtual
	void
	ping(static_string &&) = 0;

	/******************************/
	virtual
	void
	set_non_blocking(bool const value, error_code &ec) = 0;
};

/**************************************************************************************************************************************************************/
class web: pre_web {
protected:
	using pre_web::const_buffer;
	using pre_web::dynamic_buffer;
	using pre_web::static_string;
	using pre_web::error_code;

	using pre_web::write;
	using pre_web::read;
	using pre_web::ping;
	using pre_web::set_non_blocking;

	/******************************/
	void
	write(std::string const &msg) {
		write(boost::asio::buffer(msg));
	}

	/******************************/
	std::string
	read() {
		std::string s;

		read(boost::asio::dynamic_buffer(s));
		return s;
	}

	/******************************/
	void
	ping(std::string const &msg) {
		ping(static_cast<static_string>(msg));
	}

	/******************************/
	void
	set_non_blocking(bool const value) {
		error_code ec;

		set_non_blocking(value, ec);

		if (ec) {
			throw std::system_error{ec};
		}
	}
};

/**************************************************************************************************************************************************************/
class ctx_adjust_verify_mode {
	boost::asio::ssl::context &ctx;

public:
	ctx_adjust_verify_mode(boost::asio::ssl::context &ctx)
	: ctx{ctx} {
		ctx.set_default_verify_paths();
		ctx.set_verify_mode(boost::asio::ssl::verify_peer);
	}

	/******************************/
	operator boost::asio::ssl::context &() const noexcept {
		return ctx;
	}
};

/**************************************************************************************************************************************************************/
class tcp_sock: protected resolver {
protected:
	boost::asio::ip::tcp::socket s;

public:
	tcp_sock(std::string const &host, uint16_t const port)
	: resolver{host, port}
	, s{ioc} {
	}

	/******************************/
	~tcp_sock() try {
		boost::system::error_code ec;

std::cout << "TCP shutdown" << std::endl;
		s.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
	} catch (...) {
		return;
	}
};

/**************************************************************************************************************************************************************/
class tls_sock: protected resolver {
	boost::asio::ssl::context ctx;

protected:
	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> s;

public:
	tls_sock(std::string const &host, uint16_t const port, boost::asio::ssl::context_base::method const tlsv)
	: resolver{host, port}
	, ctx{tlsv}
	, s{ioc, ctx_adjust_verify_mode{ctx}} {
	}

	/******************************/
	~tls_sock() try {
		boost::system::error_code ec;

std::cout << "TLS shutdown" << std::endl;
		s.shutdown(ec);
	} catch (...) {
		return;
	}
};

/**************************************************************************************************************************************************************/
class web_tcp_sock: protected resolver {
protected:
	boost::beast::websocket::stream<boost::asio::ip::tcp::socket> ws;

public:
	web_tcp_sock(std::string const &host, uint16_t const port)
	: resolver{host, port}
	, ws{ioc} {
	}

	/******************************/
	~web_tcp_sock() try {
		boost::system::error_code ec;

std::cout << "WEB/TCP shutdown" << std::endl;
		ws.close(boost::beast::websocket::close_code::normal, ec);
	} catch (...) {
		return;
	}
};

/**************************************************************************************************************************************************************/
class web_tls_sock: protected resolver {
	boost::asio::ssl::context ctx;

protected:
	boost::beast::websocket::stream<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> ws;

public:
	web_tls_sock(std::string const &host, uint16_t const port, boost::asio::ssl::context_base::method const tlsv)
	: resolver{host, port}
	, ctx{tlsv}
	, ws{ioc, ctx_adjust_verify_mode{ctx}} {
	}

	/******************************/
	~web_tls_sock() try {
		boost::system::error_code ec;

std::cout << "WEB/TLS shutdown" << std::endl;
		ws.close(boost::beast::websocket::close_code::normal, ec);
	} catch (...) {
		return;
	}
};


/**************************************************************************************************************************************************************/
class tcp_wrapper {
protected:
	tcp_wrapper(
		boost::asio::ip::tcp::socket &s,
		boost::asio::ip::basic_resolver_results<boost::asio::ip::tcp> const &resolved)
	{
		boost::asio::connect(s, std::begin(resolved), std::end(resolved));
std::cout << "TCP Connected" << std::endl;
	}
};

/**************************************************************************************************************************************************************/
class tls_wrapper: private tcp_wrapper {
protected:
	tls_wrapper(
		boost::asio::ssl::stream<boost::asio::ip::tcp::socket> &s,
		boost::asio::ip::basic_resolver_results<boost::asio::ip::tcp> const &resolved,
		std::string const &host)
	: tcp_wrapper{s.next_layer(), resolved} {
		if (!SSL_set_tlsext_host_name(s.native_handle(), host.c_str())) {
			throw boost::beast::system_error(
				boost::beast::error_code(
					static_cast<int>(::ERR_get_error()),
					boost::asio::error::get_ssl_category()),
				"Failed to set SNI Hostname");
		}

		s.handshake(boost::asio::ssl::stream_base::client);
std::cout << "TLS connected" << std::endl;
	}
};

/**************************************************************************************************************************************************************/
class web_tcp_wrapper: private tcp_wrapper {
protected:
	web_tcp_wrapper(
		boost::beast::websocket::stream<boost::asio::ip::tcp::socket> &ws,
		boost::asio::ip::basic_resolver_results<boost::asio::ip::tcp> const &resolved,
		std::string const &api,
		std::string const &host,
		std::uint16_t const port)
	: tcp_wrapper{ws.next_layer(), resolved} {
		ws.handshake(host + ':' + std::to_string(port), api);
std::cout << "WEB/TCP connected" << std::endl;
	}
};

/**************************************************************************************************************************************************************/
class web_tls_wrapper: private tls_wrapper {
protected:
	web_tls_wrapper(
		boost::beast::websocket::stream<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> &ws,
		boost::asio::ip::basic_resolver_results<boost::asio::ip::tcp> const &resolved,
		std::string const &api,
		std::string const &host,
		std::uint16_t const port)
	: tls_wrapper{ws.next_layer(), resolved, host} {
		ws.handshake(host + ':' + std::to_string(port), api);
std::cout << "WEB/TLS connected" << std::endl;
	}
};

/**************************************************************************************************************************************************************/
class tcp: tcp_sock, tcp_wrapper, http {
	void
	write(boost::beast::http::request<boost::beast::http::string_body> const &req) override {
		boost::beast::http::write(s, req);
	}

	/******************************/
	void
	read(boost::beast::flat_buffer &buf, boost::beast::http::response<boost::beast::http::dynamic_body> &res) override {
		boost::beast::http::read(s, buf, res);
	}

public:
	tcp(std::string const &host, uint16_t const port = 80)
	: tcp_sock{host, port}
	, tcp_wrapper{s, resolved}
	, http{host} {
	}

	/******************************/
	using http::get;
	using http::post;
};

/**************************************************************************************************************************************************************/
class tls: tls_sock, tls_wrapper, http {
	void
	write(boost::beast::http::request<boost::beast::http::string_body> const &req) override {
		boost::beast::http::write(s, req);
	}

	/******************************/
	void
	read(boost::beast::flat_buffer &buf, boost::beast::http::response<boost::beast::http::dynamic_body> &res) override {
		boost::beast::http::read(s, buf, res);
	}

public:
	tls(std::string const &host, uint16_t const port = 443, boost::asio::ssl::context_base::method const tlsv = boost::asio::ssl::context::tlsv12)
	: tls_sock{host, port, tlsv}
	, tls_wrapper{s, resolved, host}
	, http{host} {
	}

	/******************************/
	tls(std::string const &host, uint16_t const port)
	: tls{host, port, boost::asio::ssl::context::tlsv12} {
	}

	/******************************/
	tls(std::string const &host, boost::asio::ssl::context_base::method const tlsv)
	: tls{host, 443, tlsv} {
	}

	/******************************/
	using http::get;
	using http::post;
};

/**************************************************************************************************************************************************************/
class web_tcp: web_tcp_sock, web_tcp_wrapper, web {
	void
	write(const_buffer &&buf) override {
		ws.write(buf);
	}

	/******************************/
	void
	read(dynamic_buffer &&buf) override {
		ws.read(buf);
	}

	/******************************/
	void
	ping(static_string &&msg) override {
		ws.ping(msg);
	}

	/******************************/
	void
	set_non_blocking(bool const value, error_code &ec) override {
		ws.next_layer().non_blocking(value, ec);
	}

public:
	web_tcp(std::string const &api, std::string const &host, uint16_t const port = 80)
	: web_tcp_sock{host, port}
	, web_tcp_wrapper{ws, resolved, api, host, port} {
	}

	/******************************/
	using web::write;
	using web::read;
	using web::ping;
	using web::set_non_blocking;
};

/**************************************************************************************************************************************************************/
class web_tls final: web_tls_sock, web_tls_wrapper, web {
	void
	write(const_buffer &&buf) override {
		ws.write(buf);
	}

	/******************************/
	void
	read(dynamic_buffer &&buf) override {
		error_code ec;

		ws.read(buf, ec);

		if (ec) {
			if (ec == boost::asio::error::would_block) {
				throw inet::web::would_block{};
			}

			throw boost::system::system_error{ec};
		}
	}

	/******************************/
	void
	ping(static_string &&msg) override {
		ws.ping(msg);
	}

	/******************************/
	void
	set_non_blocking(bool const value, error_code &ec) override final {
		ws.next_layer().next_layer().non_blocking(value, ec);
	}

public:
	web_tls(std::string const &api, std::string const &host, uint16_t const port = 443, boost::asio::ssl::context_base::method const tlsv = boost::asio::ssl::context::tlsv12)
	: web_tls_sock{host, port, tlsv}
	, web_tls_wrapper{ws, resolved, api, host, port} {
	}

	/******************************/
	web_tls(std::string const &api, std::string const &host, uint16_t const port)
	: web_tls{api, host, port, boost::asio::ssl::context::tlsv12} {
	}

	/******************************/
	web_tls(std::string const &api, std::string const &host, boost::asio::ssl::context_base::method const tlsv)
	: web_tls{api, host, 443, tlsv} {
	}

	/******************************/
	using web::write;
	using web::read;
	using web::ping;
	using web::set_non_blocking;
};

/**************************************************************************************************************************************************************/
} // namespace internal

/**************************************************************************************************************************************************************/
void
tls::deleter(void *const tls) {
	delete reinterpret_cast<internal::tls *>(tls);
}

/**************************************************************************************************************************************************************/
tls::tls(std::string const &host)
: pimpl{new internal::tls{host}, deleter} {
}

/**************************************************************************************************************************************************************/
void
tls::reinit(std::string const &host) {
	pimpl = std::unique_ptr<void, decltype(&deleter)>{new internal::tls{host}, deleter};
}

/**************************************************************************************************************************************************************/
std::string
tls::get(std::string const &path, std::map<std::string, std::string> const &fields) {
	return reinterpret_cast<internal::tls *>(pimpl.get())->get(path, fields);
}

/**************************************************************************************************************************************************************/
std::string
tls::post(std::string const &path, std::string const &data, std::map<std::string, std::string> const &fields) {
	return reinterpret_cast<internal::tls *>(pimpl.get())->post(path, data, fields);
}

/**************************************************************************************************************************************************************/
void
web::deleter(void *const web) {
	delete reinterpret_cast<internal::web_tls *>(web);
}

/**************************************************************************************************************************************************************/
web::web(std::string const &api, std::string const &host)
: pimpl{new internal::web_tls{api, host}, deleter} {
}

/**************************************************************************************************************************************************************/
void
web::reinit(std::string const &api, std::string const &host) {
	pimpl = std::unique_ptr<void, decltype(&deleter)>{new internal::web_tls{api, host}, deleter};
}

/**************************************************************************************************************************************************************/
void
web::write(std::string const &msg) {
	reinterpret_cast<internal::web_tls *>(pimpl.get())->write(msg);
}

/**************************************************************************************************************************************************************/
std::string
web::read() {
	return reinterpret_cast<internal::web_tls *>(pimpl.get())->read();
}

/**************************************************************************************************************************************************************/
void
web::ping(std::string const &msg) {
	reinterpret_cast<internal::web_tls *>(pimpl.get())->ping(msg);
}

/**************************************************************************************************************************************************************/
void
web::set_non_blocking(bool const value) {
	reinterpret_cast<internal::web_tls *>(pimpl.get())->set_non_blocking(value);
}

/**************************************************************************************************************************************************************/
} //namespace inet
