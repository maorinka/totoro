// Files compiled into the binary (the web UI and the bundled vulnerability
// database). assets.cpp is generated at build time by tools/embed.cpp.
#pragma once

#include <cstddef>
#include <string_view>

namespace wisp {

struct Asset {
	const char *path;  // e.g. "web/index.html", "vulndb.json"
	const char *data;
	size_t size;
	const char *mime;
};

const Asset *find_asset(std::string_view path);

}  // namespace wisp
