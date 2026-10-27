#pragma once
#include <cstdint>
#include <string>

#include "proctree.h"

namespace procrib {

struct ConsoleOpts {
    bool color = true;
    bool verbose = false;  // path and command line under each process
    int name_width = 44;
};

std::string render_console(const Tree& t, const ConsoleOpts& o);
std::string render_json(const Tree& t, const std::string& generated);
std::string render_html(const Tree& t, const std::string& generated);

std::string json_escape(const std::string& s);
std::string html_escape(const std::string& s);
std::string format_bytes(uint64_t n);
std::string format_filetime(uint64_t ft);

}  // namespace procrib
