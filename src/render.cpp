#include "render.h"

#include <cstdio>
#include <ctime>

namespace procrib {

namespace {

const char* kReset = "\x1b[0m";
const char* kDim = "\x1b[90m";
const char* kRed = "\x1b[31m";
const char* kGreen = "\x1b[32m";
const char* kYellow = "\x1b[33m";
const char* kCyan = "\x1b[36m";
const char* kBold = "\x1b[1m";

size_t glyphs(const std::string& s) {
    size_t n = 0;
    for (unsigned char c : s)
        if ((c & 0xC0) != 0x80) n++;
    return n;
}

std::string clip(const std::string& s, size_t width) {
    if (glyphs(s) <= width) return s;
    size_t n = 0, i = 0;
    for (; i < s.size(); i++) {
        if (((unsigned char)s[i] & 0xC0) != 0x80 && ++n > width - 1) break;
    }
    return s.substr(0, i) + "~";
}

std::string cpu_text(const Proc& p) {
    char buf[32];
    if (p.cpu_pct >= 0) std::snprintf(buf, sizeof buf, "%5.1f%%", p.cpu_pct);
    else std::snprintf(buf, sizeof buf, "%5.1fs", p.cpu_time / 1e7);
    return buf;
}

std::string link_note(const Node& n) {
    switch (n.link) {
        case Link::Orphan: return "parent " + std::to_string(n.p.ppid) + " not running";
        case Link::PidReused: return "parent pid " + std::to_string(n.p.ppid) + " was reused, ignored";
        case Link::CycleBroken: return "parent loop cut here";
        default: return "";
    }
}

const char* link_name(Link l) {
    switch (l) {
        case Link::Root: return "root";
        case Link::Child: return "child";
        case Link::Orphan: return "orphan";
        case Link::PidReused: return "pid_reused";
        case Link::CycleBroken: return "cycle_broken";
    }
    return "";
}

const char* access_name(Access a) {
    switch (a) {
        case Access::Full: return "full";
        case Access::Denied: return "denied";
        case Access::Gone: return "gone";
        case Access::Kernel: return "kernel";
    }
    return "";
}

const char* sig_class(const std::string& s) {
    if (s.empty()) return "";
    if (s.compare(0, 8, "unsigned") == 0) return "bad";
    if (s.compare(0, 6, "signed") == 0) return "ok";
    return "warn";
}

const char* sig_color(const std::string& s) {
    std::string c = sig_class(s);
    if (c == "ok") return kGreen;
    if (c == "bad") return kRed;
    return kYellow;
}

void console_node(const Tree& t, int idx, const std::string& prefix, bool last, bool top,
                  const ConsoleOpts& o, std::string& out) {
    const Node& n = t.nodes[idx];
    const Proc& p = n.p;
    auto paint = [&](const char* c, const std::string& s) {
        return o.color ? std::string(c) + s + kReset : s;
    };

    std::string branch = top ? "" : (last ? "`-- " : "+-- ");
    std::string head = prefix + branch;
    std::string tail = " (" + std::to_string(p.pid) + ")";
    size_t room = (size_t)o.name_width > glyphs(head) + glyphs(tail) + 8
                      ? o.name_width - glyphs(head) - glyphs(tail)
                      : 8;
    std::string label = head + clip(p.name, room) + tail;
    std::string pad(glyphs(label) < (size_t)o.name_width ? o.name_width - glyphs(label) : 0, ' ');

    bool dim = p.access == Access::Denied || p.access == Access::Gone;
    std::string line = o.color ? (dim ? kDim : kBold) + label + kReset : label;
    line += pad + "  ";
    if (p.access == Access::Gone) {
        line += paint(kDim, "exited");
    } else {
        char mem[32];
        std::snprintf(mem, sizeof mem, "%10s", format_bytes(p.working_set).c_str());
        line += mem + std::string("  ") + cpu_text(p);
        if (!p.sig.empty()) line += "  " + paint(sig_color(p.sig), p.sig);
        if (p.access == Access::Denied) line += "  " + paint(kDim, "[no access]");
    }
    std::string note = link_note(n);
    if (!note.empty()) line += "  " + paint(kYellow, "<" + note + ">");
    out += line + "\n";

    std::string kid_prefix = top ? "" : prefix + (last ? "    " : "|   ");
    if (o.verbose) {
        std::string detail = top ? "" : kid_prefix;
        if (!p.path.empty()) out += paint(kCyan, detail + "  " + p.path) + "\n";
        if (!p.cmdline.empty()) out += paint(kDim, detail + "  > " + p.cmdline) + "\n";
    }
    for (size_t i = 0; i < n.kids.size(); i++)
        console_node(t, n.kids[i], kid_prefix, i + 1 == n.kids.size(), false, o, out);
}

void json_node(const Tree& t, int idx, int depth, std::string& out) {
    const Node& n = t.nodes[idx];
    const Proc& p = n.p;
    std::string in(depth * 2, ' ');
    out += in + "{\n";
    auto str = [&](const char* k, const std::string& v) {
        out += in + "  \"" + k + "\": \"" + json_escape(v) + "\",\n";
    };
    auto num = [&](const char* k, const std::string& v) {
        out += in + "  \"" + k + "\": " + v + ",\n";
    };
    num("pid", std::to_string(p.pid));
    num("ppid", std::to_string(p.ppid));
    str("name", p.name);
    str("path", p.path);
    str("cmdline", p.cmdline);
    str("start", format_filetime(p.start));
    str("access", access_name(p.access));
    str("link", link_name(n.link));
    num("threads", std::to_string(p.threads));
    num("working_set", std::to_string(p.working_set));
    num("private_bytes", std::to_string(p.private_bytes));
    char cpu[32];
    std::snprintf(cpu, sizeof cpu, "%.3f", p.cpu_time / 1e7);
    num("cpu_seconds", cpu);
    if (p.cpu_pct >= 0) {
        std::snprintf(cpu, sizeof cpu, "%.2f", p.cpu_pct);
        num("cpu_percent", cpu);
    }
    str("signature", p.sig);
    out += in + "  \"children\": [";
    for (size_t i = 0; i < n.kids.size(); i++) {
        out += i ? ",\n" : "\n";
        json_node(t, n.kids[i], depth + 2, out);
    }
    out += n.kids.empty() ? "]\n" : "\n" + in + "  ]\n";
    out += in + "}";
}

void html_row(const Node& n, std::string& out) {
    const Proc& p = n.p;
    out += "<span class=\"name\">" + html_escape(p.name) + "</span> <span class=\"pid\">" +
           std::to_string(p.pid) + "</span>";
    if (p.access == Access::Gone) {
        out += " <span class=\"tag gone\">exited</span>";
    } else {
        out += " <span class=\"mem\">" + format_bytes(p.working_set) + "</span>";
        char cpu[32];
        std::snprintf(cpu, sizeof cpu, "%.1fs", p.cpu_time / 1e7);
        out += std::string(" <span class=\"cpu\">") + cpu + "</span>";
        if (!p.sig.empty())
            out += std::string(" <span class=\"tag ") + sig_class(p.sig) + "\">" +
                   html_escape(p.sig) + "</span>";
        if (p.access == Access::Denied) out += " <span class=\"tag gone\">no access</span>";
    }
    std::string note = link_note(n);
    if (!note.empty()) out += " <span class=\"tag warn\">" + html_escape(note) + "</span>";
}

void html_node(const Tree& t, int idx, std::string& out) {
    const Node& n = t.nodes[idx];
    const Proc& p = n.p;
    bool dim = p.access == Access::Denied || p.access == Access::Gone;
    std::string cls = dim ? "row dim" : "row";
    std::string meta;
    if (!p.path.empty()) meta += "<div class=\"meta\">" + html_escape(p.path) + "</div>";
    if (!p.cmdline.empty()) meta += "<div class=\"meta cmd\">" + html_escape(p.cmdline) + "</div>";
    if (p.start) meta += "<div class=\"meta\">started " + format_filetime(p.start) + ", " +
                         std::to_string(p.threads) + " threads, private " +
                         format_bytes(p.private_bytes) + "</div>";

    if (n.kids.empty()) {
        out += "<div class=\"leaf\"><div class=\"" + cls + "\">";
        html_row(n, out);
        out += "</div>" + meta + "</div>\n";
        return;
    }
    out += "<details open><summary class=\"" + cls + "\">";
    html_row(n, out);
    out += "</summary>" + meta + "<div class=\"kids\">\n";
    for (int k : n.kids) html_node(t, k, out);
    out += "</div></details>\n";
}

const char* kHtmlHead = R"(<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>procrib process tree</title>
<style>
body{font:13px monospace;margin:1em 1.5em}
.sub{color:#555;margin-bottom:.5em}
.bar{margin-bottom:.8em}
input{width:16em}
summary{cursor:pointer}
.kids{margin-left:1.2em;border-left:1px solid #bbb;padding-left:.7em}
.leaf{margin-left:1em}
.name{font-weight:bold}
.dim{color:#777}
.dim .name{font-weight:normal}
.pid,.mem,.cpu{color:#444}
.tag{font-size:smaller;border:1px solid #bbb;padding:0 4px}
.tag.ok{color:#116611}
.tag.bad{color:#a40000}
.tag.warn{color:#7a5200}
.meta{color:#555;margin-left:1.2em;word-break:break-all}
.hit .name{background:#ffec99}
</style></head><body>
)";

const char* kHtmlTail = R"(<script>
const all = () => document.querySelectorAll('details');
document.getElementById('open').onclick = () => all().forEach(d => d.open = true);
document.getElementById('close').onclick = () => all().forEach(d => d.open = false);
document.getElementById('q').oninput = e => {
  const q = e.target.value.toLowerCase();
  document.querySelectorAll('.row').forEach(r => r.classList.remove('hit'));
  if (!q) return;
  all().forEach(d => d.open = false);
  document.querySelectorAll('.row').forEach(r => {
    const box = r.closest('.leaf, details');
    const meta = [...box.children].filter(c => c.classList.contains('meta')).map(c => c.textContent).join(' ');
    if ((r.textContent + ' ' + meta).toLowerCase().includes(q)) {
      r.classList.add('hit');
      for (let d = r.closest('details'); d; d = d.parentElement.closest('details')) d.open = true;
    }
  });
};
</script></body></html>
)";

}  // namespace

std::string json_escape(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\u%04x", c);
                    o += b;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

std::string html_escape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            default: o += c;
        }
    }
    return o;
}

std::string format_bytes(uint64_t n) {
    const char* unit[] = {"B", "KB", "MB", "GB", "TB"};
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1024 && u < 4) {
        v /= 1024;
        u++;
    }
    char buf[32];
    if (u == 0) std::snprintf(buf, sizeof buf, "%llu B", (unsigned long long)n);
    else std::snprintf(buf, sizeof buf, "%.1f %s", v, unit[u]);
    return buf;
}

std::string format_filetime(uint64_t ft) {
    if (!ft) return "";
    const uint64_t epoch_diff = 11644473600ULL;
    uint64_t secs = ft / 10000000ULL;
    if (secs < epoch_diff) return "";
    std::time_t tt = static_cast<std::time_t>(secs - epoch_diff);
    std::tm* tm = std::gmtime(&tt);
    if (!tm) return "";
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", tm);
    return buf;
}

std::string render_console(const Tree& t, const ConsoleOpts& o) {
    std::string out;
    for (int r : t.roots) console_node(t, r, "", true, true, o, out);
    return out;
}

std::string render_json(const Tree& t, const std::string& generated) {
    std::string out = "{\n  \"generated\": \"" + json_escape(generated) + "\",\n";
    out += "  \"count\": " + std::to_string(t.nodes.size()) + ",\n  \"processes\": [";
    for (size_t i = 0; i < t.roots.size(); i++) {
        out += i ? ",\n" : "\n";
        json_node(t, t.roots[i], 2, out);
    }
    out += t.roots.empty() ? "]\n}\n" : "\n  ]\n}\n";
    return out;
}

std::string render_html(const Tree& t, const std::string& generated) {
    std::string out = kHtmlHead;
    out += "<h1>procrib</h1><div class=\"sub\">" + html_escape(generated) + ", " +
           std::to_string(t.nodes.size()) + " processes</div>\n";
    out += "<div class=\"bar\"><button id=\"open\">expand all</button>"
           "<button id=\"close\">collapse all</button>"
           "<input id=\"q\" placeholder=\"filter by name, pid, path\"></div>\n";
    for (int r : t.roots) html_node(t, r, out);
    out += kHtmlTail;
    return out;
}

}  // namespace procrib
