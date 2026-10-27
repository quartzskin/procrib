#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <thread>

#include "collect.h"
#include "proctree.h"
#include "render.h"

using namespace procrib;

namespace {

const char* kUsage =
    "usage: procrib [options]\n"
    "  -v, --verbose      show image path and command line under each process\n"
    "  --sig              check Authenticode/catalog signatures (slower)\n"
    "  --watch [SECS]     redraw every SECS seconds (default 2), shows CPU %\n"
    "  --html FILE        write a self-contained HTML tree\n"
    "  --json             print the tree as JSON instead of the console view\n"
    "  --demo             use a built-in fake process list (for docs and screenshots)\n"
    "  --no-color         plain output\n"
    "  -h, --help         this text\n";

std::string now_text() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

std::vector<Proc> demo_list() {
    const uint64_t t0 = 133800000000000000ULL;
    auto mk = [&](uint32_t pid, uint32_t ppid, uint64_t age, const char* name, const char* path,
                  const char* cmd, uint64_t mb, double cpu, const char* sig, Access a = Access::Full) {
        Proc p;
        p.pid = pid;
        p.ppid = ppid;
        p.start = t0 + age * 10000000ULL;
        p.name = name;
        p.path = path;
        p.cmdline = cmd;
        p.working_set = mb << 20;
        p.private_bytes = (mb * 3 / 4) << 20;
        p.cpu_time = static_cast<uint64_t>(cpu * 1e7);
        p.threads = 12;
        p.sig = sig;
        p.access = a;
        return p;
    };
    const char* sys32 = "C:\\Windows\\System32\\";
    auto sp = [&](const char* exe) { return std::string(sys32) + exe; };
    return {
        mk(4, 0, 0, "System", "", "", 1, 410.2, "", Access::Kernel),
        mk(620, 4, 5, "smss.exe", "", "", 1, 0.3, "", Access::Denied),
        mk(880, 620, 40, "services.exe", "", "", 9, 14.8, "", Access::Denied),
        mk(1044, 880, 60, "svchost.exe", "", "", 28, 22.1, "", Access::Denied),
        mk(2210, 880, 61, "spoolsv.exe", sp("spoolsv.exe").c_str(), "C:\\Windows\\System32\\spoolsv.exe", 14, 0.9, "signed"),
        mk(4100, 1044, 900, "RuntimeBroker.exe", sp("RuntimeBroker.exe").c_str(), "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding", 18, 2.4, "signed"),
        mk(5320, 1044, 1500, "notepad.exe", sp("notepad.exe").c_str(), "notepad.exe notes.txt", 22, 0.4, "signed (catalog)"),
        mk(3000, 0, 700, "explorer.exe", "C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe", 160, 88.5, "signed"),
        mk(6120, 3000, 2000, "cmd.exe", sp("cmd.exe").c_str(), "\"C:\\Windows\\System32\\cmd.exe\"", 5, 0.1, "signed"),
        mk(7044, 6120, 2400, "build-helper.exe", "D:\\tools\\build-helper.exe", "build-helper.exe --jobs 8", 64, 31.0, "unsigned"),
        mk(7388, 7044, 2410, "worker.exe", "D:\\tools\\worker.exe", "worker.exe --id 3", 41, 12.7, "unsigned"),
        mk(8800, 4321, 1800, "updater.exe", "C:\\Program Files\\Acme\\updater.exe", "updater.exe /silent", 12, 1.2, "invalid 0x800b0109"),
        mk(9100, 880, 3000, "gone.exe", "", "", 0, 0, "", Access::Gone),
        mk(9500, 2210, 50, "stale-child.exe", "C:\\Temp\\stale-child.exe", "stale-child.exe", 3, 0.1, "unsigned"),
    };
}

void put(const std::string& s) { std::fwrite(s.data(), 1, s.size(), stdout); }

}  // namespace

int main(int argc, char** argv) {
    bool demo = false, verbose = false, sig = false, json = false, watch = false, color = true;
    double interval = 2;
    std::string html_path;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "-v" || a == "--verbose") verbose = true;
        else if (a == "--sig") sig = true;
        else if (a == "--demo") demo = true;
        else if (a == "--json") json = true;
        else if (a == "--no-color") color = false;
        else if (a == "--html" && i + 1 < argc) html_path = argv[++i];
        else if (a == "--watch") {
            watch = true;
            if (i + 1 < argc && std::atof(argv[i + 1]) > 0) interval = std::atof(argv[++i]);
        } else if (a == "-h" || a == "--help") {
            put(kUsage);
            return 0;
        } else {
            std::fprintf(stderr, "procrib: bad argument '%s'\n%s", a.c_str(), kUsage);
            return 2;
        }
    }

    SetConsoleOutputCP(CP_UTF8);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    bool tty = GetConsoleMode(out, &mode) != 0;
    if (!tty || !SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) color = false;

    CollectOpts co;
    co.signatures = sig;
    CpuTracker cpu;
    ConsoleOpts opts;
    opts.color = color;
    opts.verbose = verbose;

    do {
        std::vector<Proc> procs = demo ? demo_list() : collect(co);
        if (procs.empty()) {
            std::fprintf(stderr, "procrib: could not read the process list\n");
            return 1;
        }
        cpu.update(procs);
        Tree tree = build_tree(procs);
        std::string stamp = now_text();

        if (!html_path.empty()) {
            std::ofstream f(html_path, std::ios::binary);
            if (!f) {
                std::fprintf(stderr, "procrib: cannot write %s\n", html_path.c_str());
                return 1;
            }
            f << render_html(tree, stamp);
        }
        if (json) {
            put(render_json(tree, stamp));
        } else if (html_path.empty() || watch) {
            if (watch) put("\x1b[H\x1b[J");
            put("procrib  " + stamp + "  " + std::to_string(procs.size()) + " processes\n\n");
            put(render_console(tree, opts));
            std::fflush(stdout);
        }
        if (watch) std::this_thread::sleep_for(std::chrono::duration<double>(interval));
    } while (watch);
    return 0;
}
