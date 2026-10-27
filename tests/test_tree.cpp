#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "proctree.h"
#include "render.h"

using namespace procrib;

static int failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
            failures++;                                                  \
        }                                                                \
    } while (0)

static Proc mk(uint32_t pid, uint32_t ppid, uint64_t start, const char* name = "p.exe") {
    Proc p;
    p.pid = pid;
    p.ppid = ppid;
    p.start = start;
    p.name = name;
    return p;
}

static const Node& find(const Tree& t, uint32_t pid) {
    for (const Node& n : t.nodes)
        if (n.p.pid == pid) return n;
    std::printf("FAIL pid %u missing from tree\n", pid);
    std::exit(1);
}

static bool is_root(const Tree& t, uint32_t pid) {
    for (int r : t.roots)
        if (t.nodes[r].p.pid == pid) return true;
    return false;
}

static size_t count_reachable(const Tree& t) {
    size_t n = 0;
    std::vector<int> stack(t.roots.begin(), t.roots.end());
    while (!stack.empty()) {
        int i = stack.back();
        stack.pop_back();
        n++;
        for (int k : t.nodes[i].kids) stack.push_back(k);
    }
    return n;
}

static void test_basic() {
    Tree t = build_tree({mk(4, 0, 10), mk(100, 4, 20), mk(200, 100, 30), mk(300, 100, 25)});
    CHECK(t.roots.size() == 1);
    CHECK(is_root(t, 4));
    const Node& n = find(t, 100);
    CHECK(n.link == Link::Child);
    CHECK(n.kids.size() == 2);
    CHECK(t.nodes[n.kids[0]].p.pid == 300);  // older child first
    CHECK(count_reachable(t) == 4);
}

static void test_pid_reuse() {
    // 500 claims parent 100, but the process now holding pid 100 started later.
    Tree t = build_tree({mk(4, 0, 1), mk(100, 4, 900), mk(500, 100, 50)});
    const Node& n = find(t, 500);
    CHECK(n.parent == -1);
    CHECK(n.link == Link::PidReused);
    CHECK(is_root(t, 500));
    CHECK(find(t, 100).kids.empty());
}

static void test_equal_start_is_child() {
    Tree t = build_tree({mk(100, 0, 50), mk(200, 100, 50)});
    CHECK(find(t, 200).link == Link::Child);
}

static void test_system_parent_exempt() {
    Tree t = build_tree({mk(4, 0, 900), mk(272, 4, 100)});
    CHECK(find(t, 272).link == Link::Child);
}

static void test_unknown_start_trusted() {
    Tree t = build_tree({mk(100, 0, 0), mk(200, 100, 50)});
    CHECK(find(t, 200).link == Link::Child);
    Tree u = build_tree({mk(100, 0, 50), mk(200, 100, 0)});
    CHECK(find(u, 200).link == Link::Child);
}

static void test_orphan() {
    Tree t = build_tree({mk(4, 0, 1), mk(700, 650, 20), mk(701, 700, 30)});
    CHECK(find(t, 700).link == Link::Orphan);
    CHECK(is_root(t, 700));
    CHECK(find(t, 701).parent != -1);
    CHECK(count_reachable(t) == 3);
}

static void test_self_and_zero_parent() {
    Tree t = build_tree({mk(0, 0, 0), mk(8, 8, 5), mk(9, 0, 6)});
    CHECK(t.roots.size() == 3);
    CHECK(find(t, 8).link == Link::Root);
    CHECK(find(t, 9).link == Link::Root);
}

static void test_cycle_unknown_times() {
    Tree t = build_tree({mk(1, 3, 0), mk(2, 1, 0), mk(3, 2, 0), mk(10, 1, 0)});
    CHECK(count_reachable(t) == 4);
    CHECK(t.roots.size() == 1);
    int cut = 0;
    for (const Node& n : t.nodes)
        if (n.link == Link::CycleBroken) cut++;
    CHECK(cut == 1);
    CHECK(find(t, 10).parent != -1);
}

static void test_two_cycle_picks_oldest_as_root() {
    Tree t = build_tree({mk(1, 2, 10), mk(2, 1, 20)});
    // start times make a real cycle impossible: 1 -> 2 is reuse, so nothing loops
    CHECK(find(t, 1).link == Link::PidReused);
    CHECK(count_reachable(t) == 2);

    Tree u = build_tree({mk(1, 2, 0), mk(2, 1, 0)});
    CHECK(count_reachable(u) == 2);
    CHECK(u.roots.size() == 1);
    CHECK(find(u, u.nodes[u.roots[0]].p.pid).link == Link::CycleBroken);
}

static void test_duplicate_pid() {
    Tree t = build_tree({mk(5, 0, 1), mk(5, 0, 2), mk(6, 5, 3)});
    CHECK(count_reachable(t) == 3);
}

static void test_deep_chain() {
    std::vector<Proc> v;
    for (uint32_t i = 1; i <= 5000; i++) v.push_back(mk(i, i - 1, i));
    Tree t = build_tree(v);
    CHECK(t.roots.size() == 1);
    CHECK(count_reachable(t) == 5000);
}

static void test_empty() {
    Tree t = build_tree({});
    CHECK(t.roots.empty());
    CHECK(render_json(t, "now").find("\"processes\": []") != std::string::npos);
}

static void test_render() {
    Proc a = mk(4, 0, 100, "sys\"tem<>.exe");
    a.cmdline = "x \"y\"\\z\n";
    Proc b = mk(9, 77, 200);
    b.access = Access::Denied;
    Tree t = build_tree({a, b});

    std::string j = render_json(t, "now");
    CHECK(j.find("sys\\\"tem<>.exe") != std::string::npos);
    CHECK(j.find("\\\\z\\n") != std::string::npos);
    CHECK(j.find("\"link\": \"orphan\"") != std::string::npos);

    std::string h = render_html(t, "now");
    CHECK(h.find("sys&quot;tem&lt;&gt;.exe") != std::string::npos);
    CHECK(h.find("sys\"tem<>") == std::string::npos);

    ConsoleOpts o;
    o.color = false;
    std::string c = render_console(t, o);
    CHECK(c.find("parent 77 not running") != std::string::npos);
    CHECK(c.find("[no access]") != std::string::npos);
    CHECK(c.find("\x1b") == std::string::npos);

    CHECK(json_escape(std::string("\x01")) == "\\u0001");
    CHECK(format_bytes(1536) == "1.5 KB");
    CHECK(format_filetime(132000000000000000ULL).substr(0, 2) == "20");
    CHECK(format_filetime(0).empty());
}

int main() {
    test_basic();
    test_pid_reuse();
    test_equal_start_is_child();
    test_system_parent_exempt();
    test_unknown_start_trusted();
    test_orphan();
    test_self_and_zero_parent();
    test_cycle_unknown_times();
    test_two_cycle_picks_oldest_as_root();
    test_duplicate_pid();
    test_deep_chain();
    test_empty();
    test_render();
    if (failures) {
        std::printf("%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all tests passed\n");
    return 0;
}
