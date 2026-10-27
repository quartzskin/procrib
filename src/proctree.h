#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace procrib {

enum class Access { Full, Denied, Gone, Kernel };

struct Proc {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    uint64_t start = 0;  // FILETIME ticks, 0 if unknown
    std::string name;
    std::string path;
    std::string cmdline;
    std::string sig;  // empty when not checked
    uint32_t threads = 0;
    uint64_t working_set = 0;
    uint64_t private_bytes = 0;
    uint64_t cpu_time = 0;  // user + kernel, 100ns units
    double cpu_pct = -1;    // -1 when there is no previous sample
    Access access = Access::Full;
};

// Why a node sits where it does.
enum class Link {
    Root,        // no parent recorded (ppid 0 or self)
    Child,
    Orphan,      // recorded parent is not in the list
    PidReused,   // recorded parent started after this process
    CycleBroken  // parent chain looped; link dropped here
};

struct Node {
    Proc p;
    int parent = -1;
    std::vector<int> kids;
    Link link = Link::Root;
};

struct Tree {
    std::vector<Node> nodes;
    std::vector<int> roots;
};

Tree build_tree(const std::vector<Proc>& procs);

}  // namespace procrib
