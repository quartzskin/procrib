#include "proctree.h"

#include <algorithm>
#include <unordered_map>

namespace procrib {

namespace {

bool older(const Proc& a, const Proc& b) {
    if (a.start != b.start) return a.start < b.start;
    return a.pid < b.pid;
}

}  // namespace

Tree build_tree(const std::vector<Proc>& procs) {
    Tree t;
    t.nodes.resize(procs.size());
    std::unordered_map<uint32_t, int> by_pid;
    for (size_t i = 0; i < procs.size(); i++) {
        t.nodes[i].p = procs[i];
        by_pid[procs[i].pid] = static_cast<int>(i);  // later entry wins on a duplicate pid
    }

    for (size_t i = 0; i < procs.size(); i++) {
        Node& n = t.nodes[i];
        const Proc& p = n.p;
        if (p.ppid == 0 || p.ppid == p.pid) continue;
        auto it = by_pid.find(p.ppid);
        if (it == by_pid.end() || it->second == static_cast<int>(i)) {
            n.link = Link::Orphan;
            continue;
        }
        const Proc& par = t.nodes[it->second].p;
        // System (4) is fixed, and kernel-made children such as Registry predate its timestamp.
        if (p.ppid != 4 && par.start && p.start && par.start > p.start) {
            n.link = Link::PidReused;
            continue;
        }
        n.parent = it->second;
        n.link = Link::Child;
    }

    // Walk each parent chain; on a loop the oldest member becomes the root.
    enum { Unseen, Active, Done };
    std::vector<int> state(procs.size(), Unseen);
    for (size_t s = 0; s < procs.size(); s++) {
        if (state[s] != Unseen) continue;
        std::vector<int> path;
        int cur = static_cast<int>(s);
        while (cur != -1 && state[cur] == Unseen) {
            state[cur] = Active;
            path.push_back(cur);
            cur = t.nodes[cur].parent;
        }
        if (cur != -1 && state[cur] == Active) {
            auto from = std::find(path.begin(), path.end(), cur);
            int cut = *from;
            for (auto it = from; it != path.end(); ++it) {
                if (older(t.nodes[*it].p, t.nodes[cut].p)) cut = *it;
            }
            t.nodes[cut].parent = -1;
            t.nodes[cut].link = Link::CycleBroken;
        }
        for (int i : path) state[i] = Done;
    }

    for (size_t i = 0; i < t.nodes.size(); i++) {
        int par = t.nodes[i].parent;
        if (par == -1) t.roots.push_back(static_cast<int>(i));
        else t.nodes[par].kids.push_back(static_cast<int>(i));
    }

    auto by_age = [&](int a, int b) { return older(t.nodes[a].p, t.nodes[b].p); };
    std::sort(t.roots.begin(), t.roots.end(), by_age);
    for (Node& n : t.nodes) std::sort(n.kids.begin(), n.kids.end(), by_age);
    return t;
}

}  // namespace procrib
