"""
CSC305A - Graph Theory and Discrete Optimization (Mini Project)
Ransomware Containment: minimum-cost host quarantine

Pipeline:  Input (network.json) -> Graph model -> Algorithms -> Solution -> Output

Graph model
  - Undirected graph G = (V, E)
  - V : hosts / servers / switches, each with an isolation cost w(v)
        (business impact of taking that host offline)
  - E : network links, each with a capacity (Mbps)
  - I : infected hosts, C : critical assets (database, payment server) that must stay clean

Problem
  Choose a set Q of hosts to quarantine (remove from the network) so that
    (1) containment : no path from a non-quarantined infected host to any critical asset in G - Q
    (2) service     : max flow from the gateway to the critical assets, in the part of the
                      network that is still clean, is >= D  (handled with a penalty)
  minimising  total isolation cost = sum of w(v) for v in Q.

Algorithms
  - BFS                    : infected zone / connectivity check / shortest infection path
  - Greedy                 : initial feasible solution
  - Local search           : drop + swap moves to improve the initial solution
  - Ford-Fulkerson (E-K)   : (a) remaining service capacity, (b) exact min-cost cut
                             (vertex splitting) used as an optimality benchmark
"""

import json
import random
import sys
import time
from collections import defaultdict, deque

INF = 10 ** 9
PENALTY = 1.0   # cost units charged per Mbps of service shortfall


# --------------------------------------------------------------------------
# Graph model
# --------------------------------------------------------------------------
class Network:
    def __init__(self, data):
        self.name = {n["id"]: n["name"] for n in data["nodes"]}
        self.cost = {n["id"]: n["cost"] for n in data["nodes"]}
        self.nodes = sorted(self.name)
        self.adj = {v: {} for v in self.nodes}          # adjacency list: adj[u][v] = capacity
        for u, v, cap in data["links"]:
            self.adj[u][v] = cap
            self.adj[v][u] = cap
        self.infected = set(data["infected"])
        self.critical = set(data["critical"])
        self.gateway = data["gateway"]
        self.demand = data["service_demand"]
        if self.infected & self.critical:
            raise ValueError("A critical asset is already infected - cannot be contained.")

    def label(self, vs):
        return ", ".join(self.name[v] for v in sorted(vs)) if vs else "(none)"


# --------------------------------------------------------------------------
# BFS based routines
# --------------------------------------------------------------------------
def infected_zone(net, Q):
    """All hosts the infection can reach when hosts in Q are quarantined (BFS)."""
    start = [s for s in net.infected if s not in Q]
    seen = set(start)
    dq = deque(start)
    while dq:
        u = dq.popleft()
        for v in net.adj[u]:
            if v not in Q and v not in seen:
                seen.add(v)
                dq.append(v)
    return seen


def is_contained(net, Q):
    return not (infected_zone(net, Q) & net.critical)


def shortest_infection_path(net, Q):
    """Shortest path (BFS) from any live infected host to any critical asset, or None."""
    start = [s for s in sorted(net.infected) if s not in Q]
    parent = {s: None for s in start}
    dq = deque(start)
    while dq:
        u = dq.popleft()
        if u in net.critical:
            path = []
            while u is not None:
                path.append(u)
                u = parent[u]
            return path[::-1]
        for v in sorted(net.adj[u]):
            if v not in Q and v not in parent:
                parent[v] = u
                dq.append(v)
    return None


# --------------------------------------------------------------------------
# Ford-Fulkerson (Edmonds-Karp: augmenting paths found with BFS)
# --------------------------------------------------------------------------
def max_flow(cap, s, t):
    """cap: dict-of-dicts of residual capacities (modified in place)."""
    flow = 0
    while True:
        parent = {s: None}
        dq = deque([s])
        while dq and t not in parent:
            u = dq.popleft()
            for v, c in cap[u].items():
                if c > 0 and v not in parent:
                    parent[v] = u
                    dq.append(v)
        if t not in parent:
            return flow
        b, v = INF, t
        while parent[v] is not None:
            b = min(b, cap[parent[v]][v])
            v = parent[v]
        v = t
        while parent[v] is not None:
            u = parent[v]
            cap[u][v] -= b
            cap[v][u] = cap[v].get(u, 0) + b
            v = u
        flow += b


def flow_in(net, removed):
    """Max flow gateway -> critical assets using only hosts not in `removed`."""
    if net.gateway in removed:
        return 0
    cap = defaultdict(dict)
    for u in net.nodes:
        if u in removed:
            continue
        for v, c in net.adj[u].items():
            if v not in removed:
                cap[u][v] = c
    sink = "T"
    for c in net.critical:
        if c not in removed:
            cap[c][sink] = INF
    return max_flow(cap, net.gateway, sink)


def service_capacity(net, Q):
    """Legitimate capacity left: hosts that are quarantined or infected are unusable."""
    return flow_in(net, Q | infected_zone(net, Q))


def exact_min_cost_cut(net):
    """
    Exact minimum-cost quarantine set for the CONTAINMENT constraint alone.
    Vertex splitting: v -> (v,in) --w(v)--> (v,out); links get infinite capacity.
    Max-flow = min-cut = minimum total isolation cost. Ignores the service constraint,
    so its cost is a lower bound for any feasible solution.
    """
    cap = defaultdict(dict)
    S, T = "S", "T"
    for v in net.nodes:
        cap[(v, 0)][(v, 1)] = INF if v in net.critical else net.cost[v]
    for u in net.nodes:
        for v in net.adj[u]:
            cap[(u, 1)][(v, 0)] = INF
    for s in net.infected:
        cap[S][(s, 0)] = INF
    for c in net.critical:
        cap[(c, 1)][T] = INF
    value = max_flow(cap, S, T)
    # nodes reachable from S in the residual graph -> min cut
    seen, dq = {S}, deque([S])
    while dq:
        u = dq.popleft()
        for v, c in cap[u].items():
            if c > 0 and v not in seen:
                seen.add(v)
                dq.append(v)
    Q = {v for v in net.nodes if (v, 0) in seen and (v, 1) not in seen}
    return Q, value


# --------------------------------------------------------------------------
# Objective, initial solution, local search
# --------------------------------------------------------------------------
def evaluate(net, Q):
    cost = sum(net.cost[v] for v in Q)
    svc = service_capacity(net, Q)
    penalised = cost + PENALTY * max(0, net.demand - svc)
    return penalised, cost, svc


def greedy_initial(net):
    """Repeatedly find an infection path and quarantine the cheapest host on it."""
    Q = set()
    while True:
        path = shortest_infection_path(net, Q)
        if path is None:
            return Q
        candidates = [v for v in path if v not in net.critical]
        Q.add(min(candidates, key=lambda v: (net.cost[v], v)))


def local_search(net, Q0):
    """Best-improvement local search with DROP and SWAP moves (containment kept feasible)."""
    Q = set(Q0)
    best = evaluate(net, Q)[0]
    steps = 0
    while True:
        neighbours = [Q - {v} for v in Q]                              # drop a host
        for u in Q:                                                    # swap u -> v
            for v in net.nodes:
                if v not in Q and v not in net.critical:
                    neighbours.append((Q - {u}) | {v})
        best_move = None
        for cand in neighbours:
            if not is_contained(net, cand):
                continue
            f = evaluate(net, cand)[0]
            if f < best - 1e-9:
                best, best_move = f, cand
        if best_move is None:
            return Q, steps
        Q = best_move
        steps += 1


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def describe(net, title, Q, seconds, extra=""):
    pen, cost, svc = evaluate(net, Q)
    zone = infected_zone(net, Q)
    operational = [v for v in net.nodes if v not in Q and v not in zone]
    print(f"\n--- {title} ---")
    print(f"Quarantined hosts      : {net.label(Q)}")
    print(f"Isolation cost         : {cost}")
    print(f"Contained              : {is_contained(net, Q)}  (infected zone size = {len(zone)})")
    print(f"Service capacity       : {svc} Mbps (demand {net.demand} Mbps -> "
          f"{'MET' if svc >= net.demand else 'NOT MET'})")
    print(f"Hosts still operational: {len(operational)} of {len(net.nodes)}")
    print(f"Time                   : {seconds * 1000:.2f} ms {extra}")
    return cost, svc


# --------------------------------------------------------------------------
# Random enterprise-network generator (for testing and benchmarking)
# --------------------------------------------------------------------------
def generate(seed, depts=5, hosts_per=5):
    """Layered enterprise topology: gateway - firewall - core switches - servers/app servers -
    critical assets, plus department switches with workstations (some dual-homed)."""
    rnd = random.Random(seed)
    nodes, links = [], []

    def add(name, cost):
        nodes.append({"id": len(nodes), "name": name, "cost": cost})
        return len(nodes) - 1

    gw, fw = add("Gateway", 10), add("Firewall", 9)
    cores = [add(f"Core{i + 1}", rnd.randint(8, 10)) for i in range(3)]
    links.append([gw, fw, 1000])
    for c in cores:
        links.append([fw, c, 1000])
    for a in range(3):
        for b in range(a + 1, 3):
            if rnd.random() < 0.7:
                links.append([cores[a], cores[b], 1000])
    servers = [add(f"Server{i + 1}", rnd.randint(4, 8)) for i in range(4)]
    for s in servers:
        for c in rnd.sample(cores, 2):
            links.append([s, c, 500])
    apps = [add("AppServer1", rnd.randint(5, 8)), add("AppServer2", rnd.randint(5, 8))]
    for a in apps:
        for c in rnd.sample(cores, 2):
            links.append([a, c, 1000])
    db, pay = add("Database", 0), add("PaymentServer", 0)
    for a in apps:
        links += [[a, db, 1000], [a, pay, 1000]]
    for s in rnd.sample(servers, 2):
        links.append([s, db, 300])
    hosts, switches = [], []
    for d in range(depts):
        sw = add(f"Switch{d + 1}", rnd.randint(3, 6))
        for c in rnd.sample(cores, 2):
            links.append([sw, c, 1000])
        for h in range(hosts_per):
            pc = add(f"PC{d + 1}.{h + 1}", rnd.randint(1, 3))
            hosts.append(pc)
            links.append([pc, sw, 100])
            if switches and rnd.random() < 0.25:          # dual-homed workstation
                links.append([pc, rnd.choice(switches), 100])
        switches.append(sw)
    infected = rnd.sample(hosts, 3)
    for i in infected:                                     # infected machines are costly to remove
        nodes[i]["cost"] = rnd.randint(6, 9)               # (e.g. admin / build / finance machines)
        nodes[i]["name"] = "Infected-" + nodes[i]["name"]
    return {"nodes": nodes, "links": links, "infected": infected,
            "critical": [db, pay], "gateway": gw, "service_demand": 600}


def benchmark():
    print("=== Benchmark: random enterprise networks (10 instances per size) ===")
    print(f"{'Hosts':>6}{'Greedy':>9}{'LocalS.':>9}{'Exact':>8}{'Improv%':>9}{'Gap%':>7}"
          f"{'LS=opt':>8}{'SvcOK':>7}{'t_greedy':>10}{'t_LS':>9}{'t_exact':>9}")
    for depts in (3, 5, 8, 12):
        rows = []
        for seed in range(10):
            net = Network(generate(seed, depts=depts))
            t = time.perf_counter(); Q1 = greedy_initial(net); t1 = time.perf_counter() - t
            t = time.perf_counter(); Q2, _ = local_search(net, Q1); t2 = time.perf_counter() - t
            t = time.perf_counter(); Q3, _ = exact_min_cost_cut(net); t3 = time.perf_counter() - t
            e1, e2, e3 = evaluate(net, Q1), evaluate(net, Q2), evaluate(net, Q3)
            rows.append((len(net.nodes), e1[1], e2[1], e3[1], e2[2] >= net.demand, t1, t2, t3))
        n = len(rows)
        avg = lambda i: sum(r[i] for r in rows) / n
        improv = 100 * (avg(1) - avg(2)) / avg(1)
        gap = 100 * (avg(2) - avg(3)) / avg(3)
        same = sum(1 for r in rows if r[2] == r[3])
        ok = sum(1 for r in rows if r[4])
        print(f"{rows[0][0]:>6}{avg(1):>9.1f}{avg(2):>9.1f}{avg(3):>8.1f}{improv:>9.1f}{gap:>7.1f}"
              f"{str(same) + '/' + str(n):>8}{str(ok) + '/' + str(n):>7}"
              f"{avg(5) * 1000:>10.2f}{avg(6) * 1000:>9.1f}{avg(7) * 1000:>9.2f}")
    print("\nCosts are average total isolation cost; times are in ms. 'Exact' is the containment-only")
    print("min cut (a lower bound: it may violate the service constraint). 'SvcOK' = local-search")
    print("solutions that meet the service demand.")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def run(net):
    print("=== Ransomware Containment: minimum-cost quarantine ===")
    print(f"Hosts: {len(net.nodes)}   Links: {sum(len(a) for a in net.adj.values()) // 2}")
    print(f"Infected : {net.label(net.infected)}")
    print(f"Critical : {net.label(net.critical)}")
    print(f"Gateway  : {net.name[net.gateway]}")
    base = flow_in(net, set())
    print(f"Healthy service capacity (no attack): {base} Mbps, demand: {net.demand} Mbps")

    t = time.perf_counter()
    Q1 = greedy_initial(net)
    t1 = time.perf_counter() - t
    c1, s1 = describe(net, "1. Initial solution (BFS + greedy)", Q1, t1)

    t = time.perf_counter()
    Q2, steps = local_search(net, Q1)
    t2 = time.perf_counter() - t
    c2, s2 = describe(net, "2. Improved solution (local search)", Q2, t2, f"({steps} improving moves)")

    t = time.perf_counter()
    Q3, _ = exact_min_cost_cut(net)
    t3 = time.perf_counter() - t
    c3, s3 = describe(net, "3. Benchmark: exact min cut via max-flow (containment only)", Q3, t3)

    print("\n=== Comparison ===")
    print(f"{'Method':<34}{'Cost':>6}{'Service':>10}{'Met?':>7}{'Time(ms)':>10}")
    for nm, c, s, tt in [("Initial (greedy)", c1, s1, t1),
                         ("Improved (local search)", c2, s2, t2),
                         ("Exact min cut (lower bound)", c3, s3, t3)]:
        print(f"{nm:<34}{c:>6}{s:>10}{('yes' if s >= net.demand else 'no'):>7}{tt * 1000:>10.2f}")
    if c1:
        print(f"\nLocal search reduced isolation cost by {100 * (c1 - c2) / c1:.1f}% vs the initial solution.")
    if c3:
        print(f"Gap of improved solution to the containment-only lower bound: {100 * (c2 - c3) / c3:.1f}%")


def main():
    args = sys.argv[1:]
    if args and args[0] == "--benchmark":
        benchmark()
    elif args and args[0] == "--generate":          # --generate SEED out.json [depts]
        depts = int(args[3]) if len(args) > 3 else 5
        with open(args[2], "w") as f:
            json.dump(generate(int(args[1]), depts=depts), f, indent=1)
        print(f"Wrote random network (seed {args[1]}) to {args[2]}")
    else:
        path = args[0] if args else "network.json"
        with open(path) as f:
            run(Network(json.load(f)))


if __name__ == "__main__":
    main()
