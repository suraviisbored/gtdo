# Ransomware containment

Choose hosts to quarantine at minimum isolation cost so no infected host can reach a critical asset, while keeping the required service bandwidth. Sample network: 43 hosts, 61 links, 3 infected PCs.

## Files

| Path | What it is |
|---|---|
| `ransomware_containment.py` | Greedy, local search and exact min-cut solvers, plus a benchmark. Python 3, standard library only. |
| `network.json` | The sample network (hosts, links with capacities, costs, infected and critical hosts). |
| `docs/index.html` | Interactive containment page (self-contained, no build step). |

## Run

```bash
python3 ransomware_containment.py              # solve network.json
python3 ransomware_containment.py --benchmark  # random networks, 31 to 85 hosts
```

Open `docs/index.html` directly in a browser. To host it, enable GitHub Pages from branch `main`, folder `/docs`.
