"""
run_cosmic.py — Run cosmic-galaxy UVRS on cpg-fixture.json and write expected-cosmic.json

Usage: python3 tests/integration/cosmic-galaxy/run_cosmic.py

Requires cosmic-galaxy to be importable. Install with:
  cd cosmic-galaxy && pip install -e .
"""
import json
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent / "cpg-fixture.json"
OUTPUT = Path(__file__).parent / "expected-cosmic.json"


def cpg_to_networkx(fixture):
    """Convert CPG JSON fixture to networkx DiGraph + sink list."""
    try:
        import networkx as nx
    except ImportError:
        print("networkx not installed. Run: pip install networkx", file=sys.stderr)
        sys.exit(1)

    G = nx.DiGraph()
    for node in fixture["nodes"]:
        G.add_node(node["id"], **node.get("features", {}))
    for edge in fixture["edges"]:
        G.add_edge(edge["source"], edge["target"], kind=edge["kind"])
    sinks = [n["id"] for n in fixture["nodes"] if n.get("features", {}).get("is_sink")]
    return G, sinks


def run_cosmic_uvrs(G, sinks):
    """Run cosmic-galaxy UVRS on the CPG and return per-node scores."""
    try:
        from engine import UVRS, GravityField, CosmicEngine
    except ImportError:
        print("cosmic-galaxy not importable. Install with: cd cosmic-galaxy && pip install -e .",
              file=sys.stderr)
        sys.exit(1)

    engine = CosmicEngine(graph=G, sinks=sinks)
    scores = engine.compute_uvrs()
    return scores


def main():
    if not FIXTURE.exists():
        print(f"Fixture not found: {FIXTURE}", file=sys.stderr)
        sys.exit(1)

    fixture = json.loads(FIXTURE.read_text())
    G, sinks = cpg_to_networkx(fixture)
    scores = run_cosmic_uvrs(G, sinks)

    result = {
        "tool": "cosmic-galaxy",
        "version": "7.5",
        "scores": {node_id: float(score) for node_id, score in scores.items()},
        "tolerance": 0.10,
    }
    OUTPUT.write_text(json.dumps(result, indent=2))
    print(f"Wrote {OUTPUT}")
    for k, v in result["scores"].items():
        print(f"  {k}: {v:.3f}")


if __name__ == "__main__":
    main()