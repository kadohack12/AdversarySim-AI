"""AdversarySim-AI — a safety-first purple-team assistant for Sliver C2.

The package is intentionally small and dependency-light:

* :mod:`adversary_sim.sliver` — standalone wrapper around ``sliver-client``.
* :mod:`adversary_sim.core` — async connector to a local Ollama server.
* :mod:`adversary_sim.safety` — human-in-the-loop approval gate.
* :mod:`adversary_sim.cli` — rich terminal interface.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
