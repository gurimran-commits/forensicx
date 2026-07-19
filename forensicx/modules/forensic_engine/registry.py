"""Automatic discovery for analyzer plugins."""
from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil

from forensicx.modules.forensic_engine.analyzers.base import BaseAnalyzer

LOGGER = logging.getLogger(__name__)


class AnalyzerRegistry:
    """Discover concrete analyzers from the plugin package without a central list."""

    def discover(self) -> list[BaseAnalyzer]:
        """Import plugin modules and instantiate each concrete ``BaseAnalyzer`` once."""
        package = importlib.import_module("forensicx.modules.forensic_engine.analyzers")
        analyzers: dict[str, BaseAnalyzer] = {}
        for module_info in pkgutil.iter_modules(package.__path__, f"{package.__name__}."):
            if module_info.name.endswith(".base"):
                continue
            module = importlib.import_module(module_info.name)
            for _, candidate in inspect.getmembers(module, inspect.isclass):
                if candidate is not BaseAnalyzer and issubclass(candidate, BaseAnalyzer) and not inspect.isabstract(candidate):
                    analyzer = candidate()
                    if analyzer.name in analyzers:
                        raise RuntimeError(f"Duplicate forensic analyzer name: {analyzer.name}")
                    analyzers[analyzer.name] = analyzer
        LOGGER.info("Discovered forensic analyzers: %s", ", ".join(sorted(analyzers)))
        return [analyzers[name] for name in sorted(analyzers)]
