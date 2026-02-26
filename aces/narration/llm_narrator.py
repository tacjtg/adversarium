"""LLM-based analysis of evolved strategies."""

from __future__ import annotations

import os

from aces.attack.genome import AttackGenome
from aces.attack.techniques import TechniqueRegistry
from aces.defense.genome import DefenseGenome
from aces.evolution.metrics import MetricsCollector
from aces.network.graph import NetworkGraph


class LLMNarrator:
    """Generates threat intelligence briefs from co-evolution results."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.client = None
        if self.api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                pass

    @property
    def available(self) -> bool:
        return self.client is not None

    def generate_threat_brief(
        self,
        attacker_hof: list[AttackGenome],
        defender_hof: list[DefenseGenome],
        metrics: MetricsCollector,
        network: NetworkGraph,
    ) -> str:
        """Generate a markdown threat brief from evolution results."""
        if not self.available:
            return self._generate_static_brief(attacker_hof, defender_hof, metrics)

        registry = TechniqueRegistry()
        prompt = self._build_prompt(attacker_hof, defender_hof, metrics, network, registry)

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=(
                "You are a senior threat intelligence analyst at a defense contractor. "
                "You are reviewing results from an adversarial AI co-evolution simulation "
                "that pits offensive AI agents against defensive AI agents on a simulated "
                "corporate network. Your audience is the CISO and security operations team. "
                "Write a concise, actionable threat brief in Markdown format."
            ),
            messages=[{"role": "user", "content": prompt}],
        )

        return message.content[0].text

    def narrate_kill_chain(
        self,
        genome: AttackGenome,
    ) -> str:
        """Generate a narrative description of a single evolved kill chain."""
        registry = TechniqueRegistry()
        chain_desc = []
        for i, gene in enumerate(genome.genes):
            tech = registry.get(gene.technique_id)
            chain_desc.append(
                f"{i+1}. **{tech.id}** — {tech.name} "
                f"(tactic: {tech.tactic.value}, stealth: {gene.stealth_modifier:.2f})"
            )
        return "\n".join(chain_desc)

    def _build_prompt(
        self,
        attacker_hof: list[AttackGenome],
        defender_hof: list[DefenseGenome],
        metrics: MetricsCollector,
        network: NetworkGraph,
        registry: TechniqueRegistry,
    ) -> str:
        """Build the analysis prompt with all context."""
        sections: list[str] = []

        # Network summary
        sections.append("## Network Topology\n")
        sections.append(f"- {network.host_count} hosts across {len(network.segments)} segments")
        sections.append(f"- Segments: {', '.join(network.segments.keys())}")
        sections.append(f"- {len(network.credentials)} credential sets\n")

        # Top attacker chains
        sections.append("## Top Evolved Attack Chains\n")
        for i, atk in enumerate(attacker_hof[:5]):
            fitness = atk.fitness.values if atk.fitness.valid else (0, 0)
            sections.append(f"### Attacker #{i+1} (effectiveness={fitness[0]:.1f}, stealth={fitness[1]:.2f})")
            sections.append(self.narrate_kill_chain(atk))
            sections.append("")

        # Top defender configs
        sections.append("## Top Evolved Defender Configurations\n")
        for i, d in enumerate(defender_hof[:5]):
            fitness = d.fitness.values if d.fitness.valid else (0, 0)
            sections.append(f"### Defender #{i+1} (coverage={fitness[0]:.1f}, efficiency={fitness[1]:.2f})")
            for gene in d.genes:
                sections.append(
                    f"- Detect **{gene.technique_detected}** via {gene.detection_logic.value} "
                    f"(conf={gene.confidence:.2f}, response={gene.response_action.value})"
                )
            sections.append("")

        # Evolution trends
        if metrics.history:
            sections.append("## Evolution Trends\n")
            first = metrics.history[0]
            last = metrics.history[-1]
            sections.append(f"- Generations: {len(metrics.history)}")
            sections.append(f"- Attacker fitness: {first.attacker_fitness_max:.1f} → {last.attacker_fitness_max:.1f}")
            sections.append(f"- Defender coverage: {first.defender_coverage_max:.1f} → {last.defender_coverage_max:.1f}")
            sections.append(f"- Final unique kill chains: {last.unique_kill_chains}")
            sections.append(f"- Detection coverage ratio: {last.detection_coverage_ratio:.1%}")

        sections.append(
            "\n---\n"
            "Analyze these evolved strategies. For each top attacker, explain what makes "
            "the kill chain effective and what real-world threat actor TTPs it resembles. "
            "For each top defender, explain its detection philosophy and blind spots. "
            "Conclude with strategic recommendations for the CISO."
        )

        return "\n".join(sections)

    def _generate_static_brief(
        self,
        attacker_hof: list[AttackGenome],
        defender_hof: list[DefenseGenome],
        metrics: MetricsCollector,
    ) -> str:
        """Generate a basic brief without LLM (fallback)."""
        registry = TechniqueRegistry()
        lines = ["# ACES Threat Brief\n", "*Generated without LLM narration*\n"]

        lines.append("## Top Evolved Attack Chains\n")
        for i, atk in enumerate(attacker_hof[:5]):
            fitness = atk.fitness.values if atk.fitness.valid else (0, 0)
            lines.append(f"### Attacker #{i+1} — Effectiveness: {fitness[0]:.1f}, Stealth: {fitness[1]:.2f}\n")
            for j, gene in enumerate(atk.genes):
                tech = registry.get(gene.technique_id)
                lines.append(f"{j+1}. {tech.id} — {tech.name} ({tech.tactic.value})")
            lines.append("")

        lines.append("## Top Evolved Defender Configurations\n")
        for i, d in enumerate(defender_hof[:5]):
            fitness = d.fitness.values if d.fitness.valid else (0, 0)
            lines.append(f"### Defender #{i+1} — Coverage: {fitness[0]:.1f}, Efficiency: {fitness[1]:.2f}\n")
            for gene in d.genes:
                lines.append(
                    f"- {gene.technique_detected}: {gene.detection_logic.value} "
                    f"(conf={gene.confidence:.2f}, fp={gene.false_positive_rate:.3f}, "
                    f"action={gene.response_action.value})"
                )
            lines.append("")

        if metrics.history:
            last = metrics.history[-1]
            lines.append("## Summary Statistics\n")
            lines.append(f"- Generations: {len(metrics.history)}")
            lines.append(f"- Final max attacker effectiveness: {last.attacker_fitness_max:.1f}")
            lines.append(f"- Final max defender coverage: {last.defender_coverage_max:.1f}")
            lines.append(f"- Unique kill chains: {last.unique_kill_chains}")
            lines.append(f"- Detection coverage: {last.detection_coverage_ratio:.1%}")

        return "\n".join(lines)
