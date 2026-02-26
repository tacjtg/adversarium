"""Plotly-based visualization suite for co-evolution results."""

from __future__ import annotations

import html as html_module
from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from aces.attack.genome import AttackGenome
from aces.attack.techniques import TechniqueRegistry
from aces.config import Tactic
from aces.defense.genome import DefenseGenome
from aces.evolution.metrics import MetricsCollector
from aces.network.graph import NetworkGraph
from aces.simulation.state import MatchResult


class Dashboard:
    """Generates all visualization charts from co-evolution results."""

    def __init__(
        self,
        metrics: MetricsCollector,
        attacker_hof: list[AttackGenome],
        defender_hof: list[DefenseGenome],
    ) -> None:
        self.metrics = metrics
        self.attacker_hof = attacker_hof
        self.defender_hof = defender_hof

    # ── Figure Builders (return go.Figure) ──

    def _fig_fitness_trajectory(self) -> go.Figure:
        """Dual-axis line chart: attacker effectiveness vs defender coverage."""
        history = self.metrics.history
        gens = [m.generation for m in history]
        atk_mean = [m.attacker_fitness_mean for m in history]
        atk_max = [m.attacker_fitness_max for m in history]
        atk_std = [m.attacker_fitness_std for m in history]
        def_mean = [m.defender_coverage_mean for m in history]
        def_max = [m.defender_coverage_max for m in history]

        fig = make_subplots(specs=[[{"secondary_y": True}]])

        upper = [m + s for m, s in zip(atk_mean, atk_std)]
        lower = [max(0, m - s) for m, s in zip(atk_mean, atk_std)]
        fig.add_trace(
            go.Scatter(x=gens + gens[::-1], y=upper + lower[::-1],
                       fill="toself", fillcolor="rgba(239,68,68,0.1)",
                       line=dict(width=0), name="ATK +/-1s", showlegend=False),
            secondary_y=False,
        )
        fig.add_trace(
            go.Scatter(x=gens, y=atk_mean, name="ATK Mean",
                       line=dict(color="#ef4444", width=2)),
            secondary_y=False,
        )
        fig.add_trace(
            go.Scatter(x=gens, y=atk_max, name="ATK Max",
                       line=dict(color="#991b1b", width=1, dash="dash")),
            secondary_y=False,
        )
        fig.add_trace(
            go.Scatter(x=gens, y=def_mean, name="DEF Mean",
                       line=dict(color="#3b82f6", width=2)),
            secondary_y=True,
        )
        fig.add_trace(
            go.Scatter(x=gens, y=def_max, name="DEF Max",
                       line=dict(color="#1e3a5f", width=1, dash="dash")),
            secondary_y=True,
        )

        fig.update_layout(
            title=None, margin=dict(t=10, b=40, l=50, r=50),
            xaxis_title="Generation",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            height=370,
        )
        fig.update_yaxes(title_text="Attacker Effectiveness", secondary_y=False)
        fig.update_yaxes(title_text="Defender Coverage", secondary_y=True)
        return fig

    def _fig_technique_heatmap(self) -> go.Figure | None:
        """Heatmap of technique frequency over generations."""
        history = self.metrics.history
        if not history:
            return None

        all_techs: set[str] = set()
        for m in history:
            all_techs.update(m.technique_frequencies.keys())

        # Sort by tactic order then ID
        registry = TechniqueRegistry()
        tactic_order = {t: i for i, t in enumerate(Tactic)}

        def sort_key(tid: str) -> tuple[int, str]:
            try:
                tech = registry.get(tid)
                return (tactic_order.get(tech.tactic, 99), tid)
            except KeyError:
                return (99, tid)

        sorted_techs = sorted(all_techs, key=sort_key)

        # Build labels with technique names
        labels = []
        for tid in sorted_techs:
            try:
                tech = registry.get(tid)
                labels.append(f"{tid} {tech.name[:30]}")
            except KeyError:
                labels.append(tid)

        window = max(1, len(history) // 30)
        bins: list[int] = []
        z_data: list[list[float]] = [[] for _ in sorted_techs]

        for start in range(0, len(history), window):
            end = min(start + window, len(history))
            bins.append(start)
            for t_idx, tech_id in enumerate(sorted_techs):
                freq = sum(
                    history[i].technique_frequencies.get(tech_id, 0.0)
                    for i in range(start, end)
                ) / (end - start)
                z_data[t_idx].append(freq)

        fig = go.Figure(data=go.Heatmap(
            z=z_data,
            x=[f"Gen {b}" for b in bins],
            y=labels,
            colorscale="YlOrRd",
            colorbar=dict(title="Freq", len=0.8),
        ))

        fig.update_layout(
            title=None, margin=dict(t=10, b=40, l=240, r=20),
            xaxis_title="Generation Window",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=max(500, len(sorted_techs) * 20),
        )
        return fig

    def _fig_detection_coverage(self) -> go.Figure:
        """Area chart of detection coverage over time."""
        history = self.metrics.history
        gens = [m.generation for m in history]
        coverage = [m.detection_coverage_ratio * 100 for m in history]

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=gens, y=coverage, fill="tozeroy",
            name="Detection Coverage %",
            line=dict(color="#3b82f6", width=2),
            fillcolor="rgba(59,130,246,0.15)",
        ))

        fig.update_layout(
            title=None, margin=dict(t=10, b=40, l=50, r=20),
            xaxis_title="Generation",
            yaxis_title="% Attacker Techniques Covered",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            yaxis=dict(range=[0, 100]),
            height=300,
        )
        return fig

    def _fig_attack_diversity(self) -> go.Figure:
        """Line chart of unique kill chains over generations."""
        history = self.metrics.history
        gens = [m.generation for m in history]
        unique = [m.unique_kill_chains for m in history]
        atk_div = [m.attacker_diversity for m in history]
        def_div = [m.defender_diversity for m in history]

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=gens, y=unique, name="Unique Kill Chains",
            line=dict(color="#f59e0b", width=2),
        ))
        fig.add_trace(go.Scatter(
            x=gens, y=[d * max(unique) if unique else 0 for d in atk_div],
            name="ATK Diversity (scaled)",
            line=dict(color="#ef4444", width=1, dash="dot"),
        ))
        fig.add_trace(go.Scatter(
            x=gens, y=[d * max(unique) if unique else 0 for d in def_div],
            name="DEF Diversity (scaled)",
            line=dict(color="#3b82f6", width=1, dash="dot"),
        ))

        fig.update_layout(
            title=None, margin=dict(t=10, b=40, l=50, r=20),
            xaxis_title="Generation",
            yaxis_title="Unique Kill Chains",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            height=300,
        )
        return fig

    def _fig_pareto_snapshots(self) -> go.Figure | None:
        """2x2 grid of attacker Pareto front at key generations."""
        history = self.metrics.history
        n = len(history)
        if n < 4:
            return None

        snapshot_gens = [0, n // 3, 2 * n // 3, n - 1]
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=[f"Gen {history[g].generation}" for g in snapshot_gens],
            horizontal_spacing=0.12, vertical_spacing=0.14,
        )

        for idx, g_idx in enumerate(snapshot_gens):
            row = idx // 2 + 1
            col = idx % 2 + 1
            m = history[g_idx]

            fig.add_trace(
                go.Scatter(
                    x=[m.attacker_fitness_mean],
                    y=[m.attacker_stealth_mean],
                    mode="markers",
                    marker=dict(size=12, color="#ef4444", line=dict(width=1, color="white")),
                    name=f"Gen {m.generation}",
                    showlegend=False,
                ),
                row=row, col=col,
            )

        fig.update_layout(
            title=None, margin=dict(t=30, b=40, l=50, r=20),
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=450,
        )
        fig.update_xaxes(title_text="Effectiveness", title_font_size=10)
        fig.update_yaxes(title_text="Stealth", title_font_size=10)
        return fig

    def _fig_network_heatmap(self, network: NetworkGraph) -> go.Figure:
        """Network graph with nodes colored by criticality."""
        import networkx as nx

        pos = nx.spring_layout(network.graph, seed=42, k=1.5)

        edge_x, edge_y = [], []
        for src, dst in network.graph.edges():
            if src in pos and dst in pos:
                x0, y0 = pos[src]
                x1, y1 = pos[dst]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y, mode="lines",
            line=dict(width=0.4, color="rgba(100,116,139,0.3)"),
            hoverinfo="none",
        )

        node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
        for node_id in network.graph.nodes():
            if node_id not in pos:
                continue
            x, y = pos[node_id]
            host = network.hosts[node_id]
            node_x.append(x)
            node_y.append(y)
            node_text.append(
                f"<b>{host.hostname}</b><br>"
                f"Role: {host.role.value}<br>"
                f"Segment: {host.segment}<br>"
                f"Criticality: {host.criticality:.1f}<br>"
                f"OS: {host.os.value}"
            )
            node_color.append(host.criticality)
            node_size.append(max(12, host.criticality * 35))

        node_trace = go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            marker=dict(
                size=node_size,
                color=node_color,
                colorscale=[[0, "#1e3a5f"], [0.5, "#f59e0b"], [1, "#ef4444"]],
                colorbar=dict(title="Crit.", len=0.6, thickness=12),
                line=dict(width=1, color="rgba(255,255,255,0.4)"),
            ),
            text=[network.hosts[n].hostname for n in network.graph.nodes() if n in pos],
            textposition="top center",
            textfont=dict(size=7, color="rgba(200,200,200,0.8)"),
            hovertext=node_text,
            hoverinfo="text",
        )

        fig = go.Figure(data=[edge_trace, node_trace])
        fig.update_layout(
            title=None, margin=dict(t=10, b=10, l=10, r=10),
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=550,
        )
        return fig

    def _fig_stealth_trajectory(self) -> go.Figure:
        """Attacker stealth and defender efficiency over time."""
        history = self.metrics.history
        gens = [m.generation for m in history]
        stealth = [m.attacker_stealth_mean for m in history]
        efficiency = [m.defender_efficiency_mean for m in history]

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=gens, y=stealth, name="ATK Stealth",
            line=dict(color="#ef4444", width=2),
        ))
        fig.add_trace(go.Scatter(
            x=gens, y=efficiency, name="DEF Efficiency",
            line=dict(color="#3b82f6", width=2),
        ))

        fig.update_layout(
            title=None, margin=dict(t=10, b=40, l=50, r=20),
            xaxis_title="Generation",
            yaxis_title="Score (0-1)",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            yaxis=dict(range=[0, 1.05]),
            height=300,
        )
        return fig

    # ── Individual file exports (preserved for backwards compat) ──

    def fitness_trajectory(self, output_path: str) -> None:
        self._fig_fitness_trajectory().write_html(output_path)

    def technique_heatmap(self, output_path: str) -> None:
        fig = self._fig_technique_heatmap()
        if fig:
            fig.write_html(output_path)

    def detection_coverage(self, output_path: str) -> None:
        self._fig_detection_coverage().write_html(output_path)

    def attack_diversity(self, output_path: str) -> None:
        self._fig_attack_diversity().write_html(output_path)

    def pareto_snapshots(self, output_path: str) -> None:
        fig = self._fig_pareto_snapshots()
        if fig:
            fig.write_html(output_path)

    def network_heatmap(self, network: NetworkGraph, output_path: str) -> None:
        self._fig_network_heatmap(network).write_html(output_path)

    def generate_all(self, output_dir: str, network: NetworkGraph | None = None) -> None:
        """Generate all individual chart files."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        self.fitness_trajectory(str(out / "fitness_trajectory.html"))
        self.technique_heatmap(str(out / "technique_heatmap.html"))
        self.detection_coverage(str(out / "detection_coverage.html"))
        self.attack_diversity(str(out / "attack_diversity.html"))
        self.pareto_snapshots(str(out / "pareto_snapshots.html"))

        if network:
            self.network_heatmap(network, str(out / "network_heatmap.html"))

    # ── Unified Dashboard ──

    def generate_unified_dashboard(
        self,
        output_path: str,
        network: NetworkGraph | None = None,
        threat_brief_md: str = "",
        config_dict: dict | None = None,
        elapsed_seconds: float = 0.0,
    ) -> None:
        """Generate a single self-contained HTML dashboard."""
        history = self.metrics.history
        registry = TechniqueRegistry()

        # ── Collect chart divs ──
        chart_divs: dict[str, str] = {}

        fig = self._fig_fitness_trajectory()
        chart_divs["fitness"] = fig.to_html(full_html=False, include_plotlyjs=False)

        fig = self._fig_stealth_trajectory()
        chart_divs["stealth"] = fig.to_html(full_html=False, include_plotlyjs=False)

        fig = self._fig_detection_coverage()
        chart_divs["detection"] = fig.to_html(full_html=False, include_plotlyjs=False)

        fig = self._fig_attack_diversity()
        chart_divs["diversity"] = fig.to_html(full_html=False, include_plotlyjs=False)

        fig = self._fig_technique_heatmap()
        chart_divs["heatmap"] = fig.to_html(full_html=False, include_plotlyjs=False) if fig else ""

        fig = self._fig_pareto_snapshots()
        chart_divs["pareto"] = fig.to_html(full_html=False, include_plotlyjs=False) if fig else ""

        if network:
            fig = self._fig_network_heatmap(network)
            chart_divs["network"] = fig.to_html(full_html=False, include_plotlyjs=False)
        else:
            chart_divs["network"] = "<p class='muted'>No network data available.</p>"

        # ── Overview stats ──
        last = history[-1] if history else None
        first = history[0] if history else None

        def _stat(val: float, fmt: str = ".1f") -> str:
            return f"{val:{fmt}}"

        # ── Hall of Fame HTML ──
        atk_hof_html = self._build_attacker_hof_html(registry)
        def_hof_html = self._build_defender_hof_html(registry)

        # ── Threat brief ──
        brief_html = self._md_to_html(threat_brief_md)

        # ── Config summary ──
        cfg = config_dict or {}

        # ── Assemble ──
        html = _DASHBOARD_TEMPLATE.format(
            # Overview stats
            num_generations=len(history),
            population_size=cfg.get("population_size", "?"),
            elapsed=f"{elapsed_seconds:.1f}",
            seed=cfg.get("seed", "?"),
            atk_max_final=_stat(last.attacker_fitness_max) if last else "—",
            atk_mean_final=_stat(last.attacker_fitness_mean) if last else "—",
            atk_stealth_final=_stat(last.attacker_stealth_mean, ".2f") if last else "—",
            def_max_final=_stat(last.defender_coverage_max) if last else "—",
            def_mean_final=_stat(last.defender_coverage_mean) if last else "—",
            def_eff_final=_stat(last.defender_efficiency_mean, ".2f") if last else "—",
            unique_chains=last.unique_kill_chains if last else 0,
            detection_pct=_stat(last.detection_coverage_ratio * 100) if last else "—",
            atk_diversity=_stat(last.attacker_diversity, ".2f") if last else "—",
            def_diversity=_stat(last.defender_diversity, ".2f") if last else "—",
            # Trend arrows
            atk_trend=self._trend_arrow(
                first.attacker_fitness_max if first else 0,
                last.attacker_fitness_max if last else 0,
            ),
            def_trend=self._trend_arrow(
                first.defender_coverage_max if first else 0,
                last.defender_coverage_max if last else 0,
            ),
            # Charts
            chart_fitness=chart_divs["fitness"],
            chart_stealth=chart_divs["stealth"],
            chart_detection=chart_divs["detection"],
            chart_diversity=chart_divs["diversity"],
            chart_heatmap=chart_divs["heatmap"],
            chart_pareto=chart_divs["pareto"],
            chart_network=chart_divs["network"],
            # Hall of Fame
            attacker_hof_html=atk_hof_html,
            defender_hof_html=def_hof_html,
            attacker_hof_count=len(self.attacker_hof),
            defender_hof_count=len(self.defender_hof),
            # Threat brief
            threat_brief_html=brief_html,
        )

        Path(output_path).write_text(html, encoding="utf-8")

    def _build_attacker_hof_html(self, registry: TechniqueRegistry) -> str:
        """Build HTML cards for top attackers."""
        if not self.attacker_hof:
            return "<p class='muted'>No attackers in hall of fame.</p>"

        cards = []
        for i, atk in enumerate(self.attacker_hof[:5]):
            fitness = atk.fitness.values if atk.fitness.valid else (0, 0)
            steps_html = ""
            for j, gene in enumerate(atk.genes):
                try:
                    tech = registry.get(gene.technique_id)
                    tactic_class = tech.tactic.value.replace("-", "")
                    name = html_module.escape(tech.name)
                    steps_html += (
                        f'<div class="chain-step">'
                        f'<span class="step-num">{j+1}</span>'
                        f'<span class="tactic-badge {tactic_class}">{tech.tactic.value}</span>'
                        f'<span class="tech-id">{tech.id}</span>'
                        f'<span class="tech-name">{name}</span>'
                        f'<span class="stealth-dot" title="Stealth: {gene.stealth_modifier:.2f}" '
                        f'style="opacity:{0.3 + gene.stealth_modifier * 0.7:.2f}"></span>'
                        f'</div>'
                    )
                except KeyError:
                    steps_html += f'<div class="chain-step"><span class="tech-id">{gene.technique_id}</span></div>'

            cards.append(
                f'<div class="hof-card attacker-card">'
                f'<div class="hof-header">'
                f'<span class="hof-rank">#{i+1}</span>'
                f'<span class="hof-scores">'
                f'<span class="score-label">EFF</span><span class="score-val">{fitness[0]:.1f}</span>'
                f'<span class="score-sep">|</span>'
                f'<span class="score-label">STL</span><span class="score-val">{fitness[1]:.2f}</span>'
                f'</span>'
                f'</div>'
                f'<div class="chain-steps">{steps_html}</div>'
                f'</div>'
            )
        return "\n".join(cards)

    def _build_defender_hof_html(self, registry: TechniqueRegistry) -> str:
        """Build HTML cards for top defenders."""
        if not self.defender_hof:
            return "<p class='muted'>No defenders in hall of fame.</p>"

        cards = []
        for i, d in enumerate(self.defender_hof[:5]):
            fitness = d.fitness.values if d.fitness.valid else (0, 0)
            rules_html = ""
            for gene in d.genes:
                try:
                    tech = registry.get(gene.technique_detected)
                    name = html_module.escape(tech.name[:35])
                except KeyError:
                    name = gene.technique_detected

                conf_pct = int(gene.confidence * 100)
                conf_class = "high" if gene.confidence >= 0.7 else ("med" if gene.confidence >= 0.4 else "low")
                resp_class = gene.response_action.value.replace("_", "")

                rules_html += (
                    f'<div class="rule-row">'
                    f'<span class="rule-tech">{gene.technique_detected}</span>'
                    f'<span class="rule-name">{name}</span>'
                    f'<span class="rule-logic">{gene.detection_logic.value}</span>'
                    f'<span class="conf-bar {conf_class}" title="Confidence: {gene.confidence:.0%}">'
                    f'<span class="conf-fill" style="width:{conf_pct}%"></span></span>'
                    f'<span class="rule-response {resp_class}">{gene.response_action.value}</span>'
                    f'</div>'
                )

            cards.append(
                f'<div class="hof-card defender-card">'
                f'<div class="hof-header">'
                f'<span class="hof-rank">#{i+1}</span>'
                f'<span class="hof-scores">'
                f'<span class="score-label">COV</span><span class="score-val">{fitness[0]:.1f}</span>'
                f'<span class="score-sep">|</span>'
                f'<span class="score-label">EFF</span><span class="score-val">{fitness[1]:.2f}</span>'
                f'</span>'
                f'<span class="rule-count">{len(d.genes)} rules</span>'
                f'</div>'
                f'<div class="rules-list">{rules_html}</div>'
                f'</div>'
            )
        return "\n".join(cards)

    @staticmethod
    def _trend_arrow(start: float, end: float) -> str:
        if end > start * 1.05:
            return '<span class="trend up">&#9650;</span>'
        elif end < start * 0.95:
            return '<span class="trend down">&#9660;</span>'
        return '<span class="trend flat">&#9654;</span>'

    @staticmethod
    def _md_to_html(md: str) -> str:
        """Minimal markdown to HTML conversion."""
        if not md.strip():
            return "<p class='muted'>No threat brief available.</p>"

        lines = md.split("\n")
        out: list[str] = []
        in_list = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("# "):
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append(f"<h2>{html_module.escape(stripped[2:])}</h2>")
            elif stripped.startswith("## "):
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append(f"<h3>{html_module.escape(stripped[3:])}</h3>")
            elif stripped.startswith("### "):
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append(f"<h4>{html_module.escape(stripped[4:])}</h4>")
            elif stripped.startswith("- "):
                if not in_list:
                    out.append("<ul>")
                    in_list = True
                content = stripped[2:]
                # Bold
                import re
                content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_module.escape(content))
                out.append(f"<li>{content}</li>")
            elif stripped.startswith("*") and stripped.endswith("*") and len(stripped) > 2:
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append(f"<p><em>{html_module.escape(stripped[1:-1])}</em></p>")
            elif stripped.startswith("---"):
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append("<hr>")
            elif stripped:
                if in_list:
                    out.append("</ul>")
                    in_list = False
                import re
                content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_module.escape(stripped))
                # Handle numbered list items
                if re.match(r'^\d+\.', content):
                    out.append(f"<p class='step'>{content}</p>")
                else:
                    out.append(f"<p>{content}</p>")
            else:
                if in_list:
                    out.append("</ul>")
                    in_list = False

        if in_list:
            out.append("</ul>")

        return "\n".join(out)


# ── HTML Template ──

_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACES Dashboard — Adversarial Co-Evolution Results</title>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>
/* ── Reset & Base ── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:       #0f1117;
  --surface:  #161b22;
  --surface2: #1c2230;
  --border:   #2d333b;
  --text:     #c9d1d9;
  --text2:    #8b949e;
  --red:      #ef4444;
  --red-dim:  rgba(239,68,68,0.15);
  --blue:     #3b82f6;
  --blue-dim: rgba(59,130,246,0.15);
  --amber:    #f59e0b;
  --green:    #22c55e;
  --radius:   8px;
}}
html{{font-size:14px}} body{{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.5}}
a{{color:var(--blue);text-decoration:none}} a:hover{{text-decoration:underline}}
.muted{{color:var(--text2)}}

/* ── Layout ── */
.shell{{max-width:1440px;margin:0 auto;padding:24px 28px 60px}}
header{{display:flex;align-items:center;gap:16px;padding-bottom:20px;border-bottom:1px solid var(--border);margin-bottom:24px}}
header h1{{font-size:1.5rem;font-weight:700;letter-spacing:-0.02em}}
header .subtitle{{color:var(--text2);font-size:0.85rem}}
header .logo{{font-size:2rem;line-height:1}}

/* ── Tabs ── */
.tabs{{display:flex;gap:2px;border-bottom:2px solid var(--border);margin-bottom:24px;overflow-x:hidden}}
.tab{{padding:10px 16px;cursor:pointer;color:var(--text2);font-size:0.82rem;font-weight:500;border-bottom:2px solid transparent;margin-bottom:-2px;white-space:nowrap;transition:color .15s,border-color .15s;user-select:none}}
.tab:hover{{color:var(--text)}}
.tab.active{{color:var(--text);border-bottom-color:var(--blue)}}
.tab-content{{display:none}} .tab-content.active{{display:block}}

/* ── Stat Cards ── */
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}}
.stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px}}
.stat-card .stat-label{{font-size:0.7rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text2);margin-bottom:4px}}
.stat-card .stat-value{{font-size:1.6rem;font-weight:700;line-height:1.1}}
.stat-card .stat-sub{{font-size:0.75rem;color:var(--text2);margin-top:4px}}
.stat-card.red .stat-value{{color:var(--red)}}
.stat-card.blue .stat-value{{color:var(--blue)}}
.stat-card.amber .stat-value{{color:var(--amber)}}
.stat-card.green .stat-value{{color:var(--green)}}

.trend{{font-size:0.75rem;margin-left:4px}}
.trend.up{{color:var(--green)}} .trend.down{{color:var(--red)}} .trend.flat{{color:var(--text2)}}

/* ── Chart containers ── */
.chart-box{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:20px;overflow:hidden}}
.chart-box h3{{font-size:0.9rem;font-weight:600;margin-bottom:12px;color:var(--text)}}
.chart-row{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:900px){{.chart-row{{grid-template-columns:1fr}}}}

/* ── Hall of Fame ── */
.hof-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;margin-bottom:14px}}
.hof-header{{display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap}}
.hof-rank{{font-size:1.3rem;font-weight:800;min-width:36px}}
.attacker-card .hof-rank{{color:var(--red)}}
.defender-card .hof-rank{{color:var(--blue)}}
.hof-scores{{display:flex;align-items:center;gap:6px;font-size:0.8rem}}
.score-label{{color:var(--text2);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.04em}}
.score-val{{font-weight:700;font-variant-numeric:tabular-nums}}
.score-sep{{color:var(--border)}}
.rule-count{{margin-left:auto;font-size:0.75rem;color:var(--text2);background:var(--surface2);padding:2px 10px;border-radius:20px}}

/* Kill chain steps */
.chain-steps{{display:flex;flex-direction:column;gap:4px}}
.chain-step{{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:4px;background:var(--surface2);font-size:0.78rem}}
.step-num{{font-weight:700;color:var(--text2);min-width:16px;text-align:right}}
.tactic-badge{{font-size:0.6rem;text-transform:uppercase;letter-spacing:0.04em;padding:1px 7px;border-radius:3px;font-weight:600;white-space:nowrap}}
.initialaccess{{background:var(--red-dim);color:var(--red)}}
.execution{{background:rgba(249,115,22,0.15);color:#f97316}}
.persistence{{background:rgba(168,85,247,0.15);color:#a855f7}}
.privilegeescalation{{background:rgba(236,72,153,0.15);color:#ec4899}}
.defenseevasion{{background:rgba(34,197,94,0.15);color:#22c55e}}
.credentialaccess{{background:rgba(245,158,11,0.15);color:#f59e0b}}
.discovery{{background:rgba(6,182,212,0.15);color:#06b6d4}}
.lateralmovement{{background:rgba(99,102,241,0.15);color:#6366f1}}
.collection{{background:rgba(168,162,158,0.15);color:#a8a29e}}
.exfiltration{{background:rgba(239,68,68,0.15);color:#ef4444}}
.impact{{background:rgba(220,38,38,0.2);color:#dc2626}}
.tech-id{{font-weight:600;font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;min-width:72px}}
.tech-name{{color:var(--text2);flex:1}}
.stealth-dot{{width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0}}

/* Defender rules */
.rules-list{{display:flex;flex-direction:column;gap:3px}}
.rule-row{{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:4px;background:var(--surface2);font-size:0.78rem}}
.rule-tech{{font-weight:600;font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;min-width:72px}}
.rule-name{{color:var(--text2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.rule-logic{{font-size:0.65rem;text-transform:uppercase;color:var(--amber);min-width:70px}}
.conf-bar{{width:50px;height:6px;background:var(--border);border-radius:3px;overflow:hidden;flex-shrink:0}}
.conf-fill{{height:100%;border-radius:3px}}
.conf-bar.high .conf-fill{{background:var(--green)}}
.conf-bar.med .conf-fill{{background:var(--amber)}}
.conf-bar.low .conf-fill{{background:var(--red)}}
.rule-response{{font-size:0.6rem;text-transform:uppercase;letter-spacing:0.03em;padding:1px 6px;border-radius:3px;background:var(--surface);color:var(--text2);white-space:nowrap}}
.rule-response.isolatehost{{background:rgba(239,68,68,0.15);color:var(--red)}}
.rule-response.revokecredential{{background:rgba(245,158,11,0.15);color:var(--amber)}}
.rule-response.blocktraffic{{background:rgba(99,102,241,0.15);color:#6366f1}}

/* Threat brief */
.brief{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:28px 32px;line-height:1.7}}
.brief h2{{font-size:1.2rem;margin:24px 0 10px;color:var(--text);border-bottom:1px solid var(--border);padding-bottom:6px}}
.brief h2:first-child{{margin-top:0}}
.brief h3{{font-size:1rem;margin:18px 0 8px;color:var(--text)}}
.brief h4{{font-size:0.9rem;margin:14px 0 6px;color:var(--text)}}
.brief p{{margin:6px 0;color:var(--text2)}}
.brief p.step{{padding-left:12px;border-left:2px solid var(--border)}}
.brief ul{{margin:6px 0 6px 20px;color:var(--text2)}}
.brief li{{margin:3px 0}}
.brief strong{{color:var(--text)}}
.brief hr{{border:none;border-top:1px solid var(--border);margin:20px 0}}

/* ── Run Tab ── */
.tab.run-tab{{color:var(--green)}}
.run-config-panel{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}}
@media(max-width:900px){{.run-config-panel{{grid-template-columns:1fr}}}}
.run-config-box,.run-stats-box{{min-height:300px}}
.run-form{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:8px}}
.run-field{{display:flex;flex-direction:column;gap:4px}}
.run-field label{{font-size:0.7rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text2)}}
.run-field input{{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);font-size:0.9rem;font-family:inherit;outline:none;transition:border-color .15s}}
.run-field input:focus{{border-color:var(--blue)}}
.run-btn{{grid-column:1/-1;padding:12px 24px;background:var(--green);color:#0f1117;border:none;border-radius:8px;font-size:0.95rem;font-weight:700;cursor:pointer;transition:opacity .15s,background .15s;letter-spacing:0.01em}}
.run-btn:hover{{opacity:0.9}}
.run-btn:disabled{{opacity:0.4;cursor:not-allowed}}
.run-status-idle{{display:flex;flex-direction:column;align-items:center;justify-content:center;height:200px;color:var(--text2)}}
.idle-icon{{font-size:3rem;margin-bottom:12px;opacity:0.3}}
.run-progress{{display:none}}
.run-progress.visible{{display:block}}
.progress-track{{width:100%;height:10px;background:var(--surface2);border-radius:5px;overflow:hidden;margin:12px 0}}
.progress-fill{{height:100%;background:linear-gradient(90deg,var(--blue),var(--green));border-radius:5px;transition:width .3s ease;width:0%}}
.progress-label{{font-size:0.85rem;color:var(--text);font-weight:600;margin-bottom:4px}}
.progress-stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:12px}}
.progress-stat{{background:var(--surface2);border-radius:6px;padding:8px 10px;text-align:center}}
.progress-stat .ps-label{{font-size:0.6rem;text-transform:uppercase;color:var(--text2);letter-spacing:0.05em}}
.progress-stat .ps-value{{font-size:1.05rem;font-weight:700;font-variant-numeric:tabular-nums}}
.progress-stat.red .ps-value{{color:var(--red)}}
.progress-stat.blue .ps-value{{color:var(--blue)}}
.progress-stat.amber .ps-value{{color:var(--amber)}}
.progress-stat.green .ps-value{{color:var(--green)}}
.run-live-charts{{display:none}}
.run-live-charts.visible{{display:block}}
.run-complete{{display:none;text-align:center;padding:20px 0}}
.run-complete.visible{{display:block}}
.run-complete .complete-icon{{font-size:2.5rem;color:var(--green);margin-bottom:8px}}
.run-complete h3{{color:var(--green);font-size:1.1rem;margin-bottom:8px}}
.run-complete p{{color:var(--text2);font-size:0.85rem}}
.run-complete .reload-btn{{display:inline-block;margin-top:14px;padding:10px 28px;background:var(--blue);color:white;border:none;border-radius:8px;font-size:0.9rem;font-weight:600;cursor:pointer;text-decoration:none;transition:opacity .15s}}
.run-complete .reload-btn:hover{{opacity:0.9}}
.run-error{{display:none;color:var(--red);font-size:0.85rem;margin-top:12px;padding:12px;background:rgba(239,68,68,0.1);border-radius:6px}}
.run-error.visible{{display:block}}
.run-log{{max-height:200px;overflow-y:auto;font-family:'SF Mono',SFMono-Regular,Consolas,monospace;font-size:0.72rem;color:var(--text2);background:var(--surface2);border-radius:6px;padding:10px}}
.run-log .log-line{{padding:1px 0;border-bottom:1px solid rgba(45,51,59,0.5)}}
.run-log .log-line:last-child{{border-bottom:none}}

/* ── Footer ── */
footer{{text-align:center;padding:32px 0;color:var(--text2);font-size:0.75rem;border-top:1px solid var(--border);margin-top:40px}}
</style>
</head>
<body>
<div class="shell">

<header>
  <div class="logo">&#9763;</div>
  <div>
    <h1>ACES Dashboard</h1>
    <div class="subtitle">Adversarial Co-Evolution Attack Simulator — Results</div>
  </div>
</header>

<!-- ── Tabs ── -->
<div class="tabs">
  <div class="tab active" data-tab="overview">Overview</div>
  <div class="tab" data-tab="arms-race">Arms Race</div>
  <div class="tab" data-tab="attacker-evo">Attacker Evolution</div>
  <div class="tab" data-tab="hall-of-fame">Hall of Fame</div>
  <div class="tab" data-tab="network">Network</div>
  <div class="tab" data-tab="brief">Threat Brief</div>
  <div class="tab run-tab" data-tab="run">Run Simulation</div>
</div>

<!-- ══════════ OVERVIEW ══════════ -->
<div class="tab-content active" id="tab-overview">
  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-label">Generations</div>
      <div class="stat-value">{num_generations}</div>
      <div class="stat-sub">Pop: {population_size} &middot; Seed: {seed}</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">ATK Effectiveness (max)</div>
      <div class="stat-value">{atk_max_final} {atk_trend}</div>
      <div class="stat-sub">Mean: {atk_mean_final}</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">ATK Stealth (mean)</div>
      <div class="stat-value">{atk_stealth_final}</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">DEF Coverage (max)</div>
      <div class="stat-value">{def_max_final} {def_trend}</div>
      <div class="stat-sub">Mean: {def_mean_final}</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">DEF Efficiency (mean)</div>
      <div class="stat-value">{def_eff_final}</div>
    </div>
    <div class="stat-card amber">
      <div class="stat-label">Unique Kill Chains</div>
      <div class="stat-value">{unique_chains}</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Detection Coverage</div>
      <div class="stat-value">{detection_pct}%</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Elapsed</div>
      <div class="stat-value">{elapsed}s</div>
      <div class="stat-sub">ATK div: {atk_diversity} &middot; DEF div: {def_diversity}</div>
    </div>
  </div>

  <div class="chart-box">
    <h3>Fitness Trajectory — Arms Race Dynamics</h3>
    {chart_fitness}
  </div>
  <div class="chart-row">
    <div class="chart-box">
      <h3>Stealth vs Efficiency</h3>
      {chart_stealth}
    </div>
    <div class="chart-box">
      <h3>Detection Coverage Over Time</h3>
      {chart_detection}
    </div>
  </div>
</div>

<!-- ══════════ ARMS RACE ══════════ -->
<div class="tab-content" id="tab-arms-race">
  <div class="chart-box">
    <h3>Fitness Trajectory — Attacker Effectiveness vs Defender Coverage</h3>
    {chart_fitness}
  </div>
  <div class="chart-row">
    <div class="chart-box">
      <h3>Stealth vs Efficiency</h3>
      {chart_stealth}
    </div>
    <div class="chart-box">
      <h3>Detection Coverage</h3>
      {chart_detection}
    </div>
  </div>
  <div class="chart-box">
    <h3>Attack Path Diversity</h3>
    {chart_diversity}
  </div>
</div>

<!-- ══════════ ATTACKER EVOLUTION ══════════ -->
<div class="tab-content" id="tab-attacker-evo">
  <div class="chart-box">
    <h3>ATT&amp;CK Technique Frequency Heatmap</h3>
    {chart_heatmap}
  </div>
  <div class="chart-row">
    <div class="chart-box">
      <h3>Attack Path Diversity</h3>
      {chart_diversity}
    </div>
    <div class="chart-box">
      <h3>Pareto Front Evolution (Effectiveness vs Stealth)</h3>
      {chart_pareto}
    </div>
  </div>
</div>

<!-- ══════════ HALL OF FAME ══════════ -->
<div class="tab-content" id="tab-hall-of-fame">
  <div class="chart-row">
    <div>
      <h3 style="color:var(--red);margin-bottom:14px">Top Attackers ({attacker_hof_count})</h3>
      {attacker_hof_html}
    </div>
    <div>
      <h3 style="color:var(--blue);margin-bottom:14px">Top Defenders ({defender_hof_count})</h3>
      {defender_hof_html}
    </div>
  </div>
</div>

<!-- ══════════ NETWORK ══════════ -->
<div class="tab-content" id="tab-network">
  <div class="chart-box">
    <h3>Network Topology — Asset Criticality Map</h3>
    {chart_network}
  </div>
</div>

<!-- ══════════ THREAT BRIEF ══════════ -->
<div class="tab-content" id="tab-brief">
  <div class="brief">
    {threat_brief_html}
  </div>
</div>

<!-- ══════════ RUN SIMULATION ══════════ -->
<div class="tab-content" id="tab-run">

  <!-- Config Panel -->
  <div class="run-config-panel">
    <div class="chart-box run-config-box">
      <h3>Configure Simulation</h3>
      <form class="run-form" id="runForm" onsubmit="return false">
        <div class="run-field">
          <label for="rf-gens">Generations</label>
          <input type="number" id="rf-gens" value="30" min="5" max="500" step="5">
        </div>
        <div class="run-field">
          <label for="rf-pop">Population Size</label>
          <input type="number" id="rf-pop" value="20" min="5" max="100" step="5">
        </div>
        <div class="run-field">
          <label for="rf-seed">Random Seed</label>
          <input type="number" id="rf-seed" value="42" min="0" max="99999">
        </div>
        <div class="run-field">
          <label for="rf-match">Matchups / Eval</label>
          <input type="number" id="rf-match" value="5" min="1" max="20">
        </div>
        <button type="button" class="run-btn" id="runBtn" onclick="startRun()">Start Simulation</button>
      </form>
      <div class="run-error" id="runError"></div>
    </div>

    <!-- Live Stats -->
    <div class="chart-box run-stats-box">
      <h3>Live Status</h3>
      <div class="run-status-idle" id="statusIdle">
        <div class="idle-icon">&#9654;</div>
        <p>Configure parameters and press <strong>Start Simulation</strong></p>
      </div>
      <div class="run-progress" id="runProgress">
        <div class="progress-label" id="progressLabel">Starting...</div>
        <div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
        <div class="progress-stats">
          <div class="progress-stat red">
            <div class="ps-label">ATK Effectiveness</div>
            <div class="ps-value" id="ps-atk">—</div>
          </div>
          <div class="progress-stat blue">
            <div class="ps-label">DEF Coverage</div>
            <div class="ps-value" id="ps-def">—</div>
          </div>
          <div class="progress-stat amber">
            <div class="ps-label">Kill Chains</div>
            <div class="ps-value" id="ps-chains">—</div>
          </div>
          <div class="progress-stat green">
            <div class="ps-label">Detection %</div>
            <div class="ps-value" id="ps-det">—</div>
          </div>
          <div class="progress-stat" style="color:var(--text)">
            <div class="ps-label">ATK Stealth</div>
            <div class="ps-value" id="ps-stealth">—</div>
          </div>
          <div class="progress-stat" style="color:var(--text)">
            <div class="ps-label">DEF Efficiency</div>
            <div class="ps-value" id="ps-defeff">—</div>
          </div>
        </div>
      </div>
      <div class="run-complete" id="runComplete">
        <div class="complete-icon">&#10003;</div>
        <h3>Simulation Complete</h3>
        <p id="completeMsg"></p>
        <button class="reload-btn" onclick="window.location.reload()">View Full Dashboard</button>
      </div>
    </div>
  </div>

  <!-- Live Learning Visualization -->
  <div class="run-live-charts" id="runLiveCharts">
    <div class="chart-row">
      <div class="chart-box">
        <h3>Arms Race — Live</h3>
        <div id="liveArmsRace" style="width:100%;height:340px"></div>
      </div>
      <div class="chart-box">
        <h3>Stealth vs Efficiency — Live</h3>
        <div id="liveStealthEff" style="width:100%;height:340px"></div>
      </div>
    </div>
    <div class="chart-row">
      <div class="chart-box">
        <h3>Detection Coverage — Live</h3>
        <div id="liveDetection" style="width:100%;height:280px"></div>
      </div>
      <div class="chart-box">
        <h3>Kill Chain Diversity — Live</h3>
        <div id="liveChains" style="width:100%;height:280px"></div>
      </div>
    </div>
  </div>

  <!-- Generation Log -->
  <div class="chart-box" id="runLogBox" style="display:none">
    <h3>Generation Log</h3>
    <div class="run-log" id="runLog"></div>
  </div>

</div>

<footer>
  ACES — Adversarial Co-Evolution Simulator &middot; Generated by ACES v0.1.0
</footer>

</div>

<script>
document.querySelectorAll('.tab').forEach(tab => {{
  tab.addEventListener('click', () => {{
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    // Trigger Plotly resize for newly visible charts
    window.dispatchEvent(new Event('resize'));
  }});
}});
</script>
<script>
// ── Live chart state ──
var _liveData = {{
  gens: [], atkEff: [], defCov: [], stealth: [], defEff: [], detection: [], chains: [],
  chartsReady: false
}};

var _plotlyDarkLayout = {{
  paper_bgcolor: 'rgba(0,0,0,0)',
  plot_bgcolor: 'rgba(0,0,0,0)',
  font: {{ color: '#8b949e', size: 11 }},
  margin: {{ t: 8, b: 36, l: 48, r: 16 }},
  xaxis: {{ title: 'Generation', gridcolor: 'rgba(45,51,59,0.5)', zerolinecolor: 'rgba(45,51,59,0.5)' }},
  yaxis: {{ gridcolor: 'rgba(45,51,59,0.5)', zerolinecolor: 'rgba(45,51,59,0.5)' }},
  legend: {{ orientation: 'h', yanchor: 'bottom', y: 1.02, xanchor: 'center', x: 0.5, font: {{ size: 10 }} }},
  hovermode: 'x unified',
}};

function initLiveCharts() {{
  var cfg = {{ responsive: true, displayModeBar: false }};

  // Arms Race chart (dual y-axis)
  Plotly.newPlot('liveArmsRace', [
    {{ x: [], y: [], name: 'ATK Effectiveness', line: {{ color: '#ef4444', width: 2 }}, yaxis: 'y' }},
    {{ x: [], y: [], name: 'DEF Coverage', line: {{ color: '#3b82f6', width: 2 }}, yaxis: 'y2' }},
  ], Object.assign({{}}, _plotlyDarkLayout, {{
    yaxis: Object.assign({{}}, _plotlyDarkLayout.yaxis, {{ title: 'ATK Effectiveness' }}),
    yaxis2: {{ title: 'DEF Coverage', overlaying: 'y', side: 'right', gridcolor: 'rgba(45,51,59,0.3)', font: {{ color: '#8b949e' }} }},
    height: 340,
  }}), cfg);

  // Stealth vs Efficiency
  Plotly.newPlot('liveStealthEff', [
    {{ x: [], y: [], name: 'ATK Stealth', line: {{ color: '#ef4444', width: 2 }} }},
    {{ x: [], y: [], name: 'DEF Efficiency', line: {{ color: '#3b82f6', width: 2 }} }},
  ], Object.assign({{}}, _plotlyDarkLayout, {{
    yaxis: Object.assign({{}}, _plotlyDarkLayout.yaxis, {{ title: 'Score (0-1)', range: [0, 1.05] }}),
    height: 340,
  }}), cfg);

  // Detection Coverage
  Plotly.newPlot('liveDetection', [
    {{ x: [], y: [], name: 'Detection %', fill: 'tozeroy',
      line: {{ color: '#3b82f6', width: 2 }}, fillcolor: 'rgba(59,130,246,0.12)' }},
  ], Object.assign({{}}, _plotlyDarkLayout, {{
    yaxis: Object.assign({{}}, _plotlyDarkLayout.yaxis, {{ title: '% Techniques Covered', range: [0, 100] }}),
    height: 280,
  }}), cfg);

  // Kill Chains
  Plotly.newPlot('liveChains', [
    {{ x: [], y: [], name: 'Unique Kill Chains', line: {{ color: '#f59e0b', width: 2 }} }},
  ], Object.assign({{}}, _plotlyDarkLayout, {{
    yaxis: Object.assign({{}}, _plotlyDarkLayout.yaxis, {{ title: 'Unique Chains' }}),
    height: 280,
  }}), cfg);

  _liveData.chartsReady = true;
}}

function updateLiveCharts(d) {{
  var gen = d.generation;
  _liveData.gens.push(gen);
  _liveData.atkEff.push(d.atk_eff || 0);
  _liveData.defCov.push(d.def_cov || 0);
  _liveData.stealth.push(d.atk_stealth || 0);
  _liveData.defEff.push(d.def_eff || 0);
  _liveData.detection.push(d.detection || 0);
  _liveData.chains.push(d.chains || 0);

  var g = _liveData.gens;

  Plotly.react('liveArmsRace', [
    {{ x: g, y: _liveData.atkEff, name: 'ATK Effectiveness', line: {{ color: '#ef4444', width: 2 }}, yaxis: 'y' }},
    {{ x: g, y: _liveData.defCov, name: 'DEF Coverage', line: {{ color: '#3b82f6', width: 2 }}, yaxis: 'y2' }},
  ]);

  Plotly.react('liveStealthEff', [
    {{ x: g, y: _liveData.stealth, name: 'ATK Stealth', line: {{ color: '#ef4444', width: 2 }} }},
    {{ x: g, y: _liveData.defEff, name: 'DEF Efficiency', line: {{ color: '#3b82f6', width: 2 }} }},
  ]);

  Plotly.react('liveDetection', [
    {{ x: g, y: _liveData.detection, name: 'Detection %', fill: 'tozeroy',
      line: {{ color: '#3b82f6', width: 2 }}, fillcolor: 'rgba(59,130,246,0.12)' }},
  ]);

  Plotly.react('liveChains', [
    {{ x: g, y: _liveData.chains, name: 'Unique Kill Chains', line: {{ color: '#f59e0b', width: 2 }} }},
  ]);
}}

function startRun() {{
  var btn = document.getElementById('runBtn');
  var progress = document.getElementById('runProgress');
  var complete = document.getElementById('runComplete');
  var errorDiv = document.getElementById('runError');
  var liveCharts = document.getElementById('runLiveCharts');
  var logBox = document.getElementById('runLogBox');
  var statusIdle = document.getElementById('statusIdle');

  if (window.location.protocol === 'file:') {{
    errorDiv.textContent = 'Run via the ACES server: python examples/run_server.py';
    errorDiv.classList.add('visible');
    return;
  }}

  // Reset state
  btn.disabled = true;
  btn.textContent = 'Running...';
  statusIdle.style.display = 'none';
  progress.classList.add('visible');
  complete.classList.remove('visible');
  errorDiv.classList.remove('visible');
  liveCharts.classList.add('visible');
  logBox.style.display = 'block';
  document.getElementById('runLog').innerHTML = '';
  _liveData = {{ gens: [], atkEff: [], defCov: [], stealth: [], defEff: [], detection: [], chains: [], chartsReady: false }};

  // Init live charts
  initLiveCharts();

  var params = {{
    generations: parseInt(document.getElementById('rf-gens').value) || 30,
    population: parseInt(document.getElementById('rf-pop').value) || 20,
    seed: parseInt(document.getElementById('rf-seed').value) || 42,
    matchups: parseInt(document.getElementById('rf-match').value) || 5,
  }};

  fetch('/api/run', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(params),
  }}).then(function(r) {{ return r.json(); }}).then(function(data) {{
    if (data.error) {{
      errorDiv.textContent = data.error;
      errorDiv.classList.add('visible');
      btn.disabled = false;
      btn.textContent = 'Start Simulation';
      return;
    }}

    var es = new EventSource('/api/status');
    es.onmessage = function(e) {{
      var d = JSON.parse(e.data);

      if (d.type === 'generation' || d.generation) {{
        var gen = d.generation || 0;
        var total = d.total || params.generations;
        var pct = Math.round((gen / total) * 100);
        document.getElementById('progressFill').style.width = pct + '%';
        document.getElementById('progressLabel').textContent =
          'Generation ' + gen + ' / ' + total + '  (' + pct + '%)';

        // Update stat cards
        if (d.atk_eff !== undefined) document.getElementById('ps-atk').textContent = d.atk_eff;
        if (d.def_cov !== undefined) document.getElementById('ps-def').textContent = d.def_cov;
        if (d.chains !== undefined) document.getElementById('ps-chains').textContent = d.chains;
        if (d.detection !== undefined) document.getElementById('ps-det').textContent = d.detection + '%';
        if (d.atk_stealth !== undefined) document.getElementById('ps-stealth').textContent = d.atk_stealth;
        if (d.def_eff !== undefined) document.getElementById('ps-defeff').textContent = d.def_eff;

        // Update live charts
        if (_liveData.chartsReady) updateLiveCharts(d);

        // Log line
        var log = document.getElementById('runLog');
        var line = document.createElement('div');
        line.className = 'log-line';
        line.textContent = 'Gen ' + gen +
          '  ATK=' + (d.atk_eff||'?') + ' stl=' + (d.atk_stealth||'?') +
          '  DEF=' + (d.def_cov||'?') + ' eff=' + (d.def_eff||'?') +
          '  chains=' + (d.chains||'?') +
          '  det=' + (d.detection||'?') + '%';
        log.appendChild(line);
        log.scrollTop = log.scrollHeight;
      }}

      if (d.type === 'complete') {{
        es.close();
        document.getElementById('progressFill').style.width = '100%';
        document.getElementById('progressLabel').textContent = 'Complete!';
        complete.classList.add('visible');
        document.getElementById('completeMsg').textContent =
          'Finished in ' + d.elapsed + 's — Results saved to ' + d.output_dir;
        btn.disabled = false;
        btn.textContent = 'Start Simulation';
      }}

      if (d.type === 'error') {{
        es.close();
        errorDiv.textContent = 'Error: ' + d.error;
        errorDiv.classList.add('visible');
        btn.disabled = false;
        btn.textContent = 'Start Simulation';
      }}
    }};

    es.onerror = function() {{
      es.close();
      setTimeout(function() {{ _pollComplete(btn); }}, 2000);
    }};
  }}).catch(function(err) {{
    errorDiv.textContent = 'Request failed: ' + err;
    errorDiv.classList.add('visible');
    btn.disabled = false;
    btn.textContent = 'Start Simulation';
  }});
}}

function _pollComplete(btn) {{
  fetch('/api/progress').then(function(r) {{ return r.json(); }}).then(function(d) {{
    if (d.status === 'complete' || d.status === 'error') {{
      btn.disabled = false;
      btn.textContent = 'Start Simulation';
      if (d.status === 'complete') {{
        document.getElementById('runComplete').classList.add('visible');
        document.getElementById('completeMsg').textContent = 'Simulation complete.';
      }}
    }} else {{
      setTimeout(function() {{ _pollComplete(btn); }}, 1500);
    }}
  }});
}}
</script>
</body>
</html>"""
