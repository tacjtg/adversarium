"""Lightweight web server for running ACES simulations from the browser.

Uses only Python stdlib (http.server, threading, json).
No external dependencies required.

Usage:
    python -m aces.web.server --port 8150
"""

from __future__ import annotations

import json
import queue
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.evolution.coevolution import CoevolutionEngine, save_results
from aces.narration.llm_narrator import LLMNarrator
from aces.visualization.dashboard import Dashboard


class _RunState:
    """Shared state for the current simulation run."""

    def __init__(self) -> None:
        self.running = False
        self.progress: dict = {}
        self.event_queues: list[queue.Queue] = []
        self.last_result_path: str | None = None
        self.last_dashboard_html: str | None = None
        self.error: str | None = None
        self._lock = threading.Lock()

    def broadcast(self, event: dict) -> None:
        with self._lock:
            dead = []
            for q in self.event_queues:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.event_queues.remove(q)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            self.event_queues.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self.event_queues:
                self.event_queues.remove(q)


_state = _RunState()


def _run_simulation(
    generations: int,
    population: int,
    seed: int,
    matchups: int,
    output_dir: str,
) -> None:
    """Execute a simulation run in a background thread."""
    global _state
    _state.running = True
    _state.error = None
    _state.progress = {"generation": 0, "total": generations, "status": "starting"}
    _state.broadcast({"type": "started", "total": generations})

    try:
        TechniqueRegistry.reset()

        config = Config.from_defaults()
        config.num_generations = generations
        config.population_size = population
        config.seed = seed
        config.matchups_per_eval = matchups

        def on_gen(gen: int, total: int, metrics_snapshot) -> None:
            _state.progress = {
                "generation": gen + 1,
                "total": total,
                "status": "running",
                "atk_eff": round(metrics_snapshot.attacker_fitness_max, 2),
                "atk_stealth": round(metrics_snapshot.attacker_stealth_mean, 3),
                "def_cov": round(metrics_snapshot.defender_coverage_max, 1),
                "def_eff": round(metrics_snapshot.defender_efficiency_mean, 3),
                "chains": metrics_snapshot.unique_kill_chains,
                "detection": round(metrics_snapshot.detection_coverage_ratio * 100, 1),
            }
            _state.broadcast({"type": "generation", **_state.progress})

        engine = CoevolutionEngine(config)
        result = engine.run(quiet=True, on_generation=on_gen)

        out_path = save_results(result, output_dir)

        narrator = LLMNarrator()
        brief = narrator.generate_threat_brief(
            result.attacker_hof, result.defender_hof, result.metrics, engine.network
        )
        with open(out_path / "threat_brief.md", "w") as f:
            f.write(brief)

        dashboard = Dashboard(result.metrics, result.attacker_hof, result.defender_hof)
        dashboard.generate_all(str(out_path), network=engine.network)

        dashboard.generate_unified_dashboard(
            output_path=str(out_path / "dashboard.html"),
            network=engine.network,
            threat_brief_md=brief,
            config_dict=config.model_dump(),
            elapsed_seconds=result.elapsed_seconds,
        )

        _state.last_result_path = str(out_path)
        _state.last_dashboard_html = (out_path / "dashboard.html").read_text(encoding="utf-8")
        _state.progress = {"generation": generations, "total": generations, "status": "complete"}
        _state.broadcast({
            "type": "complete",
            "output_dir": str(out_path),
            "elapsed": round(result.elapsed_seconds, 1),
        })

    except Exception as e:
        _state.error = str(e)
        _state.progress = {"status": "error", "error": str(e)}
        _state.broadcast({"type": "error", "error": str(e)})

    finally:
        _state.running = False


class ACESHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the ACES web interface."""

    def log_message(self, format, *args):
        pass

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/dashboard":
            self._serve_dashboard()
        elif path == "/api/status":
            self._serve_sse()
        elif path == "/api/progress":
            self._send_json(_state.progress)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/run":
            self._handle_run()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _serve_dashboard(self) -> None:
        """Serve last run's dashboard or the launcher page."""
        if _state.last_dashboard_html:
            self._send_html(_state.last_dashboard_html)
        else:
            self._send_html(_build_launcher_page())

    def _serve_sse(self) -> None:
        """Server-Sent Events stream for live progress."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = _state.subscribe()
        try:
            self.wfile.write(f"data: {json.dumps(_state.progress)}\n\n".encode())
            self.wfile.flush()

            while True:
                try:
                    event = q.get(timeout=1.0)
                    self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                    self.wfile.flush()
                    if event.get("type") in ("complete", "error"):
                        break
                except queue.Empty:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            _state.unsubscribe(q)

    def _handle_run(self) -> None:
        """Start a new simulation run."""
        if _state.running:
            self._send_json({"error": "Simulation already running"}, 409)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length else "{}"
        try:
            params = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        generations = int(params.get("generations", 30))
        population = int(params.get("population", 20))
        seed = int(params.get("seed", 42))
        matchups = int(params.get("matchups", 5))

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = params.get("output") or f"results/run_{timestamp}"

        thread = threading.Thread(
            target=_run_simulation,
            args=(generations, population, seed, matchups, output_dir),
            daemon=True,
        )
        thread.start()

        self._send_json({
            "status": "started",
            "generations": generations,
            "population": population,
            "seed": seed,
            "matchups": matchups,
            "output_dir": output_dir,
        })


def _build_launcher_page() -> str:
    """Build a standalone launcher page with full live dashboard."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACES — Adversarial Co-Evolution Simulator</title>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f1117;--surface:#161b22;--surface2:#1c2230;--border:#2d333b;
  --text:#c9d1d9;--text2:#8b949e;--red:#ef4444;--blue:#3b82f6;
  --amber:#f59e0b;--green:#22c55e;--radius:8px;
}
html{font-size:14px}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.5}
.shell{max-width:1440px;margin:0 auto;padding:24px 28px 60px}
header{display:flex;align-items:center;gap:16px;padding-bottom:20px;border-bottom:1px solid var(--border);margin-bottom:24px}
header h1{font-size:1.5rem;font-weight:700;letter-spacing:-0.02em}
header .subtitle{color:var(--text2);font-size:0.85rem}
header .logo{font-size:2rem;line-height:1}

.chart-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:20px;overflow:hidden}
.chart-box h3{font-size:0.9rem;font-weight:600;margin-bottom:12px;color:var(--text)}
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:900px){.chart-row{grid-template-columns:1fr}}

/* ── Run Panel ── */
.run-config-panel{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}
@media(max-width:900px){.run-config-panel{grid-template-columns:1fr}}
.run-form{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:8px}
.run-field{display:flex;flex-direction:column;gap:4px}
.run-field label{font-size:0.7rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--text2)}
.run-field input{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);font-size:0.9rem;font-family:inherit;outline:none;transition:border-color .15s}
.run-field input:focus{border-color:var(--blue)}
.run-btn{grid-column:1/-1;padding:12px 24px;background:var(--green);color:#0f1117;border:none;border-radius:8px;font-size:0.95rem;font-weight:700;cursor:pointer;transition:opacity .15s;letter-spacing:0.01em}
.run-btn:hover{opacity:0.9}
.run-btn:disabled{opacity:0.4;cursor:not-allowed}
.run-status-idle{display:flex;flex-direction:column;align-items:center;justify-content:center;height:200px;color:var(--text2)}
.idle-icon{font-size:3rem;margin-bottom:12px;opacity:0.3}
.run-progress{display:none}
.run-progress.visible{display:block}
.progress-track{width:100%;height:10px;background:var(--surface2);border-radius:5px;overflow:hidden;margin:12px 0}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--green));border-radius:5px;transition:width .3s ease;width:0%}
.progress-label{font-size:0.85rem;color:var(--text);font-weight:600;margin-bottom:4px}
.progress-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:12px}
.progress-stat{background:var(--surface2);border-radius:6px;padding:8px 10px;text-align:center}
.progress-stat .ps-label{font-size:0.6rem;text-transform:uppercase;color:var(--text2);letter-spacing:0.05em}
.progress-stat .ps-value{font-size:1.05rem;font-weight:700;font-variant-numeric:tabular-nums}
.progress-stat.red .ps-value{color:var(--red)}
.progress-stat.blue .ps-value{color:var(--blue)}
.progress-stat.amber .ps-value{color:var(--amber)}
.progress-stat.green .ps-value{color:var(--green)}
.run-live-charts{display:none}
.run-live-charts.visible{display:block}
.run-complete{display:none;text-align:center;padding:20px 0}
.run-complete.visible{display:block}
.run-complete .complete-icon{font-size:2.5rem;color:var(--green);margin-bottom:8px}
.run-complete h3{color:var(--green);font-size:1.1rem;margin-bottom:8px}
.run-complete p{color:var(--text2);font-size:0.85rem}
.run-complete .reload-btn{display:inline-block;margin-top:14px;padding:10px 28px;background:var(--blue);color:white;border:none;border-radius:8px;font-size:0.9rem;font-weight:600;cursor:pointer;transition:opacity .15s}
.run-complete .reload-btn:hover{opacity:0.9}
.run-error{display:none;color:var(--red);font-size:0.85rem;margin-top:12px;padding:12px;background:rgba(239,68,68,0.1);border-radius:6px}
.run-error.visible{display:block}
.run-log{max-height:200px;overflow-y:auto;font-family:'SF Mono',SFMono-Regular,Consolas,monospace;font-size:0.72rem;color:var(--text2);background:var(--surface2);border-radius:6px;padding:10px}
.run-log .log-line{padding:1px 0;border-bottom:1px solid rgba(45,51,59,0.5)}
.run-log .log-line:last-child{border-bottom:none}

footer{text-align:center;padding:32px 0;color:var(--text2);font-size:0.75rem;border-top:1px solid var(--border);margin-top:40px}
</style>
</head>
<body>
<div class="shell">

<header>
  <div class="logo">&#9763;</div>
  <div>
    <h1>ACES Dashboard</h1>
    <div class="subtitle">Adversarial Co-Evolution Simulator — Live</div>
  </div>
</header>

<!-- Config + Status -->
<div class="run-config-panel">
  <div class="chart-box">
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
  <div class="chart-box">
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
          <div class="ps-value" id="ps-atk">&mdash;</div>
        </div>
        <div class="progress-stat blue">
          <div class="ps-label">DEF Coverage</div>
          <div class="ps-value" id="ps-def">&mdash;</div>
        </div>
        <div class="progress-stat amber">
          <div class="ps-label">Kill Chains</div>
          <div class="ps-value" id="ps-chains">&mdash;</div>
        </div>
        <div class="progress-stat green">
          <div class="ps-label">Detection %</div>
          <div class="ps-value" id="ps-det">&mdash;</div>
        </div>
        <div class="progress-stat">
          <div class="ps-label">ATK Stealth</div>
          <div class="ps-value" id="ps-stealth">&mdash;</div>
        </div>
        <div class="progress-stat">
          <div class="ps-label">DEF Efficiency</div>
          <div class="ps-value" id="ps-defeff">&mdash;</div>
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

<!-- Live Charts -->
<div class="run-live-charts" id="runLiveCharts">
  <div class="chart-row">
    <div class="chart-box">
      <h3>Arms Race &mdash; Live</h3>
      <div id="liveArmsRace" style="width:100%;height:340px"></div>
    </div>
    <div class="chart-box">
      <h3>Stealth vs Efficiency &mdash; Live</h3>
      <div id="liveStealthEff" style="width:100%;height:340px"></div>
    </div>
  </div>
  <div class="chart-row">
    <div class="chart-box">
      <h3>Detection Coverage &mdash; Live</h3>
      <div id="liveDetection" style="width:100%;height:280px"></div>
    </div>
    <div class="chart-box">
      <h3>Kill Chain Diversity &mdash; Live</h3>
      <div id="liveChains" style="width:100%;height:280px"></div>
    </div>
  </div>
</div>

<!-- Log -->
<div class="chart-box" id="runLogBox" style="display:none">
  <h3>Generation Log</h3>
  <div class="run-log" id="runLog"></div>
</div>

<footer>ACES &mdash; Adversarial Co-Evolution Simulator</footer>

</div>

<script>
var _liveData = {
  gens: [], atkEff: [], defCov: [], stealth: [], defEff: [], detection: [], chains: [],
  chartsReady: false
};

var _plotlyDark = {
  paper_bgcolor: 'rgba(0,0,0,0)',
  plot_bgcolor: 'rgba(0,0,0,0)',
  font: { color: '#8b949e', size: 11 },
  margin: { t: 8, b: 36, l: 48, r: 16 },
  xaxis: { title: 'Generation', gridcolor: 'rgba(45,51,59,0.5)', zerolinecolor: 'rgba(45,51,59,0.5)' },
  yaxis: { gridcolor: 'rgba(45,51,59,0.5)', zerolinecolor: 'rgba(45,51,59,0.5)' },
  legend: { orientation: 'h', yanchor: 'bottom', y: 1.02, xanchor: 'center', x: 0.5, font: { size: 10 } },
  hovermode: 'x unified',
};

function initLiveCharts() {
  var cfg = { responsive: true, displayModeBar: false };

  Plotly.newPlot('liveArmsRace', [
    { x: [], y: [], name: 'ATK Effectiveness', line: { color: '#ef4444', width: 2 }, yaxis: 'y' },
    { x: [], y: [], name: 'DEF Coverage', line: { color: '#3b82f6', width: 2 }, yaxis: 'y2' },
  ], Object.assign({}, _plotlyDark, {
    yaxis: Object.assign({}, _plotlyDark.yaxis, { title: 'ATK Effectiveness' }),
    yaxis2: { title: 'DEF Coverage', overlaying: 'y', side: 'right', gridcolor: 'rgba(45,51,59,0.3)' },
    height: 340,
  }), cfg);

  Plotly.newPlot('liveStealthEff', [
    { x: [], y: [], name: 'ATK Stealth', line: { color: '#ef4444', width: 2 } },
    { x: [], y: [], name: 'DEF Efficiency', line: { color: '#3b82f6', width: 2 } },
  ], Object.assign({}, _plotlyDark, {
    yaxis: Object.assign({}, _plotlyDark.yaxis, { title: 'Score (0-1)', range: [0, 1.05] }),
    height: 340,
  }), cfg);

  Plotly.newPlot('liveDetection', [
    { x: [], y: [], name: 'Detection %', fill: 'tozeroy',
      line: { color: '#3b82f6', width: 2 }, fillcolor: 'rgba(59,130,246,0.12)' },
  ], Object.assign({}, _plotlyDark, {
    yaxis: Object.assign({}, _plotlyDark.yaxis, { title: '% Techniques Covered', range: [0, 100] }),
    height: 280,
  }), cfg);

  Plotly.newPlot('liveChains', [
    { x: [], y: [], name: 'Unique Kill Chains', line: { color: '#f59e0b', width: 2 } },
  ], Object.assign({}, _plotlyDark, {
    yaxis: Object.assign({}, _plotlyDark.yaxis, { title: 'Unique Chains' }),
    height: 280,
  }), cfg);

  _liveData.chartsReady = true;
}

function updateLiveCharts(d) {
  _liveData.gens.push(d.generation);
  _liveData.atkEff.push(d.atk_eff || 0);
  _liveData.defCov.push(d.def_cov || 0);
  _liveData.stealth.push(d.atk_stealth || 0);
  _liveData.defEff.push(d.def_eff || 0);
  _liveData.detection.push(d.detection || 0);
  _liveData.chains.push(d.chains || 0);
  var g = _liveData.gens;

  Plotly.react('liveArmsRace', [
    { x: g, y: _liveData.atkEff, name: 'ATK Effectiveness', line: { color: '#ef4444', width: 2 }, yaxis: 'y' },
    { x: g, y: _liveData.defCov, name: 'DEF Coverage', line: { color: '#3b82f6', width: 2 }, yaxis: 'y2' },
  ]);
  Plotly.react('liveStealthEff', [
    { x: g, y: _liveData.stealth, name: 'ATK Stealth', line: { color: '#ef4444', width: 2 } },
    { x: g, y: _liveData.defEff, name: 'DEF Efficiency', line: { color: '#3b82f6', width: 2 } },
  ]);
  Plotly.react('liveDetection', [
    { x: g, y: _liveData.detection, name: 'Detection %', fill: 'tozeroy',
      line: { color: '#3b82f6', width: 2 }, fillcolor: 'rgba(59,130,246,0.12)' },
  ]);
  Plotly.react('liveChains', [
    { x: g, y: _liveData.chains, name: 'Unique Kill Chains', line: { color: '#f59e0b', width: 2 } },
  ]);
}

function startRun() {
  var btn = document.getElementById('runBtn');
  var progress = document.getElementById('runProgress');
  var complete = document.getElementById('runComplete');
  var errorDiv = document.getElementById('runError');
  var liveCharts = document.getElementById('runLiveCharts');
  var logBox = document.getElementById('runLogBox');
  var statusIdle = document.getElementById('statusIdle');

  btn.disabled = true;
  btn.textContent = 'Running...';
  if (statusIdle) statusIdle.style.display = 'none';
  progress.classList.add('visible');
  complete.classList.remove('visible');
  errorDiv.classList.remove('visible');
  liveCharts.classList.add('visible');
  logBox.style.display = 'block';
  document.getElementById('runLog').innerHTML = '';
  _liveData = { gens: [], atkEff: [], defCov: [], stealth: [], defEff: [], detection: [], chains: [], chartsReady: false };
  initLiveCharts();

  var params = {
    generations: parseInt(document.getElementById('rf-gens').value) || 30,
    population: parseInt(document.getElementById('rf-pop').value) || 20,
    seed: parseInt(document.getElementById('rf-seed').value) || 42,
    matchups: parseInt(document.getElementById('rf-match').value) || 5,
  };

  fetch('/api/run', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(params),
  }).then(function(r) { return r.json(); }).then(function(data) {
    if (data.error) {
      errorDiv.textContent = data.error;
      errorDiv.classList.add('visible');
      btn.disabled = false;
      btn.textContent = 'Start Simulation';
      return;
    }
    var es = new EventSource('/api/status');
    es.onmessage = function(e) {
      var d = JSON.parse(e.data);
      if (d.type === 'generation' || d.generation) {
        var gen = d.generation || 0;
        var total = d.total || params.generations;
        var pct = Math.round((gen / total) * 100);
        document.getElementById('progressFill').style.width = pct + '%';
        document.getElementById('progressLabel').textContent =
          'Generation ' + gen + ' / ' + total + '  (' + pct + '%)';
        if (d.atk_eff !== undefined) document.getElementById('ps-atk').textContent = d.atk_eff;
        if (d.def_cov !== undefined) document.getElementById('ps-def').textContent = d.def_cov;
        if (d.chains !== undefined) document.getElementById('ps-chains').textContent = d.chains;
        if (d.detection !== undefined) document.getElementById('ps-det').textContent = d.detection + '%';
        if (d.atk_stealth !== undefined) document.getElementById('ps-stealth').textContent = d.atk_stealth;
        if (d.def_eff !== undefined) document.getElementById('ps-defeff').textContent = d.def_eff;
        if (_liveData.chartsReady) updateLiveCharts(d);
        var log = document.getElementById('runLog');
        var line = document.createElement('div');
        line.className = 'log-line';
        line.textContent = 'Gen ' + gen +
          '  ATK=' + (d.atk_eff||'?') + ' stl=' + (d.atk_stealth||'?') +
          '  DEF=' + (d.def_cov||'?') + ' eff=' + (d.def_eff||'?') +
          '  chains=' + (d.chains||'?') + '  det=' + (d.detection||'?') + '%';
        log.appendChild(line);
        log.scrollTop = log.scrollHeight;
      }
      if (d.type === 'complete') {
        es.close();
        document.getElementById('progressFill').style.width = '100%';
        document.getElementById('progressLabel').textContent = 'Complete!';
        complete.classList.add('visible');
        document.getElementById('completeMsg').textContent =
          'Finished in ' + d.elapsed + 's. Results saved to ' + d.output_dir;
        btn.disabled = false;
        btn.textContent = 'Start Simulation';
      }
      if (d.type === 'error') {
        es.close();
        errorDiv.textContent = 'Error: ' + d.error;
        errorDiv.classList.add('visible');
        btn.disabled = false;
        btn.textContent = 'Start Simulation';
      }
    };
    es.onerror = function() {
      es.close();
      setTimeout(function() { _pollComplete(btn); }, 2000);
    };
  }).catch(function(err) {
    errorDiv.textContent = 'Request failed: ' + err;
    errorDiv.classList.add('visible');
    btn.disabled = false;
    btn.textContent = 'Start Simulation';
  });
}

function _pollComplete(btn) {
  fetch('/api/progress').then(function(r) { return r.json(); }).then(function(d) {
    if (d.status === 'complete' || d.status === 'error') {
      btn.disabled = false;
      btn.textContent = 'Start Simulation';
      if (d.status === 'complete') {
        document.getElementById('runComplete').classList.add('visible');
        document.getElementById('completeMsg').textContent = 'Simulation complete.';
      }
    } else {
      setTimeout(function() { _pollComplete(btn); }, 1500);
    }
  });
}
</script>
</body>
</html>"""


def create_server(host: str = "127.0.0.1", port: int = 8150) -> HTTPServer:
    """Create and return the ACES HTTP server."""
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer((host, port), ACESHandler)
    return server


def run_server(host: str = "127.0.0.1", port: int = 8150) -> None:
    """Start the ACES web server."""
    server = create_server(host, port)
    print(f"\n  ACES Web Server")
    print(f"  http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ACES Web Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8150)
    args = parser.parse_args()
    run_server(args.host, args.port)
