from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from typing import Any


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _ticks(max_value: float, *, n: int = 5) -> list[float]:
    if max_value <= 0:
        return [0.0]
    step = max_value / n
    return [step * i for i in range(n + 1)]


def _svg_bar_chart(
    *,
    title: str,
    names: list[str],
    values: list[float],
    y_label: str,
    value_fmt: str,
    width: int = 1200,
    height: int = 480,
) -> str:
    assert len(names) == len(values)

    margin_left = 90
    margin_right = 30
    margin_top = 50
    margin_bottom = 160

    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom

    vmax = max(values) if values else 1.0
    vmax = vmax * 1.05 if vmax > 0 else 1.0
    ticks = _ticks(vmax, n=5)

    n = max(1, len(values))
    gap = 10
    bar_w = max(1, int((plot_w - gap * (n - 1)) / n))

    def x_for(i: int) -> int:
        return margin_left + i * (bar_w + gap)

    def y_for(v: float) -> int:
        v = max(0.0, v)
        return margin_top + int(plot_h * (1.0 - (v / vmax)))

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">')
    parts.append('<rect width="100%" height="100%" fill="white"/>')
    parts.append(f'<text x="{width//2}" y="30" text-anchor="middle" font-size="18" font-family="DejaVu Sans">{_esc(title)}</text>')

    # Axes
    x0 = margin_left
    y0 = margin_top + plot_h
    x1 = margin_left + plot_w
    y1 = margin_top
    parts.append(f'<line x1="{x0}" y1="{y0}" x2="{x1}" y2="{y0}" stroke="#222" stroke-width="1"/>')
    parts.append(f'<line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y1}" stroke="#222" stroke-width="1"/>')

    # Y ticks + grid
    for t in ticks:
        y = y_for(t)
        parts.append(f'<line x1="{x0}" y1="{y}" x2="{x1}" y2="{y}" stroke="#ddd" stroke-width="1"/>')
        parts.append(
            f'<text x="{x0-10}" y="{y+4}" text-anchor="end" font-size="12" font-family="DejaVu Sans">{value_fmt.format(t)}</text>'
        )

    # Y label (rotated)
    parts.append(
        f'<text x="20" y="{margin_top + plot_h//2}" transform="rotate(-90 20 {margin_top + plot_h//2})" '
        f'text-anchor="middle" font-size="14" font-family="DejaVu Sans">{_esc(y_label)}</text>'
    )

    # Bars + x labels
    for i, (name, v) in enumerate(zip(names, values)):
        x = x_for(i)
        y = y_for(v)
        h = y0 - y
        parts.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{h}" fill="#4C78A8"/>')

        # Rotated label
        lx = x + bar_w // 2
        ly = y0 + 10
        parts.append(
            f'<text x="{lx}" y="{ly}" transform="rotate(35 {lx} {ly})" '
            f'text-anchor="start" font-size="12" font-family="DejaVu Sans">{_esc(name)}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def _svg_line_chart(
    *,
    title: str,
    names: list[str],
    series: dict[str, list[float]],
    y_label: str,
    value_fmt: str,
    width: int = 1200,
    height: int = 480,
) -> str:
    assert all(len(v) == len(names) for v in series.values())

    margin_left = 90
    margin_right = 30
    margin_top = 50
    margin_bottom = 160

    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom

    all_vals = [v for vals in series.values() for v in vals]
    vmax = max(all_vals) if all_vals else 1.0
    vmax = vmax * 1.05 if vmax > 0 else 1.0
    ticks = _ticks(vmax, n=5)

    n = max(1, len(names))

    def x_for(i: int) -> int:
        if n == 1:
            return margin_left + plot_w // 2
        return margin_left + int((plot_w * i) / (n - 1))

    def y_for(v: float) -> int:
        v = max(0.0, v)
        return margin_top + int(plot_h * (1.0 - (v / vmax)))

    colors = ["#4C78A8", "#F58518", "#54A24B", "#E45756"]

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">')
    parts.append('<rect width="100%" height="100%" fill="white"/>')
    parts.append(f'<text x="{width//2}" y="30" text-anchor="middle" font-size="18" font-family="DejaVu Sans">{_esc(title)}</text>')

    # Axes
    x0 = margin_left
    y0 = margin_top + plot_h
    x1 = margin_left + plot_w
    y1 = margin_top
    parts.append(f'<line x1="{x0}" y1="{y0}" x2="{x1}" y2="{y0}" stroke="#222" stroke-width="1"/>')
    parts.append(f'<line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y1}" stroke="#222" stroke-width="1"/>')

    # Y ticks + grid
    for t in ticks:
        y = y_for(t)
        parts.append(f'<line x1="{x0}" y1="{y}" x2="{x1}" y2="{y}" stroke="#ddd" stroke-width="1"/>')
        parts.append(
            f'<text x="{x0-10}" y="{y+4}" text-anchor="end" font-size="12" font-family="DejaVu Sans">{value_fmt.format(t)}</text>'
        )

    # Y label (rotated)
    parts.append(
        f'<text x="20" y="{margin_top + plot_h//2}" transform="rotate(-90 20 {margin_top + plot_h//2})" '
        f'text-anchor="middle" font-size="14" font-family="DejaVu Sans">{_esc(y_label)}</text>'
    )

    # X labels
    for i, name in enumerate(names):
        lx = x_for(i)
        ly = y0 + 10
        parts.append(
            f'<text x="{lx}" y="{ly}" transform="rotate(35 {lx} {ly})" '
            f'text-anchor="start" font-size="12" font-family="DejaVu Sans">{_esc(name)}</text>'
        )

    # Series lines
    legend_x = x1 - 140
    legend_y = margin_top + 10
    legend_i = 0

    for (label, vals), color in zip(series.items(), colors):
        points = [(x_for(i), y_for(v)) for i, v in enumerate(vals)]
        d = " ".join(f"{x},{y}" for x, y in points)
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{d}"/>')
        for x, y in points:
            parts.append(f'<circle cx="{x}" cy="{y}" r="3" fill="{color}"/>')

        # Legend
        ly = legend_y + legend_i * 18
        parts.append(f'<rect x="{legend_x}" y="{ly-10}" width="12" height="12" fill="{color}"/>')
        parts.append(
            f'<text x="{legend_x+18}" y="{ly}" font-size="12" font-family="DejaVu Sans">{_esc(label)}</text>'
        )
        legend_i += 1

    parts.append("</svg>")
    return "\n".join(parts)


def _write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _svg_to_png(svg_path: str, png_path: str) -> None:
    os.makedirs(os.path.dirname(png_path), exist_ok=True)

    rsvg = shutil.which("rsvg-convert")
    if rsvg:
        subprocess.check_call([rsvg, "-o", png_path, svg_path])
        return

    convert = shutil.which("convert")
    if convert:
        subprocess.check_call([convert, svg_path, png_path])
        return

    raise RuntimeError("No SVG->PNG converter found (need rsvg-convert or ImageMagick convert)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input benchmark JSON file")
    ap.add_argument("--out-dir", required=True, help="Output directory for plots")
    args = ap.parse_args()

    with open(args.inp, "r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    cases = sorted(data["cases"], key=lambda c: c["name"])
    names = [c["name"] for c in cases]

    throughput_p50 = [c["throughput_mb_s"]["p50"] for c in cases]
    latency_us_p50 = [c["time_per_call_s"]["p50"] * 1e6 for c in cases]
    latency_us_p95 = [c["time_per_call_s"]["p95"] * 1e6 for c in cases]

    out_throughput_svg = os.path.join(args.out_dir, "bench_throughput.svg")
    out_latency_svg = os.path.join(args.out_dir, "bench_latency_us.svg")
    out_throughput_png = os.path.join(args.out_dir, "bench_throughput.png")
    out_latency_png = os.path.join(args.out_dir, "bench_latency_us.png")

    _write_text(
        out_throughput_svg,
        _svg_bar_chart(
            title="Sanitization throughput by benchmark case (p50)",
            names=names,
            values=throughput_p50,
            y_label="Throughput (MiB/s) — higher is better",
            value_fmt="{:.1f}",
        ),
    )
    _write_text(
        out_latency_svg,
        _svg_line_chart(
            title="Sanitization latency by benchmark case",
            names=names,
            series={"p50": latency_us_p50, "p95": latency_us_p95},
            y_label="Latency (µs per sanitize call) — lower is better",
            value_fmt="{:.1f}",
        ),
    )

    _svg_to_png(out_throughput_svg, out_throughput_png)
    _svg_to_png(out_latency_svg, out_latency_png)

    print("Wrote plots:")
    print(" -", out_throughput_png)
    print(" -", out_throughput_svg)
    print(" -", out_latency_png)
    print(" -", out_latency_svg)


if __name__ == "__main__":
    main()
