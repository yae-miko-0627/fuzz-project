#!/usr/bin/env python3
"""
csv_to_xy_plot.py

小工具：把 CSV 导出为 x-y 图（支持 line / scatter）。

用法示例:
  python csv_to_xy_plot.py data.csv --x time --y value -o out.png --kind line

支持：列名或列索引（从0开始）、自定义分隔符、输出文件格式、坐标轴标题、对数坐标等。
"""
from __future__ import annotations
import argparse
import csv
import sys
from typing import List, Tuple, Optional

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

try:
    import pandas as pd
    _HAS_PANDAS = True
except Exception:
    _HAS_PANDAS = False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='CSV -> X/Y plot tool')
    p.add_argument('csvfile', help='输入 CSV 文件路径')
    p.add_argument('--x', required=True, help='X 列名或列索引（从0开始）')
    p.add_argument('--y', required=True, help='Y 列名或列索引（从0开始）, 多列用逗号分隔')
    p.add_argument('-d', '--delimiter', default=',', help='CSV 分隔符，默认 ","')
    p.add_argument('-o', '--output', default='out.png', help='输出文件，例如 out.png 或 out.pdf')
    p.add_argument('--kind', choices=['line','scatter'], default='line', help='图类型')
    p.add_argument('--title', default='', help='图标题')
    p.add_argument('--xlabel', default='', help='X 轴标题')
    p.add_argument('--ylabel', default='', help='Y 轴标题')
    p.add_argument('--dpi', type=int, default=150, help='输出分辨率 DPI')
    p.add_argument('--marker', default='o', help='点标记，line 图也可用')
    p.add_argument('--style', default=None, help='matplotlib style (例如 ggplot)')
    p.add_argument('--xlog', action='store_true', help='X 轴对数刻度')
    p.add_argument('--ylog', action='store_true', help='Y 轴对数刻度')
    p.add_argument('--x-unit', choices=['sec', 'min', 'hour'], default='sec', help='X 轴单位转换：sec/min/hour（默认 sec）')
    return p.parse_args()


def _select_series_from_df(df, key):
    # key: name or integer index string
    if isinstance(key, str) and key.isdigit():
        idx = int(key)
        return df.iloc[:, idx]
    try:
        return df[key]
    except Exception:
        # fallback by index
        try:
            idx = int(key)
            return df.iloc[:, idx]
        except Exception:
            raise KeyError(f'无法在 DataFrame 中找到列/索引: {key}')


def read_csv_with_pandas(path: str, delimiter: str):
    df = pd.read_csv(path, sep=delimiter)
    return df


def read_csv_basic(path: str, delimiter: str, header: bool=True) -> Tuple[List[str], List[List[str]]]:
    with open(path, newline='') as f:
        reader = csv.reader(f, delimiter=delimiter)
        rows = list(reader)
    if not rows:
        return [], []
    if header:
        return rows[0], rows[1:]
    else:
        # generate numeric headers
        n = len(rows[0])
        hdr = [str(i) for i in range(n)]
        return hdr, rows


def to_floats(seq):
    out = []
    for v in seq:
        try:
            out.append(float(v))
        except Exception:
            out.append(float('nan'))
    return out


def plot_xy(x, ys: List[Tuple[str, List[float]]], args: argparse.Namespace):
    if args.style:
        try:
            plt.style.use(args.style)
        except Exception:
            pass
    fig, ax = plt.subplots()
    for label, yvals in ys:
        if args.kind == 'scatter':
            ax.scatter(x, yvals, label=label)
        else:
            ax.plot(x, yvals, marker=args.marker, label=label)
    if args.title:
        ax.set_title(args.title)
    if args.xlabel:
        ax.set_xlabel(args.xlabel)
    if args.ylabel:
        ax.set_ylabel(args.ylabel)
    if args.xlog:
        ax.set_xscale('log')
    if args.ylog:
        ax.set_yscale('log')
    ax.grid(True)
    if len(ys) > 1:
        ax.legend()
    fig.tight_layout()
    fig.savefig(args.output, dpi=args.dpi)


def main():
    args = parse_args()
    # parse y into list
    y_keys = [k.strip() for k in args.y.split(',') if k.strip()]

    if _HAS_PANDAS:
        df = read_csv_with_pandas(args.csvfile, args.delimiter)
        x_series = _select_series_from_df(df, args.x)
        x_vals = to_floats(x_series.tolist())
        ys = []
        for yk in y_keys:
            y_series = _select_series_from_df(df, yk)
            ys.append((yk, to_floats(y_series.tolist())))
    else:
        # fallback: use csv reader, assume header exists
        hdr, rows = read_csv_basic(args.csvfile, args.delimiter, header=True)
        if not hdr:
            print('CSV 内容为空或无法读取', file=sys.stderr)
            sys.exit(2)
        # build columns
        cols = list(zip(*rows)) if rows else [[] for _ in hdr]
        # map header names to indices
        hdr_map = {name: i for i, name in enumerate(hdr)}
        def get_col(key):
            if key.isdigit():
                return cols[int(key)]
            if key in hdr_map:
                return cols[hdr_map[key]]
            raise KeyError(f'找不到列: {key}')
        x_vals = to_floats(get_col(args.x))
        ys = []
        for yk in y_keys:
            ys.append((yk, to_floats(get_col(yk))))

    # 单位转换：支持秒/分钟/小时
    if args.x_unit == 'min':
        x_vals = [v / 60.0 for v in x_vals]
    elif args.x_unit == 'hour':
        x_vals = [v / 3600.0 for v in x_vals]

    # 若用户未自定义 xlabel，自动补充单位
    if not args.xlabel:
        if args.x_unit == 'min':
            args.xlabel = 'Time (min)'
        elif args.x_unit == 'hour':
            args.xlabel = 'Time (hour)'
        else:
            args.xlabel = 'Time (s)'

    plot_xy(x_vals, ys, args)


if __name__ == '__main__':
    main()
