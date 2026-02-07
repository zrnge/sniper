#!/usr/bin/env python3
# ============================================================
#  SNIPER - Simple Network Input Payload ExploRer
#  Owner  : https://github.com/zrnge
#  License: Use only where explicitly authorized
# ============================================================

import argparse
import itertools
import requests
import sys
import time
from typing import Dict, List, Optional, Set


BANNER = r"""
 ███████╗███╗   ██╗██╗██████╗ ███████╗██████╗
 ██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
 ███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝
 ╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗
 ███████║██║ ╚████║██║██║     ███████╗██║  ██║
 ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

 Simple Network Input Payload ExploRer
 Owner: github.com/zrnge
"""


def load_payloads(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except Exception as e:
        print(f"[!] Failed to read payload file {path}: {e}")
        sys.exit(1)


def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" not in h:
            print(f"[!] Invalid header format: {h}")
            sys.exit(1)
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def parse_status_filter(value: Optional[str]) -> Optional[Set[int]]:
    if not value:
        return None
    try:
        return {int(x) for x in value.split(",")}
    except ValueError:
        print("[!] Invalid --status format")
        sys.exit(1)


def match_filters(
    status: int,
    length: int,
    status_filter: Optional[Set[int]],
    len_eq: Optional[int],
    len_min: Optional[int],
    len_max: Optional[int],
    invert: bool,
) -> bool:
    match = True

    if status_filter:
        match &= status in status_filter
    if len_eq is not None:
        match &= length == len_eq
    if len_min is not None:
        match &= length >= len_min
    if len_max is not None:
        match &= length <= len_max

    return not match if invert else match


def build_payload_matrix(
    param_payloads: Dict[str, List[str]],
    mode: str,
):
    keys = list(param_payloads.keys())
    values = list(param_payloads.values())

    if mode == "pitchfork":
        for combo in zip(*values):
            yield dict(zip(keys, combo))
    else:  # clusterbomb
        for combo in itertools.product(*values):
            yield dict(zip(keys, combo))


def fuzz(
    url: str,
    method: str,
    payload_matrix,
    delay: float,
    timeout: int,
    headers: dict,
    status_filter: Optional[Set[int]],
    len_eq: Optional[int],
    len_min: Optional[int],
    len_max: Optional[int],
    invert: bool,
):
    session = requests.Session()
    session.headers.update(headers)

    for params in payload_matrix:
        try:
            if method == "GET":
                r = session.get(
                    url,
                    params=params,
                    timeout=timeout,
                    allow_redirects=False,
                )
            else:
                r = session.post(
                    url,
                    data=params,
                    timeout=timeout,
                    allow_redirects=False,
                )

            status = r.status_code
            length = len(r.text)

            if match_filters(
                status,
                length,
                status_filter,
                len_eq,
                len_min,
                len_max,
                invert,
            ):
                print(
                    f"PARAMS={params} "
                    f"STATUS={status} "
                    f"LENGTH={length}"
                )

            time.sleep(delay)

        except requests.RequestException as e:
            if invert:
                print(f"PARAMS={params} ERROR={e}")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="SNIPER – Multi-parameter HTTP fuzzer"
    )

    parser.add_argument("-u", "--url", required=True)
    parser.add_argument(
        "-X", "--method", choices=["GET", "POST"], default="POST"
    )

    parser.add_argument(
        "--param",
        action="append",
        required=True,
        help="Parameter mapping: name=payload_file (repeatable)",
    )

    parser.add_argument(
        "--mode",
        choices=["pitchfork", "clusterbomb"],
        default="clusterbomb",
    )

    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--timeout", type=int, default=5)

    parser.add_argument("-H", "--header", action="append", default=[])

    # Grep-style filters
    parser.add_argument("--status")
    parser.add_argument("--len-eq", type=int)
    parser.add_argument("--len-min", type=int)
    parser.add_argument("--len-max", type=int)
    parser.add_argument("-v", "--invert", action="store_true")

    args = parser.parse_args()

    param_payloads = {}
    for p in args.param:
        if "=" not in p:
            print("[!] Invalid --param format (use name=file.txt)")
            sys.exit(1)
        name, file = p.split("=", 1)
        param_payloads[name] = load_payloads(file)

    headers = parse_headers(args.header)
    status_filter = parse_status_filter(args.status)

    payload_matrix = build_payload_matrix(
        param_payloads, args.mode
    )

    fuzz(
        url=args.url,
        method=args.method,
        payload_matrix=payload_matrix,
        delay=args.delay,
        timeout=args.timeout,
        headers=headers,
        status_filter=status_filter,
        len_eq=args.len_eq,
        len_min=args.len_min,
        len_max=args.len_max,
        invert=args.invert,
    )


if __name__ == "__main__":
    main()
