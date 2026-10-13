#!/usr/bin/env python3
import argparse
import json
import time
import uuid
from collections import Counter

import requests
import websocket

BASE = "https://sidekick.shopify.ai"
ORIGIN = "https://www.shopify.com"
REFERER = "https://www.shopify.com/"


def create_anonymous_user(session: requests.Session) -> str:
    r = session.post(
        f"{BASE}/api/anonymous_user",
        headers={
            "Origin": ORIGIN,
            "Referer": REFERER,
            "Content-Type": "application/json",
            "Accept": "*/*",
        },
        data=b"",
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    identifier = data.get("identifier")
    if not identifier:
        raise RuntimeError(f"identifier 없음: {data}")
    return identifier


def get_ws_url(session: requests.Session, anonymous_id: str) -> str:
    r = session.get(
        f"{BASE}/api/events/init",
        headers={
            "Origin": ORIGIN,
            "Referer": REFERER,
            "X-Anonymous-User-ID": anonymous_id,
            "Accept": "*/*",
        },
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    ws_url = data.get("url")
    if not ws_url:
        raise RuntimeError(f"WebSocket URL 없음: {data}")
    return ws_url


def parse_actioncable_frame(raw: str):
    try:
        outer = json.loads(raw)
    except json.JSONDecodeError:
        return {"type": "non_json", "event": None, "tool_name": None, "outer": None, "inner": None}

    event = None
    tool_name = None
    inner = None

    msg = outer.get("message")
    if isinstance(msg, dict):
        event = msg.get("event")
        data = msg.get("data")

        if isinstance(data, str):
            try:
                inner = json.loads(data)
            except json.JSONDecodeError:
                inner = None
        elif isinstance(data, dict):
            inner = data

        if event in {"tool_call_start", "tool_result", "loader_message"}:
            candidate = inner if isinstance(inner, dict) else {}
            if event == "loader_message":
                candidate = candidate.get("data", {}) if isinstance(candidate, dict) else {}
            tool_name = candidate.get("name")
            if not tool_name and event == "tool_result":
                preview = candidate.get("preview", {}) if isinstance(candidate, dict) else {}
                if isinstance(preview, dict):
                    tool_name = preview.get("type")

    return {
        "type": outer.get("type"),
        "event": event,
        "tool_name": tool_name,
        "outer": outer,
        "inner": inner,
    }


def run_chat(scenario: str, question: str, receive_seconds: float = 15.0):
    http = requests.Session()

    t0 = time.perf_counter()
    anonymous_id = create_anonymous_user(http)
    t_anon = time.perf_counter()

    ws_url = get_ws_url(http, anonymous_id)
    t_init = time.perf_counter()

    ws = websocket.create_connection(
        ws_url,
        origin=ORIGIN,
        timeout=1.0,
    )
    t_ws = time.perf_counter()

    identifier_obj = {
        "channel": "ConversationsChannel",
        "scenario": scenario,
        "features": ["brochure/default"],
    }
    identifier = json.dumps(identifier_obj, separators=(",", ":"))

    subscribe = {
        "command": "subscribe",
        "identifier": identifier,
    }
    ws.send(json.dumps(subscribe, separators=(",", ":")))

    stats = {
        "scenario": scenario,
        "anonymous_id": anonymous_id,
        "frames": 0,
        "total_bytes": 0,
        "max_frame_bytes": 0,
        "first_frame_ms": None,
        "confirm_subscription": 0,
        "pings": 0,
        "events": Counter(),
        "tools": Counter(),
        "conversation_ids": [],
        "errors": [],
        "sample_large_frames": [],
    }

    confirm_deadline = time.perf_counter() + 8
    confirmed = False
    while time.perf_counter() < confirm_deadline:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            continue

        if raw is None:
            continue

        now = time.perf_counter()
        size = len(raw.encode("utf-8", errors="replace"))
        stats["frames"] += 1
        stats["total_bytes"] += size
        stats["max_frame_bytes"] = max(stats["max_frame_bytes"], size)
        if stats["first_frame_ms"] is None:
            stats["first_frame_ms"] = round((now - t_ws) * 1000, 1)

        parsed = parse_actioncable_frame(raw)

        if parsed["type"] == "ping":
            stats["pings"] += 1
        if parsed["type"] == "confirm_subscription":
            stats["confirm_subscription"] += 1
            confirmed = True
            break

        if parsed["event"]:
            stats["events"][parsed["event"]] += 1

        outer = parsed["outer"] or {}
        msg = outer.get("message")
        if isinstance(msg, dict) and msg.get("event") == "conversation_id":
            data = msg.get("data")
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    pass
            if isinstance(data, dict) and data.get("conversation_id"):
                stats["conversation_ids"].append(data["conversation_id"])

    if not confirmed:
        stats["errors"].append("confirm_subscription을 확인하지 못함")

    message_payload = {
        "type": "message",
        "content": question,
        "idempotency_key": str(uuid.uuid4()),
        "scenario": scenario,
        "context": {
            "brochure": {
                "product_interest": "Plus",
                "locale": "en",
                "country_code": "US",
            }
        },
        "action": "message",
    }

    message_frame = {
        "command": "message",
        "identifier": identifier,
        "data": json.dumps(message_payload, separators=(",", ":")),
    }

    send_time = time.perf_counter()
    ws.send(json.dumps(message_frame, separators=(",", ":")))

    end_time = send_time + receive_seconds
    first_after_send = None

    while time.perf_counter() < end_time:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            continue
        except Exception as e:
            stats["errors"].append(f"recv 오류: {e}")
            break

        if raw is None:
            continue

        now = time.perf_counter()
        if first_after_send is None:
            first_after_send = now

        size = len(raw.encode("utf-8", errors="replace"))
        stats["frames"] += 1
        stats["total_bytes"] += size
        stats["max_frame_bytes"] = max(stats["max_frame_bytes"], size)

        parsed = parse_actioncable_frame(raw)

        if parsed["type"] == "ping":
            stats["pings"] += 1
        if parsed["type"] == "confirm_subscription":
            stats["confirm_subscription"] += 1

        event = parsed["event"]
        if event:
            stats["events"][event] += 1

        tool_name = parsed["tool_name"]
        if tool_name:
            stats["tools"][tool_name] += 1

        outer = parsed["outer"] or {}
        msg = outer.get("message")
        if isinstance(msg, dict) and msg.get("event") == "conversation_id":
            data = msg.get("data")
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    pass
            if isinstance(data, dict) and data.get("conversation_id"):
                stats["conversation_ids"].append(data["conversation_id"])

        if size >= 10000 and len(stats["sample_large_frames"]) < 5:
            stats["sample_large_frames"].append({
                "bytes": size,
                "event": event,
                "tool_name": tool_name,
            })

    try:
        ws.close()
    except Exception:
        pass

    stats["anonymous_user_ms"] = round((t_anon - t0) * 1000, 1)
    stats["events_init_ms"] = round((t_init - t_anon) * 1000, 1)
    stats["ws_connect_ms"] = round((t_ws - t_init) * 1000, 1)
    stats["first_response_after_message_ms"] = (
        round((first_after_send - send_time) * 1000, 1)
        if first_after_send
        else None
    )
    stats["receive_window_seconds"] = receive_seconds
    stats["events"] = dict(stats["events"])
    stats["tools"] = dict(stats["tools"])
    return stats


def print_summary(stats):
    print(f"\n=== scenario={stats['scenario']} ===")
    print(f"frames                  : {stats['frames']}")
    print(f"total_bytes             : {stats['total_bytes']}")
    print(f"max_frame_bytes         : {stats['max_frame_bytes']}")
    print(f"first_response_ms       : {stats['first_response_after_message_ms']}")
    print(f"confirm_subscription    : {stats['confirm_subscription']}")
    print(f"pings                   : {stats['pings']}")
    print(f"events                   : {stats['events']}")
    print(f"tools                    : {stats['tools']}")
    print(f"conversation_ids         : {stats['conversation_ids']}")
    print(f"large_frames             : {stats['sample_large_frames']}")
    print(f"errors                   : {stats['errors']}")


def main():
    parser = argparse.ArgumentParser(
        description="Shopify Sidekick ActionCable 응답량/이벤트 저강도 비교 도구"
    )
    parser.add_argument(
        "--question",
        default="What can you help me with?",
        help="각 scenario에 동일하게 보낼 질문",
    )
    parser.add_argument(
        "--receive-seconds",
        type=float,
        default=15.0,
        help="메시지 전송 후 수신 집계 시간 (기본 15초)",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        help="테스트할 scenario. 여러 번 지정 가능. 기본: brochure, test",
    )
    parser.add_argument(
        "--output",
        default="sidekick_ws_stats.json",
        help="결과 JSON 파일명",
    )
    args = parser.parse_args()

    scenarios = args.scenarios or ["brochure", "test"]
    results = []

    for scenario in scenarios:
        print(f"[*] scenario={scenario} 시작")
        result = run_chat(
            scenario=scenario,
            question=args.question,
            receive_seconds=args.receive_seconds,
        )
        results.append(result)
        print_summary(result)
        time.sleep(2)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\n[+] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
