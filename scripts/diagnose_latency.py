"""One small live call per reasoning setting with a planner-shaped prompt; prints measured numbers.
Usage: python scripts/diagnose_latency.py [setting ...]   (setting: default | low | medium ...)
The key comes from .env and is never printed."""

import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.agent_runtime.model_planner import SYSTEM_PROMPT_V1, ModelAction  # noqa: E402
from sentinelx.model_clients import load_config  # noqa: E402

USER = ("TASK FROM THE USER: Summarize today's agenda.\nUSER NOTE: Start at "
        "http://calendar.lab.test:8000/today\n\nYOUR PREVIOUS STEPS:\n(none yet)\n\n"
        "<<<UNTRUSTED DATA source=current_url>>>\nabout:blank\n<<<END UNTRUSTED DATA>>>\n\n"
        "Reply with the next step as one JSON object.")


def main() -> None:
    cfg = load_config()
    key = cfg.api_key.get_secret_value()
    for setting in (sys.argv[1:] or ["default", "low"]):
        body = {"model": cfg.model, "temperature": 1.0, "top_p": 0.95, "max_tokens": cfg.max_tokens,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT_V1},
                             {"role": "user", "content": USER}]}
        if setting != "default":
            body["reasoning_effort"] = setting
        t = time.perf_counter()
        r = httpx.post(cfg.base_url + "/chat/completions", json=body, timeout=120,
                       headers={"Authorization": f"Bearer {key}"})
        ms = (time.perf_counter() - t) * 1000
        out = {"setting": setting, "http": r.status_code, "latency_ms": round(ms)}
        if r.status_code == 200:
            j = r.json()
            msg = j["choices"][0]["message"]
            usage = j.get("usage", {})
            out.update(tokens_in=usage.get("prompt_tokens"),
                       tokens_out=usage.get("completion_tokens"),
                       reasoning_tokens=(usage.get("completion_tokens_details") or {}).get(
                           "reasoning_tokens", "not reported"),
                       reasoning_chars=len(msg.get("reasoning_content") or ""),
                       finish=j["choices"][0].get("finish_reason"))
            try:
                text = (msg.get("content") or "").strip()
                ModelAction.model_validate_json(text)
                out["valid_action_json"] = True
            except Exception as e:  # noqa: BLE001
                out["valid_action_json"] = False
                out["why"] = str(e)[:120]
        else:
            out["body"] = r.text[:200].replace(key, "***")
        print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
