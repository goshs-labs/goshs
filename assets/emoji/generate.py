#!/usr/bin/env python3
"""Generate the chat emoji catalog from Mattermost's emoji.json.

Source (Mattermost server checkout):
    webapp/channels/src/utils/emoji.json

Usage:
    python3 assets/emoji/generate.py /path/to/mattermost/webapp/channels/src/utils/emoji.json

Writes httpserver/static/js/emoji.json (a static asset the chat UI fetches):

    {
      "map":   { "<short_name>": "<unicode char>", ... },   # every alias
      "order": [ "<primary short_name>", ... ]              # base emoji, file order
    }

`map` backs :shortcode: rendering, the composer autosuggest, and reaction search
(all aliases). `order` is the display order for the reaction picker grid; the
character for each name is looked up in `map`. Skin-tone variations are not
emitted — reactions use the base emoji.
"""
import json
import os
import sys


# Fitzpatrick skin-tone modifier codepoints. Any emoji whose unified sequence
# contains one is a skin-toned variant (or the tone swatch itself); we drop these
# and keep only the neutral/default base emoji.
SKIN_TONE_MODIFIERS = {"1F3FB", "1F3FC", "1F3FD", "1F3FE", "1F3FF"}


def has_skin_tone(unified: str) -> bool:
    return any(part.upper() in SKIN_TONE_MODIFIERS for part in unified.split("-"))


def char_from_unified(unified: str) -> str:
    return "".join(chr(int(part, 16)) for part in unified.split("-"))


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: generate.py <path to mattermost emoji.json>")
    src = sys.argv[1]
    with open(src, encoding="utf-8") as fh:
        emojis = json.load(fh)

    emoji_map: dict[str, str] = {}
    order: list[str] = []
    for e in emojis:
        unified = e.get("unified") or ""
        # Skip Mattermost-custom image emoji (no unicode codepoint), e.g. ":mattermost:".
        if not unified or any(part == "" for part in unified.split("-")):
            continue
        # Skip skin-toned variants and the tone swatches; keep the neutral base.
        if has_skin_tone(unified):
            continue
        char = char_from_unified(unified)
        primary = e["short_name"]
        order.append(primary)
        for name in e.get("short_names") or [primary]:
            emoji_map[name] = char

    out_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "httpserver", "static", "js",
    )
    out_path = os.path.normpath(os.path.join(out_dir, "emoji.json"))
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"map": emoji_map, "order": order}, fh, ensure_ascii=False, separators=(",", ":"))
        fh.write("\n")

    print(f"wrote {out_path}: {len(order)} emoji, {len(emoji_map)} shortcodes")


if __name__ == "__main__":
    main()
