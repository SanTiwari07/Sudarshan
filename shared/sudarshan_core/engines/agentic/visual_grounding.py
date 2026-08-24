"""
Visual and structural UI grounding fallback for unknown APKs.

When UIAutomator/XML misses visible actionable controls, this module attempts
to recover them from:
  1. Structural XML analysis (non-clickable nodes that look like controls)
  2. Optional Gemini vision grounding (disabled unless explicitly enabled)

No fixed coordinates, no package-specific templates.
"""

from __future__ import annotations

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

from sudarshan_core.engines.agentic.semantic_action import (
    SemanticRole,
    classify_semantic_role,
)

logger = logging.getLogger(__name__)

# Opt-in vision grounding for action discovery (separate from captioning).
VISION_GROUNDING_ENABLED: bool = os.getenv(
    "SUDARSHAN_VISION_GROUNDING", ""
).lower() in ("1", "true", "yes")

_BUTTONLIKE_CLASS_RE = re.compile(
    r"(button|imagebutton|materialbutton|chip|cardview|textview|compose)",
    re.I,
)
_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


@dataclass
class GroundedElement:
    node_id: str
    label: str
    class_name: str
    center_x: int
    center_y: int
    bounds: str
    semantic_role: SemanticRole
    confidence: float
    detection_source: str
    is_clickable: bool = True
    is_input: bool = False
    is_checkable: bool = False
    is_scrollable: bool = False
    resource_id: str = ""


def _bounds_center(bounds: str) -> Tuple[int, int, int]:
    m = _BOUNDS_RE.match(bounds or "")
    if not m:
        return 0, 0, 0
    x1, y1, x2, y2 = map(int, m.groups())
    area = max(0, (x2 - x1) * (y2 - y1))
    return (x1 + x2) // 2, (y1 + y2) // 2, area


def _looks_actionable_label(text: str, desc: str) -> bool:
    combined = f"{text} {desc}".strip()
    if len(combined) < 2:
        return False
    if len(combined) > 80:
        return False
    # Skip pure informational paragraphs
    if combined.count(" ") > 12 and not any(
        c.isupper() for c in combined[:20]
    ):
        return False
    return True


def recover_from_xml_structure(
    xml_content: str,
    existing_node_ids: Sequence[str],
    *,
    context_text: str = "",
    screen_width: int = 1080,
    screen_height: int = 1920,
) -> List[GroundedElement]:
    """
    Recover actionable elements UIAutomator parser skipped.

    Targets:
      - clickable=false but button-like class with short label
      - nodes inside dialog containers with CTA-like text
      - sibling clusters that look like Allow/Deny pairs
    """
    if not xml_content:
        return []

    recovered: List[GroundedElement] = []
    seen_labels: set[str] = set()
    existing = set(existing_node_ids)

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return []

    all_text: List[str] = []
    elems: List[ET.Element] = []
    for elem in root.iter():
        elems.append(elem)
        t = (elem.attrib.get("text") or "").strip()
        d = (elem.attrib.get("content-desc") or "").strip()
        if t or d:
            all_text.append(t or d)
    dialog_context = context_text or " ".join(all_text[:30])

    idx = 0
    for elem in elems:
        bounds = elem.attrib.get("bounds", "")
        if not bounds or not _BOUNDS_RE.match(bounds):
            continue

        text = (elem.attrib.get("text") or "").strip()
        desc = (elem.attrib.get("content-desc") or "").strip()
        label = text or desc
        if not _looks_actionable_label(text, desc):
            continue

        clickable = elem.attrib.get("clickable") == "true"
        checkable = elem.attrib.get("checkable") == "true"
        scrollable = elem.attrib.get("scrollable") == "true"
        enabled = elem.attrib.get("enabled", "true") != "false"
        if not enabled:
            continue

        cls_full = elem.attrib.get("class", "")
        cls_name = cls_full.split(".")[-1]
        res_id = elem.attrib.get("resource-id", "")
        res_short = res_id.split("/")[-1] if "/" in res_id else res_id

        is_input = "EditText" in cls_full or "edit" in cls_full.lower()
        node_id = f"vg{idx}"
        idx += 1
        if node_id in existing:
            continue

        looks_button = (
            clickable
            or checkable
            or scrollable
            or _BUTTONLIKE_CLASS_RE.search(cls_name)
            or _BUTTONLIKE_CLASS_RE.search(res_short)
        )
        if not looks_button and not is_input:
            # Heuristic: short labeled region in lower 60% of screen
            cx, cy, area = _bounds_center(bounds)
            if area < 1200 or cy < int(screen_height * 0.35):
                continue
            if len(label) > 40:
                continue
            looks_button = True

        if not looks_button:
            continue

        sig = label.lower()
        if sig in seen_labels:
            continue
        seen_labels.add(sig)

        cx, cy, area = _bounds_center(bounds)
        if not validate_grounded_coordinates(cx, cy, screen_width, screen_height, bounds):
            continue

        classification = classify_semantic_role(
            label=label,
            class_name=cls_name,
            context_text=dialog_context,
            is_checkable=checkable,
            is_clickable=clickable or looks_button,
            is_input=is_input,
            is_scrollable=scrollable,
            bounds_area=area,
        )

        recovered.append(GroundedElement(
            node_id=node_id,
            label=label,
            class_name=cls_name,
            center_x=cx,
            center_y=cy,
            bounds=bounds,
            semantic_role=classification.role,
            confidence=min(0.92, classification.confidence * 0.95),
            detection_source="xml_structure_recovery",
            is_clickable=clickable or looks_button,
            is_input=is_input,
            is_checkable=checkable,
            is_scrollable=scrollable,
            resource_id=res_short,
        ))

    return recovered


def validate_grounded_coordinates(
    x: int,
    y: int,
    screen_width: int,
    screen_height: int,
    bounds: str = "",
) -> bool:
    if x <= 0 or y <= 0:
        return False
    if x > screen_width or y > screen_height:
        return False
    if bounds:
        m = _BOUNDS_RE.match(bounds)
        if m:
            x1, y1, x2, y2 = map(int, m.groups())
            if not (x1 <= x <= x2 and y1 <= y <= y2):
                return False
    return True


def grounded_to_ui_nodes(elements: Sequence[GroundedElement]) -> List[Any]:
    """Convert grounded elements to UINode-compatible objects."""
    from sudarshan_core.engines.agentic.perception import UINode

    nodes: List[UINode] = []
    for g in elements:
        nodes.append(UINode(
            node_id=g.node_id,
            class_name=g.class_name,
            text=g.label if not g.is_input else g.label,
            desc="",
            resource_id=g.resource_id,
            center_x=g.center_x,
            center_y=g.center_y,
            is_input=g.is_input,
            is_clickable=g.is_clickable,
            is_scrollable=g.is_scrollable,
            is_checkable=g.is_checkable,
            enabled=True,
            checked=None,
            bounds=g.bounds,
            semantic_role=g.semantic_role.value,
            detection_source=g.detection_source,
            confidence=g.confidence,
        ))
    return nodes


_VISION_PROMPT = """You are analyzing an Android app screenshot during automated \
security testing. List every visible actionable UI control the user could tap.

Return ONLY valid JSON array. Each item:
{"label": "visible text or brief description", "x": center_x, "y": center_y, \
"role": "ACCEPT|DECLINE|PROGRESS|INPUT|UNKNOWN", "confidence": 0.0-1.0}

Rules:
- Use pixel coordinates relative to the screenshot image.
- Do NOT invent controls you cannot see.
- If nothing actionable, return [].
- No markdown, no explanation."""


def ground_from_vision(
    screenshot_path: str,
    *,
    screen_width: int,
    screen_height: int,
    hint_context: str = "",
) -> List[GroundedElement]:
    """
    Optional Gemini vision grounding. Disabled unless SUDARSHAN_VISION_GROUNDING=1.
    """
    if not VISION_GROUNDING_ENABLED:
        return []

    try:
        from sudarshan_core.ai.gemini_provider import gemini_is_configured, get_gemini_manager
        if not gemini_is_configured():
            return []

        from pathlib import Path
        path = Path(screenshot_path)
        if not path.is_file():
            return []

        img_bytes = path.read_bytes()
        try:
            from google.genai import types
            img_part = types.Part.from_bytes(data=img_bytes, mime_type="image/png")
        except Exception:
            img_part = {"inline_data": {"mime_type": "image/png", "data": img_bytes}}

        prompt = _VISION_PROMPT
        if hint_context:
            prompt += f"\nContext hint (may be wrong): {hint_context[:300]}"

        result = get_gemini_manager().generate_content(contents=[prompt, img_part])
        raw = (result.text or "").strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json)?\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw)

        items = json.loads(raw)
        if not isinstance(items, list):
            return []

        grounded: List[GroundedElement] = []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            label = str(item.get("label", "")).strip()
            x = int(item.get("x", 0))
            y = int(item.get("y", 0))
            if not label or not validate_grounded_coordinates(x, y, screen_width, screen_height):
                continue
            role_str = str(item.get("role", "UNKNOWN")).upper()
            try:
                role = SemanticRole(role_str)
            except ValueError:
                role = SemanticRole.UNKNOWN
            conf = float(item.get("confidence", 0.7))
            grounded.append(GroundedElement(
                node_id=f"vis{i}",
                label=label,
                class_name="VisionGrounded",
                center_x=x,
                center_y=y,
                bounds=f"[{max(0,x-40)},{max(0,y-20)}][{min(screen_width,x+40)},{min(screen_height,y+20)}]",
                semantic_role=role,
                confidence=min(0.93, conf),
                detection_source="visual_grounding",
            ))
        return grounded

    except Exception as exc:
        logger.warning(
            "[VisualGrounding] Vision grounding failed (%s: %s)",
            type(exc).__name__, exc,
        )
        return []


def _labeled_actionable_count(nodes: Sequence[Any]) -> int:
    n = 0
    for node in nodes:
        label = (getattr(node, "text", "") or getattr(node, "desc", "") or "").strip()
        if not label:
            continue
        if (
            getattr(node, "is_clickable", False)
            or getattr(node, "is_checkable", False)
            or getattr(node, "is_input", False)
        ):
            n += 1
    return n


def _merge_grounded(
    merged: List[Any],
    recovered: Sequence[GroundedElement],
) -> List[Any]:
    existing_labels = {
        (getattr(n, "text", "") or getattr(n, "desc", "")).strip().lower()
        for n in merged
        if (getattr(n, "text", "") or getattr(n, "desc", ""))
    }
    existing_bounds = {getattr(n, "bounds", "") for n in merged}
    added: List[Any] = []
    for g in recovered:
        sig = (g.label or "").strip().lower()
        if sig and sig in existing_labels:
            continue
        if g.bounds and g.bounds in existing_bounds and sig in existing_labels:
            continue
        added.extend(grounded_to_ui_nodes([g]))
        if sig:
            existing_labels.add(sig)
        if g.bounds:
            existing_bounds.add(g.bounds)
    merged.extend(added)
    return added


def augment_observation_nodes(
    xml_content: str,
    ui_nodes: List[Any],
    *,
    screenshot_path: str = "",
    screen_width: int = 1080,
    screen_height: int = 1920,
    context_text: str = "",
    min_nodes: int = 1,
) -> Tuple[List[Any], List[str]]:
    """
    Recover missing actionable controls even when some clickable nodes exist.

    UIAutomator often reports a clickable parent with no label while the
    visible CTA is a non-clickable child. Recovery must still run.
    """
    sources: List[str] = []
    existing_ids = [getattr(n, "node_id", "") for n in ui_nodes]
    merged = list(ui_nodes)

    recovered = recover_from_xml_structure(
        xml_content,
        existing_ids,
        context_text=context_text,
        screen_width=screen_width,
        screen_height=screen_height,
    )
    added = _merge_grounded(merged, recovered)
    if added:
        sources.append("xml_structure_recovery")

    need_vision = (
        bool(screenshot_path)
        and (
            len(merged) < min_nodes
            or _labeled_actionable_count(merged) < min_nodes
        )
    )
    if need_vision:
        from sudarshan_core.engines.agentic.action_dispatch import (
            png_image_size,
            screenshot_coords_to_device,
        )

        img_size = png_image_size(screenshot_path)
        vision = ground_from_vision(
            screenshot_path,
            screen_width=screen_width,
            screen_height=screen_height,
            hint_context=context_text,
        )
        if vision and img_size:
            iw, ih = img_size
            for g in vision:
                dx, dy = screenshot_coords_to_device(
                    g.center_x, g.center_y,
                    image_width=iw, image_height=ih,
                    device_width=screen_width, device_height=screen_height,
                )
                g.center_x, g.center_y = dx, dy
        added_v = _merge_grounded(merged, vision)
        if added_v:
            sources.append("visual_grounding")

    return merged, sources
