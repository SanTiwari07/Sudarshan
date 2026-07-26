import os
import re
import json
import time
import hashlib
import logging
import asyncio
from datetime import datetime
import xml.etree.ElementTree as ET
from google import genai
from google.genai import types
from typing import Optional, Dict, List, Any, Set, Tuple

import pytesseract
from PIL import Image
import io

from sudarshan_core.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

# Safe deterministic data for form filling
FORM_VALUES = {
    "username": "demo",
    "email": "demo@gmail.com",
    "password": "Password@123",
    "phone": "9876543210",
    "otp": "123456",
    "amount": "100",
    "account": "123456789",
    "name": "Test User",
    "address": "123 Test St",
    "search": "test"
}

class UIExplorer:
    def __init__(self, device_serial: str, adb_path: str = "adb", event_bus: Optional[RuntimeEventBus] = None, mode: str = "ai"):
        self.device_serial = device_serial
        self.adb_path = adb_path
        self.event_bus = event_bus
        self.mode = mode
        self._is_running = False
        self._cancel_task = False
        self.start_time = 0
        self.duration_seconds = 0
        
        # Telemetry & Reports
        self.attack_timeline: List[Dict[str, Any]] = []
        self.exploration_graph: List[Dict[str, Any]] = []
        self.coverage_metrics = {
            "screens": 0,
            "buttons_found": 0,
            "buttons_clicked": 0,
            "forms_found": 0,
            "forms_completed": 0,
            "permissions_granted": 0,
            "dialogs_dismissed": 0,
            "navigation_depth": 0,
            "coverage_percent": 0
        }
        
        # State tracking
        self.visited_hashes: Set[str] = set()
        self.clicked_nodes: Set[str] = set()
        self.screen_cache: Dict[str, Dict[str, Any]] = {}
        self.action_history: List[Tuple[str, str]] = [] # (screen_hash, target_id)
        
        import threading
        # We track events that happen between actions to assign them to edges
        self._recent_frida_events: List[Dict[str, Any]] = []
        self._events_lock = threading.Lock()

        if GEMINI_API_KEY:
            self.client = genai.Client(api_key=GEMINI_API_KEY)
        else:
            self.client = None
            logger.warning("[UIExplorer] No GEMINI_API_KEY found. AI exploration layer is disabled.")

        self.deterministic_keywords = {
            "allow": "dialogs_dismissed",
            "ok": "dialogs_dismissed", 
            "yes": "dialogs_dismissed", 
            "accept": "dialogs_dismissed",
            "continue": "buttons_clicked", 
            "next": "buttons_clicked", 
            "login": "buttons_clicked", 
            "sign in": "buttons_clicked", 
            "confirm": "buttons_clicked", 
            "grant": "permissions_granted", 
            "start": "buttons_clicked"
        }

        if self.event_bus:
            self.event_bus.subscribe(self._on_frida_event)

    def _on_frida_event(self, event: Dict[str, Any]):
        """Callback for the RuntimeEventBus."""
        timestamp = datetime.utcnow().strftime('%H:%M:%S')
        timeline_entry = {
            "timestamp": timestamp,
            "source": "Frida",
            "category": event.get("category", "unknown"),
            "data": event.get("data", {})
        }
        self.attack_timeline.append(timeline_entry)
        with self._events_lock:
            self._recent_frida_events.append(timeline_entry)

    def _get_timestamp(self) -> str:
        # returns mm:ss format relative to start_time
        elapsed = int(time.time() - self.start_time) if self.start_time else 0
        return f"{elapsed // 60:02d}:{elapsed % 60:02d}"

    async def _adb(self, *args) -> str:
        cmd = [self.adb_path, "-s", self.device_serial] + list(args)
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return stdout.decode('utf-8', errors='ignore')

    async def _dump_ui(self) -> Optional[str]:
        # Some Android versions do not support dumping to /dev/stdout
        await self._adb("shell", "uiautomator", "dump", "/data/local/tmp/ui_dump.xml")
        output = await self._adb("shell", "cat", "/data/local/tmp/ui_dump.xml")
        
        match = re.search(r'(<\?xml.*)', output, re.DOTALL)
        if match:
            return match.group(1)
            
        logger.warning(f"[UIExplorer] UI dump failed. Output: {output[:100]}...")
        return None

    def _get_screen_hash(self, nodes: List[Dict[str, Any]]) -> str:
        """Hash based only on stable interactive properties to survive layout shifts."""
        stable_repr = ""
        for n in nodes:
            stable_repr += f"{n['class']}|{n['text']}|{n['desc']}|{n['resource_id']}|{n['is_input']};"
        return hashlib.sha256(stable_repr.encode('utf-8')).hexdigest()[:12]

    def _parse_ui(self, xml_content: str) -> List[Dict[str, Any]]:
        nodes = []
        try:
            root = ET.fromstring(xml_content)
            for elem in root.iter():
                is_clickable = elem.attrib.get('clickable') == 'true'
                is_checkable = elem.attrib.get('checkable') == 'true'
                is_scrollable = elem.attrib.get('scrollable') == 'true'
                is_input = elem.attrib.get('class') == 'android.widget.EditText'
                
                if not (is_clickable or is_checkable or is_scrollable or is_input):
                    continue

                text = elem.attrib.get('text', '').strip()
                desc = elem.attrib.get('content-desc', '').strip()
                res_id = elem.attrib.get('resource-id', '')
                bounds_str = elem.attrib.get('bounds', '')
                
                if not bounds_str:
                    continue

                m = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
                if m:
                    x1, y1, x2, y2 = map(int, m.groups())
                    node_id = f"node_{len(nodes)}"
                    nodes.append({
                        "id": node_id,
                        "class": elem.attrib.get('class', '').split('.')[-1],
                        "text": text,
                        "desc": desc,
                        "resource_id": res_id.split('/')[-1] if '/' in res_id else res_id,
                        "center_x": (x1 + x2) // 2,
                        "center_y": (y1 + y2) // 2,
                        "is_input": is_input
                    })
        except Exception as e:
            logger.error(f"[UIExplorer] Failed to parse XML: {e}")
            
        # Update metrics
        self.coverage_metrics["buttons_found"] = max(self.coverage_metrics["buttons_found"], sum(1 for n in nodes if not n['is_input']))
        self.coverage_metrics["forms_found"] = max(self.coverage_metrics["forms_found"], sum(1 for n in nodes if n['is_input']))
        
        return nodes

    def _find_deterministic_action(self, nodes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for node in nodes:
            content = (node['text'] + " " + node['desc']).lower()
            if not content.strip():
                continue
            for kw, category in self.deterministic_keywords.items():
                if kw == content or f" {kw} " in f" {content} ":
                    return {
                        "action": "tap",
                        "target_id": node['id'],
                        "x": node['center_x'],
                        "y": node['center_y'],
                        "metric_category": category,
                        "reasoning": f"Deterministic match for '{kw}'"
                    }
        return None

    def _is_loop(self, screen_hash: str, target_id: str) -> bool:
        # Check if we've done this exact action on this screen 3 times in recent history
        history = self.action_history[-10:] # look at last 10 actions
        count = sum(1 for h in history if h[0] == screen_hash and h[1] == target_id)
        return count >= 3

    async def _find_ai_action(self, screen_hash: str, nodes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not self.model or not nodes:
            return None
            
        # Check Cache
        if screen_hash in self.screen_cache:
            logger.debug(f"[UIExplorer] Cache hit for screen {screen_hash}")
            cached_action = self.screen_cache[screen_hash]
            if not self._is_loop(screen_hash, cached_action["target_id"]):
                return cached_action
            else:
                logger.debug(f"[UIExplorer] Loop detected from cache on {screen_hash}. Ignoring cache.")

        simplified_nodes = []
        for n in nodes:
            sn = {"id": n["id"], "type": n["class"]}
            if n["text"]: sn["text"] = n["text"]
            if n["desc"]: sn["desc"] = n["desc"]
            if n["resource_id"]: sn["resource_id"] = n["resource_id"]
            if n["is_input"]: sn["is_input"] = True
            simplified_nodes.append(sn)

        prompt = f"""
You are an autonomous Android security testing agent. Your objective is to thoroughly explore the application.
Priority Goal: Dismiss Dialogs -> Grant Permissions -> Reach Login -> Fill Forms -> Authenticate -> Reach Dashboard -> Trigger Banking Functionality.

UI Elements available:
{json.dumps(simplified_nodes, indent=2)}

Available Form Data Dictionary:
{json.dumps(list(FORM_VALUES.keys()))}

Instructions:
1. If there is a text input field, choose 'type' and select the most appropriate key from the Form Data Dictionary for the 'text' field.
2. If there are buttons, choose 'tap' to progress.
3. If you want to abort this screen, choose 'ignore'.

Return valid JSON matching this schema:
{{
  "action": "tap" | "type" | "ignore",
  "target_id": "element id",
  "text": "the key from Form Data Dictionary (only if action is 'type')",
  "reasoning": "brief explanation"
}}
"""
        try:
            response = await asyncio.to_thread(
                self.client.models.generate_content,
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )
            decision = json.loads(response.text)
            
            action_type = decision.get("action")
            target_id = decision.get("target_id")
            
            if action_type == "ignore":
                return None
                
            if self._is_loop(screen_hash, target_id):
                logger.debug(f"[UIExplorer] AI suggested loop on {screen_hash}. Aborting branch.")
                return None
            
            target_node = next((n for n in nodes if n["id"] == target_id), None)
            if target_node:
                action = {
                    "action": action_type,
                    "target_id": target_id,
                    "x": target_node['center_x'],
                    "y": target_node['center_y'],
                    "text": decision.get("text", ""),
                    "reasoning": decision.get("reasoning", ""),
                    "metric_category": "forms_completed" if action_type == "type" else "buttons_clicked",
                    "from_ai": True
                }
                self.screen_cache[screen_hash] = action
                return action
            return None
        except Exception as e:
            logger.error(f"[UIExplorer] AI interaction failed: {e}")
            return None

    async def _find_ocr_action(self, screen_hash: str) -> Optional[Dict[str, Any]]:
        """Fallback to OCR/Vision when uiautomator fails or AI is blocked."""
        # 1. Take screenshot
        remote_path = f"/sdcard/ui_exp_{screen_hash}.png"
        local_path = f"ui_exp_{screen_hash}.png"
        await self._adb("shell", "screencap", "-p", remote_path)
        await self._adb("pull", remote_path, local_path)
        await self._adb("shell", "rm", remote_path)
        
        if not os.path.exists(local_path):
            return None
            
        action = None
        try:
            # 2. Try pytesseract (local OCR)
            try:
                img = Image.open(local_path)
                data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
                
                # Look for deterministic keywords
                for i, text in enumerate(data['text']):
                    if text.strip().lower() in self.deterministic_keywords:
                        x, y = data['left'][i] + data['width'][i]//2, data['top'][i] + data['height'][i]//2
                        action = {
                            "action": "tap",
                            "target_id": f"ocr_{text}",
                            "x": x,
                            "y": y,
                            "metric_category": self.deterministic_keywords[text.strip().lower()],
                            "reasoning": f"OCR Match: {text}",
                            "from_ai": False
                        }
                        break
            except Exception as e:
                logger.debug(f"[UIExplorer] Pytesseract failed/not available: {e}")
                
            # 3. Fallback to Gemini Vision if OCR didn't find anything and model is available
            if not action and self.client:
                logger.info(f"[UIExplorer] Using Gemini Vision fallback for {screen_hash}")
                prompt = "Analyze this Android screen. Respond with JSON {\"action\":\"tap\", \"x\":123, \"y\":456, \"reasoning\":\"clicking next\"}. If no obvious action, return {\"action\":\"ignore\"}."
                
                with open(local_path, "rb") as img_file:
                    image_data = img_file.read()
                
                response = await asyncio.to_thread(
                    self.client.models.generate_content,
                    model=GEMINI_MODEL,
                    contents=[
                        types.Part.from_bytes(data=image_data, mime_type='image/png'),
                        prompt
                    ],
                    config=types.GenerateContentConfig(response_mime_type="application/json")
                )
                
                decision = json.loads(response.text)
                if decision.get("action") == "tap":
                    action = {
                        "action": "tap",
                        "target_id": "vision_tap",
                        "x": decision.get("x", 500),
                        "y": decision.get("y", 500),
                        "metric_category": "buttons_clicked",
                        "reasoning": f"Vision Match: {decision.get('reasoning')}",
                        "from_ai": True
                    }
        finally:
            if os.path.exists(local_path):
                os.remove(local_path)
                
        return action

    async def _execute_action(self, action: Dict[str, Any]):
        atype = action["action"]
        x, y = action["x"], action["y"]
        
        # Log to timeline
        msg = f"{'AI' if action.get('from_ai') else 'Deterministic'} chose {atype} on node {action['target_id']} ({action.get('reasoning','')})"
        logger.info(f"[UIExplorer] {msg}")
        
        self.attack_timeline.append({
            "timestamp": self._get_timestamp(),
            "source": "AI" if self.mode == "ai" else "Hybrid_AI",
            "action": atype,
            "target": action["target_id"],
            "details": msg
        })
        
        if atype == "tap":
            await self._adb("shell", "input", "tap", str(x), str(y))
        elif atype == "type":
            await self._adb("shell", "input", "tap", str(x), str(y))
            await asyncio.sleep(0.5)
            import shlex
            # Lookup actual value from dictionary
            dict_key = action.get("text", "")
            actual_text = FORM_VALUES.get(dict_key, dict_key) # fallback to literal if AI messed up
            safe_text = shlex.quote(actual_text.replace(' ', '%s'))
            await self._adb("shell", "input", "text", safe_text)
            
        # Update metric stats
        category = action.get("metric_category")
        if category in self.coverage_metrics:
            self.coverage_metrics[category] += 1
            
        self.clicked_nodes.add(action["target_id"])

        await asyncio.sleep(1.5)

    async def start(self, duration_seconds: int):
        self._is_running = True
        self._cancel_task = False
        self.start_time = time.time()
        self.duration_seconds = duration_seconds
        
        self.attack_timeline.append({
            "timestamp": "00:00",
            "source": "System",
            "action": "Analysis Started",
            "details": f"Explorer Mode: {self.mode}"
        })
        
        last_hash = None
        
        while self._is_running and (time.time() - self.start_time) < duration_seconds:
            if self._cancel_task:
                break
                
            try:
                xml_content = await self._dump_ui()
                if not xml_content:
                    await asyncio.sleep(2)
                    continue
                    
                nodes = self._parse_ui(xml_content)
                if not nodes:
                    logger.info("[UIExplorer] No actionable nodes found on screen.")
                    await asyncio.sleep(2)
                    continue

                current_hash = self._get_screen_hash(nodes)
                
                # Navigation tracking
                if current_hash not in self.visited_hashes:
                    self.visited_hashes.add(current_hash)
                    self.coverage_metrics["screens"] = len(self.visited_hashes)
                    self.coverage_metrics["navigation_depth"] += 1
                
                # Clear recent Frida events for edge tracking
                with self._events_lock:
                    captured_frida_events = list(self._recent_frida_events)
                    self._recent_frida_events.clear()

                action = self._find_deterministic_action(nodes)
                if not action:
                    action = await self._find_ai_action(current_hash, nodes)
                    
                if action:
                    # Log edge to graph
                    if last_hash:
                        self.exploration_graph.append({
                            "from": last_hash,
                            "to": current_hash,
                            "action": action["action"],
                            "target_id": action["target_id"],
                            "goal": action.get("reasoning", ""),
                            "timestamp": self._get_timestamp(),
                            "source": "AI",
                            "frida_events": captured_frida_events
                        })
                    
                    self.action_history.append((current_hash, action["target_id"]))
                    await self._execute_action(action)
                    last_hash = current_hash
                else:
                    # Fallback to OCR if both deterministic and AI fail to find an action
                    action = await self._find_ocr_action(current_hash)
                    if action:
                        logger.info(f"[UIExplorer] Found action via OCR/Vision on {current_hash}")
                        self.action_history.append((current_hash, action["target_id"]))
                        await self._execute_action(action)
                        last_hash = current_hash
                    else:
                        logger.debug("[UIExplorer] No actionable elements found. Swiping up.")
                        self.attack_timeline.append({
                            "timestamp": self._get_timestamp(),
                            "source": "AI",
                            "action": "swipe",
                            "details": "Swiping to unblock UI"
                        })
                        await self._adb("shell", "input", "swipe", "500", "1500", "500", "500", "300")
                        await asyncio.sleep(1.5)
                        last_hash = current_hash # next screen comes from this swipe
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[UIExplorer] Loop error: {e}")
                await asyncio.sleep(2)
                
        self.attack_timeline.append({
            "timestamp": self._get_timestamp(),
            "source": "System",
            "action": "Analysis Completed"
        })
        
        if self.event_bus:
            self.event_bus.unsubscribe(self._on_frida_event)
            
        self._is_running = False

    def stop(self):
        self._cancel_task = True

    def get_reports(self) -> Dict[str, Any]:
        """Returns the generated artifacts."""
        # Calculate coverage percent roughly based on found vs clicked
        if self.coverage_metrics["buttons_found"] > 0:
            pct = int((self.coverage_metrics["buttons_clicked"] / self.coverage_metrics["buttons_found"]) * 100)
            self.coverage_metrics["coverage_percent"] = min(100, pct)
            
        summary = {
            "mode": self.mode,
            "duration_seconds": self.duration_seconds,
            "screens_visited": self.coverage_metrics["screens"],
            "buttons_clicked": self.coverage_metrics["buttons_clicked"],
            "forms_completed": self.coverage_metrics["forms_completed"],
            "permissions_granted": self.coverage_metrics["permissions_granted"],
            "dialogs_dismissed": self.coverage_metrics["dialogs_dismissed"],
            "loops_detected": sum(1 for h in self.action_history if self.action_history.count(h) > 2),
            "gemini_calls": len(self.screen_cache),
            "cache_hits": len(self.action_history) - len(self.screen_cache), # Rough estimate
            "coverage_percent": self.coverage_metrics["coverage_percent"]
        }
        
        return {
            "exploration_graph": self.exploration_graph,
            "coverage": self.coverage_metrics,
            "attack_timeline": self.attack_timeline,
            "exploration_summary": summary
        }
