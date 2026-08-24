"""
Unit tests for generic semantic action classification and acceptance policy.

These tests deliberately use arbitrary button labels and unknown workflows —
no package-specific or screen-specific rules.
"""

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.semantic_action import (
    SemanticRole,
    acceptance_priority_boost,
    classify_semantic_role,
    infer_affirmative_choice,
    is_acceptance_role,
    validate_coordinates_for_screen,
)
from sudarshan_core.engines.agentic.exploration_engine import ActionItem, ActionPrioritizer
from sudarshan_core.engines.agentic.visual_grounding import (
    recover_from_xml_structure,
    validate_grounded_coordinates,
)


class TestSemanticClassification(unittest.TestCase):
    def test_unknown_affirmative_labels(self):
        for label in (
            "Let's go",
            "Get started",
            "Proceed securely",
            "Activate now",
            "Claim reward",
            "Finish setup",
            "Start now",
        ):
            result = classify_semantic_role(label=label, is_clickable=True)
            self.assertIn(
                result.role,
                {SemanticRole.ACCEPT, SemanticRole.PROGRESS, SemanticRole.OPEN},
                msg=f"Unexpected role for {label!r}: {result.role}",
            )

    def test_install_update_dialog(self):
        ctx = "A new version of the app is ready. Download the update."
        result = classify_semantic_role(
            label="Install",
            class_name="Button",
            context_text=ctx,
            is_clickable=True,
            bounds_area=12000,
        )
        self.assertIn(result.role, {SemanticRole.INSTALL, SemanticRole.ACCEPT})
        self.assertGreater(result.confidence, 0.5)

    def test_decline_vs_accept_pair(self):
        allow = ActionItem(
            action_id="a1", node_id="n1", action_type="click", label="Allow",
            semantic_role=SemanticRole.ACCEPT.value, confidence=0.9,
        )
        deny = ActionItem(
            action_id="a2", node_id="n2", action_type="click", label="Deny",
            semantic_role=SemanticRole.DECLINE.value, confidence=0.9,
        )
        choice = infer_affirmative_choice(
            [deny, allow],
            context_text="Allow app to access your contacts?",
        )
        self.assertIs(choice, allow)

    def test_arbitrary_primary_cta(self):
        proceed = ActionItem(
            action_id="a1", node_id="n1", action_type="click",
            label="Complete verification", center_y=900,
            semantic_role=SemanticRole.PROGRESS.value, confidence=0.7,
        )
        dismiss = ActionItem(
            action_id="a2", node_id="n2", action_type="click",
            label="Maybe later", center_y=700,
            semantic_role=SemanticRole.DECLINE.value, confidence=0.8,
        )
        choice = infer_affirmative_choice([dismiss, proceed])
        self.assertIs(choice, proceed)

    def test_acceptance_priority_boost(self):
        self.assertGreater(
            acceptance_priority_boost(SemanticRole.ACCEPT),
            acceptance_priority_boost(SemanticRole.DECLINE),
        )
        self.assertTrue(is_acceptance_role(SemanticRole.INSTALL))

    def test_checkable_toggle(self):
        result = classify_semantic_role(
            label="Enable notifications",
            is_checkable=True,
            is_clickable=True,
        )
        self.assertEqual(result.role, SemanticRole.ENABLE)


class TestCoordinateValidation(unittest.TestCase):
    def test_rejects_out_of_bounds(self):
        ok, reason = validate_coordinates_for_screen(
            2000, 3000, screen_width=1080, screen_height=2400,
        )
        self.assertFalse(ok)
        self.assertIn("out_of_bounds", reason)

    def test_accepts_valid_bounds(self):
        ok, reason = validate_coordinates_for_screen(
            540, 1200,
            screen_width=1080,
            screen_height=2400,
            bounds="[400,1100][680,1300]",
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")

    def test_visual_grounding_validator(self):
        self.assertTrue(validate_grounded_coordinates(100, 200, 1080, 2400))
        self.assertFalse(validate_grounded_coordinates(-1, 200, 1080, 2400))


class TestXmlStructureRecovery(unittest.TestCase):
    def test_recovers_non_clickable_button_label(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy>
  <node class="android.widget.TextView" text="New Update Available"
        bounds="[100,400][980,500]" clickable="false"/>
  <node class="android.widget.TextView" text="Proceed with setup"
        bounds="[100,900][980,1000]" clickable="false"/>
</hierarchy>"""
        recovered = recover_from_xml_structure(
            xml, [], screen_width=1080, screen_height=1920,
            context_text="New Update Available Proceed with setup",
        )
        labels = [r.label for r in recovered]
        self.assertIn("Proceed with setup", labels)

    def test_prioritizer_prefers_acceptance(self):
        from sudarshan_core.engines.agentic.exploration_engine import ApplicationProfile

        profile = ApplicationProfile()
        actions = [
            ActionItem(
                action_id="1", node_id="n1", action_type="click",
                label="Not now", semantic_role=SemanticRole.DECLINE.value,
            ),
            ActionItem(
                action_id="2", node_id="n2", action_type="click",
                label="Get access", semantic_role=SemanticRole.ACCEPT.value,
            ),
        ]
        ranked = ActionPrioritizer.rank_actions(actions, profile)
        self.assertEqual(ranked[0].label, "Get access")


if __name__ == "__main__":
    unittest.main()
