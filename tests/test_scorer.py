import unittest
from types import SimpleNamespace
from execcheck.scorer import score_entry

class TestScorerOverrideBlocked(unittest.TestCase):
    def setUp(self):
        scoring = SimpleNamespace(
            unsigned=0,
            missing_team_id=0,
            override_blocked=7,
            vt_malicious=0,
            custom_flag_mask={}
        )
        self.config = SimpleNamespace(scoring=scoring)

    def test_label_override_triggers(self):
        score, trace = score_entry({'policy_match_label': 'Override'}, self.config)
        self.assertEqual(score, 7)
        self.assertIn('override_blocked (+7)', trace)

    def test_code_override_triggers(self):
        score, trace = score_entry({'policy_match': 3}, self.config)
        self.assertEqual(score, 7)
        self.assertIn('override_blocked (+7)', trace)

    def test_non_override_does_not_trigger(self):
        score, trace = score_entry({'policy_match_label': 'Allow'}, self.config)
        self.assertEqual(score, 0)
        self.assertNotIn('override_blocked (+7)', trace)

if __name__ == '__main__':
    unittest.main()
