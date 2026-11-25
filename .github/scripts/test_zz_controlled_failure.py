"""A deliberate failure to time how long the rest of the run lives after a job fails. Never merged."""
import unittest


class Controlled(unittest.TestCase):
    def test_fails_on_purpose(self):
        self.fail("controlled failure of epistle-ci to time cancel-others")
