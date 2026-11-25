"""Fails only in the merge queue, to time how long the rest of a queue run lives after a job fails. Never merged."""
import os
import unittest


class QueueOnly(unittest.TestCase):
    def test_fails_in_the_merge_queue_only(self):
        if os.environ.get("GITHUB_EVENT_NAME") == "merge_group":
            self.fail("controlled failure in the merge queue to time the first-failure cut")


if __name__ == "__main__":
    unittest.main()
