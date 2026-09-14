"""
Tests for the recorded stack lifecycle.

The source scan at the bottom is unusual for a test suite and is here on
purpose. `transition_to(save=False)` appends to `status_history` in memory and
leaves the caller to persist it; a caller that saves with `update_fields`
omitting that field drops the history with no error, no exception and nothing
visible until someone opens a timeline weeks later and finds it empty. A unit
test cannot catch that, because the bug is in which fields a caller names.
"""

import pathlib
import re

from django.test import SimpleTestCase

from apps.infrastructure.models import Stack

BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[3]

# Files that move a stack between statuses.
TRANSITION_SOURCES = [
    "apps/emulations/tasks.py",
    "apps/infrastructure/tasks.py",
    "apps/infrastructure/views.py",
]


class TransitionTests(SimpleTestCase):
    """What transition_to records, without touching the database."""

    def _stack(self, status=Stack.Status.PENDING, history=None):
        """
        Build an unsaved Stack for in-memory assertions.

        Args:
            status: Starting status.
            history: Starting history, defaulting to empty.

        Returns:
            A Stack instance that is never saved, so these stay SimpleTestCase.
        """
        return Stack(status=status, status_history=list(history or []))

    def test_a_transition_is_recorded_with_a_timestamp(self):
        """The timestamp is the whole point: durations are derived from it."""
        stack = self._stack()
        stack.transition_to(Stack.Status.DEPLOYING, save=False)
        self.assertEqual(len(stack.status_history), 1)
        entry = stack.status_history[0]
        self.assertEqual(entry["status"], Stack.Status.DEPLOYING)
        self.assertTrue(entry["at"])

    def test_the_status_moves_with_the_record(self):
        """The history must never disagree with the status it describes."""
        stack = self._stack()
        stack.transition_to(Stack.Status.READY, save=False)
        self.assertEqual(stack.status, Stack.Status.READY)

    def test_transitions_accumulate_in_order(self):
        """A timeline is only readable oldest first."""
        stack = self._stack()
        for status in (Stack.Status.DEPLOYING, Stack.Status.READY, Stack.Status.DESTROYING):
            stack.transition_to(status, save=False)
        self.assertEqual(
            [entry["status"] for entry in stack.status_history],
            [Stack.Status.DEPLOYING, Stack.Status.READY, Stack.Status.DESTROYING],
        )

    def test_re_entering_the_same_status_is_ignored(self):
        """
        A task that saves twice must not create a phase of zero length.

        Otherwise a timeline shows "Deploying 0s" repeatedly and the real
        duration is split across entries that look like separate attempts.
        """
        stack = self._stack()
        stack.transition_to(Stack.Status.DEPLOYING, save=False)
        stack.transition_to(Stack.Status.DEPLOYING, save=False)
        self.assertEqual(len(stack.status_history), 1)

    def test_the_first_transition_is_recorded_even_if_the_status_matches(self):
        """
        A stack created directly in a status still needs its opening entry.

        Without this a stack whose first transition equals its default status
        would start with an empty history and no measurable beginning.
        """
        stack = self._stack(status=Stack.Status.PENDING)
        stack.transition_to(Stack.Status.PENDING, save=False)
        self.assertEqual(len(stack.status_history), 1)

    def test_a_failure_reason_is_kept(self):
        """The timeline answers where it failed; the detail answers why."""
        stack = self._stack()
        stack.transition_to(Stack.Status.FAILED, "UnauthorizedOperation", save=False)
        self.assertEqual(stack.status_history[-1]["detail"], "UnauthorizedOperation")


class PersistenceContractTests(SimpleTestCase):
    """
    Every deferred transition must be followed by a save that writes it.

    This reads the source rather than exercising behaviour, because the failure
    it guards against produces no error at all. A caller that omits
    status_history from update_fields loses the history silently, on exactly the
    long-running task paths that are hardest to observe.
    """

    def test_no_status_is_assigned_directly(self):
        """
        Assigning `status` bypasses the recording entirely.

        Any new call site must go through transition_to, or its phase simply
        never appears in the timeline.
        """
        offenders = []
        for name in TRANSITION_SOURCES:
            source = (BACKEND_ROOT / name).read_text()
            for match in re.finditer(r"\.status = Stack\.Status\.", source):
                offenders.append(f"{name}:{source[:match.start()].count(chr(10)) + 1}")
        self.assertEqual(offenders, [], f"assign via transition_to instead: {offenders}")

    def test_every_deferred_transition_is_persisted(self):
        """
        A save following transition_to(save=False) must name status_history.

        The saves are matched on the same variable as the transition, since
        these blocks often save a second unrelated model first.
        """
        offenders = []
        for name in TRANSITION_SOURCES:
            source = (BACKEND_ROOT / name).read_text()
            for match in re.finditer(r"(\w+)\.transition_to\([^)]*save=False\)", source):
                variable = match.group(1)
                following = source[match.end():match.end() + 1200]
                save = re.search(
                    rf"{variable}\.save\(update_fields=\[(.*?)\]", following, re.S
                )
                if not save or "status_history" not in save.group(1):
                    offenders.append(f"{name}:{source[:match.start()].count(chr(10)) + 1}")
        self.assertEqual(
            offenders,
            [],
            f"these transitions would be lost on save: {offenders}",
        )
