"""
The two example playbooks a new user starts with.

An empty Playbooks page teaches nothing: the block editor has five block types
and no obvious answer to "what goes where". So every user gets two examples,
and between them they answer that question from both directions.

  1. An annotated template. Every block type appears once, and the content of
     each block explains what that block is for. Reading it in the reader shows
     what each type becomes; opening it in the editor shows which field
     produced it.

  2. A real fork of a shipped PLAYBOOK.md. The template shows the shape; the
     fork shows the standard - a full seven-phase incident response written by
     people who have done it, already in their library to adapt.

Both are marked is_example, so the UI can label them and the user can delete
them without ceremony. They are ordinary playbooks in every other respect.
"""

from __future__ import annotations

import logging

from .models import Playbook
from .sources import PlaybookSourceError, load_shipped_playbook

logger = logging.getLogger(__name__)

# The emulation whose playbook seeds the worked example. Codefinger is the
# smallest of the campaign playbooks that still carries the full phase set, so
# the example is representative without being 27 KB of reading.
EXAMPLE_FORK_SOURCE = "codefinger"

TEMPLATE_TITLE = "Example - how a playbook is built"
TEMPLATE_SUMMARY = (
    "A worked example of every block type. Safe to edit, safe to delete."
)

# Authored in the exact conventions blocksToMarkdown emits, so opening this in
# the editor yields one clean block per section rather than a wall of prose.
TEMPLATE_BODY = """# Example - how a playbook is built

## 1. Preparation

This is a **Phase** block. Each phase becomes a tab when someone reads the
playbook, so use them for the stages of the response - Preparation,
Identification, Containment, Eradication, Recovery.

Everything you add below a phase belongs to it, until the next phase starts.

### What belongs here

This is a **Notes** block. Use it for context that is not an action: what has
to be true before the incident, which logs need to already be on, who gets
called. It takes a heading and prose.

## 2. Identification

#### Step 1 - Confirm the alert is real before escalating

This is a **Step** block. A step is one action a responder takes, and it
becomes a checkable item with a progress bar in the reader - so write one
action per step, not a paragraph of several.

The body is for what to look for, and what "good" looks like.

#### Step 2 - Pull the evidence

Put the reasoning in the step, and the exact command in a Command block
underneath it.

Check the trail status before assuming logging was on:

```bash
aws cloudtrail get-trail-status --name my-trail --region us-east-1
```

That was a **Command** block. It gets a copy button in the reader, so paste
the real command with real flags - a responder should not have to retype it
during an incident.

**Decision - Did the attacker actually disable logging?**

| If | Then |
| --- | --- |
| IsLogging is false | Treat as confirmed evasion; go to Containment |
| IsLogging is true, gaps in delivery | Check the S3 bucket policy before escalating |
| IsLogging is true, no gaps | Alert is likely a false positive; close it out |

That was a **Decision** block. Use one wherever the response branches, so the
next person does not have to guess which way to go. Each row is one condition
and what it means.

## 3. Containment

Delete this playbook whenever you like - it is only here as a reference. The
one beside it is a real playbook forked from an emulation package, which is
the other way to start: take a shipped one and adapt it to your environment.
"""


def _template_playbook(user) -> Playbook:
    """Create the annotated block-type example for a user."""
    return Playbook.objects.create(
        owner=user,
        title=TEMPLATE_TITLE,
        summary=TEMPLATE_SUMMARY,
        body=TEMPLATE_BODY,
        status=Playbook.Status.PUBLISHED,
        visibility=Playbook.Visibility.PRIVATE,
        is_example=True,
    )


def _forked_playbook(user) -> Playbook | None:
    """
    Create a real fork of a shipped playbook, or None if none is available.

    The emulation registry needs EMULATIONS_BASE_DIR and the packages on disk.
    Neither is guaranteed (a test run, a misconfigured container), and a user
    failing to be created because an example could not be seeded would be a
    poor trade, so this degrades to None rather than raising.
    """
    try:
        display_name, markdown = load_shipped_playbook(EXAMPLE_FORK_SOURCE)
    except PlaybookSourceError as exc:
        logger.info("No example fork seeded for %s: %s", user, exc)
        return None

    return Playbook.objects.create(
        owner=user,
        title="Example - %s, adapted" % display_name,
        summary=(
            "A real shipped playbook, forked. Edit it to match your accounts, "
            "your escalation path, your tooling."
        ),
        body=markdown,
        source_emulation=EXAMPLE_FORK_SOURCE,
        status=Playbook.Status.DRAFT,
        visibility=Playbook.Visibility.PRIVATE,
        is_example=True,
    )


def seed_examples(user) -> list[Playbook]:
    """
    Give a user their starting examples.

    Idempotent: a user who already has any playbook - example or their own - is
    left alone, so this can run on login, on a management command, or on a
    backfill without ever duplicating or resurrecting something deleted.

    Args:
        user: The user to seed.

    Returns:
        The playbooks created, which is empty when the user already had some.
    """
    if Playbook.objects.filter(owner=user).exists():
        return []

    created = [_template_playbook(user)]
    forked = _forked_playbook(user)
    if forked is not None:
        created.append(forked)
    return created
