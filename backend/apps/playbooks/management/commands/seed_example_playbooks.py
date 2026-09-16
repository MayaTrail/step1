"""
Backfill the starter example playbooks for existing users.

New users get theirs from the post_save signal in apps/playbooks/signals.py.
This covers everyone who signed up before that existed, and anyone whose
seeding failed because the emulation packages were not mounted at the time.

Seeding is idempotent: a user who already has any playbook is skipped, so this
never duplicates and never resurrects something the user deleted.

    python manage.py seed_example_playbooks
    python manage.py seed_example_playbooks --user someone@example.com
    python manage.py seed_example_playbooks --dry-run
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from apps.playbooks.examples import seed_examples
from apps.playbooks.models import Playbook


class Command(BaseCommand):
    """Give users without any playbooks their starting examples."""

    help = "Seed the example playbooks for users who have none."

    def add_arguments(self, parser):
        """Register command-line options."""
        parser.add_argument(
            "--user",
            help="Only seed this user, by email or username.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be seeded without writing anything.",
        )

    def handle(self, *args, **options):
        """Seed each eligible user and report what happened."""
        User = get_user_model()
        users = User.objects.all()

        target = options.get("user")
        if target:
            users = users.filter(email=target) | users.filter(username=target)
            if not users.exists():
                self.stderr.write(self.style.ERROR("No user matching %r." % target))
                return

        seeded_total = 0
        skipped = 0

        for user in users.iterator():
            if Playbook.objects.filter(owner=user).exists():
                skipped += 1
                continue

            if options["dry_run"]:
                self.stdout.write("would seed: %s" % user)
                seeded_total += 1
                continue

            created = seed_examples(user)
            if created:
                seeded_total += 1
                self.stdout.write(
                    self.style.SUCCESS(
                        "seeded %s with %d playbook(s): %s"
                        % (user, len(created), ", ".join(p.title for p in created))
                    )
                )
            else:
                skipped += 1

        self.stdout.write(
            "\n%s %d user(s), skipped %d that already had playbooks."
            % ("Would seed" if options["dry_run"] else "Seeded", seeded_total, skipped)
        )
