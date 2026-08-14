"""
The Threat Intel feed subscription list.

Source: the Cloud Security Forum #blogs-and-feeds list. Two overlapping pastes
were provided — the current curated list and an older one from a year earlier
that still carried vendor research blogs. Merging them by feed id and by
normalised URL (scheme, `www.` and trailing slash ignored) collapses 64 raw
entries into the 40 below: 24 were duplicates.

Fields
------
id       The forum's feed id, kept so an entry can be traced back to the source
         list. Also the stable key the UI filters by.
title    Display name of the publication.
url      The RSS/Atom endpoint.
curated  True when the feed appears in the current list; False when it only
         appears in the year-old one. Purely a fact about the input lists — no
         editorial judgement — but it is the axis the forum itself pruned on,
         so it is the natural filter if the vendor blogs are ever dropped again.
official True for feeds published by the cloud provider rather than by a
         researcher or vendor. These are the advisory-grade sources.
enabled  Set False to stop polling a feed without deleting its provenance.

Observed status
---------------
A full live probe of all 40 URLs on 2026-08-15 returned 797 items from 31
feeds. Nine did not yield a feed. They are left enabled rather than pruned
here: the daily run reports each failure by name, so a publisher that has
merely moved its feed gets noticed and fixed instead of silently disappearing.
Flip `enabled` to False for any that stay dead.

    Kat Traxler          HTTP 404          (in the current curated list)
    Fog Security         HTTP 404
    Lightspin            HTTP 403
    Bridgecrew           connection refused
    Orca Security        redirect loop
    Sym                  TLS handshake failure
    Threat Stack         DNS does not resolve
    3CORESec             DNS does not resolve
    Expel                serves an HTML page, not a feed
"""

from __future__ import annotations

from typing import Any, TypedDict


class Feed(TypedDict):
    """One RSS/Atom subscription."""

    id: str
    title: str
    url: str
    curated: bool
    official: bool
    enabled: bool


FEEDS: list[Feed] = [
    # ── Present in the current curated list ──────────────────────────────────
    {"id": "10627331036689", "title": "Cirrius Tech Blog", "url": "https://cirriustech.co.uk/blog/index.xml", "curated": True, "official": False, "enabled": True},
    {"id": "9331707933286", "title": "Skybound's Blog", "url": "https://www.skybound.link/index.xml", "curated": True, "official": False, "enabled": True},
    {"id": "8895966069796", "title": "Cloud Security Newsletter", "url": "https://rss.beehiiv.com/feeds/hEEMTXlHVR.xml", "curated": True, "official": False, "enabled": True},
    {"id": "8534749099264", "title": "Grounded Cloud Security", "url": "https://groundedcloudsecurity.substack.com/feed", "curated": True, "official": False, "enabled": True},
    {"id": "7793683955639", "title": "AWS Security Digest", "url": "https://awssecuritydigest.com/feed.xml", "curated": True, "official": False, "enabled": True},
    {"id": "7725747154547", "title": "CloudSecurity on Chris Farris", "url": "https://www.chrisfarris.com/categories/cloudsecurity/rss.xml", "curated": True, "official": False, "enabled": True},
    {"id": "7258814012592", "title": "Cloud Archives — Securosis", "url": "http://securosis.com/category/cloud/feed", "curated": True, "official": False, "enabled": True},
    {"id": "6744549388531", "title": "AWS Cloud Security Weekly", "url": "https://aws-cloudsec.com/feed", "curated": True, "official": False, "enabled": True},
    {"id": "6734355369669", "title": "Cloud Conversations — Kat Traxler", "url": "https://kattraxler.cloud/feed.xml", "curated": True, "official": False, "enabled": True},
    {"id": "6608868607264", "title": "Posts on PrimeHarbor", "url": "https://www.primeharbor.com/blog/index.xml", "curated": True, "official": False, "enabled": True},
    {"id": "6585905007440", "title": "Invictus Incident Response", "url": "https://www.invictus-ir.com/news/rss.xml", "curated": True, "official": False, "enabled": True},
    {"id": "6293736661078", "title": "Cloud Security Lab a Week (S.L.A.W)", "url": "https://rss.beehiiv.com/feeds/o5E9jNG0b8.xml", "curated": True, "official": False, "enabled": True},
    {"id": "5518419958740", "title": "Public Cloud Security Breaches", "url": "https://www.breaches.cloud/news/index.xml", "curated": True, "official": False, "enabled": True},
    {"id": "5369081907606", "title": "CloudSecList", "url": "https://cloudseclist.com/feed.xml", "curated": True, "official": False, "enabled": True},
    {"id": "5138022214820", "title": "Detection Engineering", "url": "https://www.detectionengineering.net/feed", "curated": True, "official": False, "enabled": True},
    {"id": "4531306309217", "title": "Hacking The Cloud", "url": "https://hackingthe.cloud/feed_rss_created.xml", "curated": True, "official": False, "enabled": True},
    {"id": "3998226637285", "title": "Nick Frichette", "url": "https://frichetten.com/blog/index.xml", "curated": True, "official": False, "enabled": True},
    {"id": "3922153637539", "title": "Open Cloud Vulnerability & Security Issue Database", "url": "https://www.cloudvulndb.org/rss/feed.xml", "curated": True, "official": False, "enabled": True},
    {"id": "3629421140308", "title": "AWS Breaking Changes", "url": "https://github.com/SummitRoute/aws_breaking_changes/releases.atom", "curated": True, "official": True, "enabled": True},
    {"id": "3619513265698", "title": "AWS Security Bulletins", "url": "https://aws.amazon.com/security/security-bulletins/rss/feed/", "curated": True, "official": True, "enabled": True},
    {"id": "3255480074853", "title": "tl;dr sec", "url": "https://tldrsec.com/feed.xml", "curated": True, "official": False, "enabled": True},
    {"id": "3258338747235", "title": "Christophe Tafani-Dereeper", "url": "https://blog.christophetd.fr/feed/", "curated": True, "official": False, "enabled": True},
    {"id": "3258346913058", "title": "One Cloud Please", "url": "https://onecloudplease.com/feed", "curated": True, "official": False, "enabled": True},
    {"id": "3260683691380", "title": "Aidan Steele's Blog", "url": "https://awsteele.com/feed", "curated": True, "official": False, "enabled": True},
    {"id": "3270933380049", "title": "William Bengtson on Medium", "url": "https://medium.com/feed/@WilliamBengtson", "curated": True, "official": False, "enabled": True},
    {"id": "3255421666949", "title": "Summit Route", "url": "http://summitroute.com/blog/feed.xml", "curated": True, "official": False, "enabled": True},

    # ── Only in the year-old list (mostly vendor research blogs) ─────────────
    {"id": "8886045549366", "title": "Cloud Security Podcast TV", "url": "http://www.cloudsecuritypodcast.tv/videos/rss.xml", "curated": False, "official": False, "enabled": True},
    {"id": "8691651103141", "title": "Fog Security Technical Blog", "url": "https://www.fogsecurity.io/blog/rss.xml", "curated": False, "official": False, "enabled": True},
    {"id": "4636646918871", "title": "Risk and Cyber — Phil Venables", "url": "https://www.philvenables.com/blog-feed.xml", "curated": False, "official": False, "enabled": True},
    {"id": "4523887696561", "title": "Lightspin Research", "url": "https://blog.lightspin.io/tag/research/rss.xml", "curated": False, "official": False, "enabled": True},
    {"id": "4506398349058", "title": "Bridgecrew Research", "url": "https://bridgecrew.io/blog/category/research/feed/", "curated": False, "official": False, "enabled": True},
    {"id": "4491846016423", "title": "Orca Security Research Pod", "url": "https://orca.security/resources/category/research-pod/feed/", "curated": False, "official": False, "enabled": True},
    {"id": "4491030285335", "title": "Wiz Research", "url": "https://www.wiz.io/blog/tag/research/rss/", "curated": False, "official": False, "enabled": True},
    {"id": "3879850803014", "title": "The Sym Blog", "url": "https://blog.symops.com/feed.xml", "curated": False, "official": False, "enabled": True},
    {"id": "3790782570466", "title": "Cloud Archives — Unit 42", "url": "https://unit42.paloaltonetworks.com/category/cloud/feed", "curated": False, "official": False, "enabled": True},
    {"id": "3785365460067", "title": "Datadog Security Labs", "url": "https://securitylabs.datadoghq.com/rss/feed.xml", "curated": False, "official": False, "enabled": True},
    {"id": "3282085883264", "title": "Threat Stack Blog", "url": "https://www.threatstack.com/blog/feed", "curated": False, "official": False, "enabled": True},
    {"id": "3260696435172", "title": "Expel Blog", "url": "https://expel.com/blog/feed/", "curated": False, "official": False, "enabled": True},
    {"id": "3258320202418", "title": "Rhino Security Labs", "url": "https://rhinosecuritylabs.com/feed/", "curated": False, "official": False, "enabled": True},
    {"id": "3251666358102", "title": "3CORESec Blog", "url": "https://blog.3coresec.com/feeds/posts/default?alt=rss", "curated": False, "official": False, "enabled": True},
]


def enabled_feeds() -> list[Feed]:
    """
    Return the feeds the ingest task should poll.

    Returns:
        Every feed whose `enabled` flag is set, in catalogue order.
    """
    return [feed for feed in FEEDS if feed["enabled"]]


def feed_index() -> dict[str, Feed]:
    """
    Map feed id to feed, for attaching publication metadata to an item.

    Returns:
        Dict keyed by feed id over the whole catalogue, enabled or not, so
        items ingested before a feed was disabled still resolve their source.
    """
    return {feed["id"]: feed for feed in FEEDS}


def public_sources() -> list[dict[str, Any]]:
    """
    Describe the subscription list for the API, without the `enabled` plumbing.

    Returns:
        One dict per feed with id, title, url, curated and official.
    """
    return [
        {
            "id": feed["id"],
            "title": feed["title"],
            "url": feed["url"],
            "curated": feed["curated"],
            "official": feed["official"],
        }
        for feed in FEEDS
        if feed["enabled"]
    ]
