"""
Compiling the shipped Sigma rules into a customer's SIEM query language.

A detection is written once, as Sigma, and a customer runs Splunk or OpenSearch.
Something has to translate. That translation is a compiler problem with an
official, maintained implementation — pySigma plus a backend per target — so it
is done here deterministically rather than by asking a model to write a query.
The product's promise is that an engineer can check the work; a query nobody can
verify is not evidence.

Three layers, and only the middle one is ever ours:

    rule       the shipped sigma_*.yml, unchanged.
    pipeline   maps field names onto the target's schema. Optional, and absent
               by default: MayaTrail's rules are written against raw CloudTrail
               JSON, which is what both backends assume when no pipeline is
               given, and what the detection archive itself stores. A pipeline
               is needed only for a customer whose CloudTrail is normalised
               (Splunk CIM, ECS), and is then written once per schema rather
               than once per rule.
    backend    emits the query language.

Correlations are the honest limit. Sigma expresses "these events, in this
window, this many times" as a correlation document, and backend support for
them varies: the Splunk backend implements event_count and value_count but not
temporal_ordered, and the OpenSearch Lucene backend implements none. Those rules
are reported as skipped, with the reason, rather than failing the file — the
base rules in the same file still convert, and a caller that needs the
correlation can fall back the way sigma_eval.SigmaUnsupported already does.

Deliberately Django-free, like detections.py and sigma_eval.py beside it, so the
validator and the conversion CLI can import it without settings, a database or
AWS credentials. pySigma and its backends are imported lazily, so the module
stays importable in the runtime image, where they are not installed; calling
convert() without them raises BackendUnavailable with the install line.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any

import yaml


class BackendUnavailable(RuntimeError):
    """Raised when a target's pySigma backend is not installed."""


@dataclass(frozen=True)
class Target:
    """One conversion target: a backend class and how to describe it."""

    name: str
    label: str
    module: str
    class_name: str
    # Backend-specific output formats worth exposing. The first is the default
    # plain query form; the rest are deployable artefacts, e.g. a Splunk
    # savedsearches.conf stanza that can be dropped into an app.
    output_formats: tuple[str, ...] = ("default",)
    install: str = ""


TARGETS: dict[str, Target] = {
    "splunk": Target(
        name="splunk",
        label="Splunk (SPL)",
        module="sigma.backends.splunk",
        class_name="SplunkBackend",
        output_formats=("default", "savedsearches"),
        install="pySigma-backend-splunk",
    ),
    "opensearch": Target(
        name="opensearch",
        label="OpenSearch / Wazuh Indexer (Lucene)",
        module="sigma.backends.opensearch",
        class_name="OpensearchLuceneBackend",
        output_formats=("default", "dsl_lucene"),
        install="pySigma-backend-opensearch",
    ),
}


@dataclass(frozen=True)
class ConvertedQuery:
    """One rule, compiled for one target."""

    title: str
    rule_id: str
    query: str


@dataclass(frozen=True)
class SkippedRule:
    """A rule this target cannot express, and why."""

    title: str
    rule_id: str
    reason: str


@dataclass
class ConversionResult:
    """Everything one file produced for one target."""

    target: str
    queries: list[ConvertedQuery] = field(default_factory=list)
    skipped: list[SkippedRule] = field(default_factory=list)
    # Set when the file could not be compiled at all, as opposed to individual
    # rules being inexpressible. A caller gating a build should treat this, and
    # only this, as a failure.
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def available_targets() -> list[str]:
    """Target names whose backend is importable in this environment."""
    names = []
    for name, target in TARGETS.items():
        try:
            _backend_class(target)
        except BackendUnavailable:
            continue
        names.append(name)
    return names


def _backend_class(target: Target) -> Any:
    """Import a target's backend class, or explain how to install it."""
    try:
        module = importlib.import_module(target.module)
    except ImportError as exc:
        raise BackendUnavailable(
            f"{target.label} needs {target.install}: pip install {target.install}"
        ) from exc
    return getattr(module, target.class_name)


def _documents(text: str) -> list[dict]:
    """Parse a rule file into its non-empty YAML documents."""
    return [document for document in yaml.safe_load_all(text) if document]


def _dump(documents: list[dict]) -> str:
    """Render documents back to a multi-document YAML string for pySigma."""
    return "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in documents)


def _convert_documents(
    documents: list[dict], backend: Any, output_format: str
) -> tuple[list[str], list[Any]]:
    """
    Compile a document set, resolving correlation references first.

    Returns the queries and the rule objects they came from. The two are not
    always the same length: a base rule referenced by a correlation is folded
    into that correlation's query and emits nothing of its own, which is correct
    — such a rule is a building block, not a detection that should alert by
    itself. _pair() uses the rule objects to label output despite that.
    """
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml(_dump(documents))
    # from_yaml resolves references lazily, so a correlation naming a missing
    # rule would otherwise surface as a confusing error inside the backend.
    collection.resolve_rule_references()
    rules = list(collection.rules)
    if output_format and output_format != "default":
        rendered = backend.convert(collection, output_format=output_format)
        queries = [rendered] if isinstance(rendered, str) else [str(q) for q in rendered]
        return queries, rules
    return [str(query) for query in backend.convert(collection)], rules


def _identify(document: dict) -> tuple[str, str]:
    """Title and id for reporting, tolerant of an untitled document."""
    return str(document.get("title", "<untitled>")), str(document.get("id", ""))


def convert(
    text: str,
    target: str,
    output_format: str = "default",
    pipeline: Any = None,
) -> ConversionResult:
    """
    Compile one Sigma file for one target.

    The whole file is compiled in a single pass first, which is both faster and
    the only way a backend that *does* support correlations can emit them. Only
    when that fails does this fall back to compiling the base rules alone and
    re-attempting each correlation on its own, so one inexpressible correlation
    does not cost the file its other rules — and so the reason reported is the
    one that rule actually produced.

    On that fallback path a base rule can appear twice in spirit: once as its
    own query and once folded inside a correlation that survived. That is
    deliberate. A base rule is a valid standalone detection with its own title
    and level, and when the sibling correlation is the part this target cannot
    express, the standalone query is the only coverage left.

    Args:
        text: Contents of a sigma_*.yml file.
        target: A key of TARGETS.
        output_format: A member of that target's output_formats.
        pipeline: Optional pySigma ProcessingPipeline for a customer whose
            CloudTrail schema is normalised. None means raw CloudTrail fields.

    Returns:
        A ConversionResult. `error` is set only when nothing could be compiled.

    Raises:
        BackendUnavailable: the target's backend is not installed.
        KeyError: unknown target name.
    """
    spec = TARGETS[target]
    backend_class = _backend_class(spec)
    backend_args = {"processing_pipeline": pipeline} if pipeline is not None else {}
    result = ConversionResult(target=target)

    try:
        documents = _documents(text)
    except yaml.YAMLError as exc:
        result.error = f"YAMLError: {str(exc).splitlines()[0]}"
        return result

    if not documents:
        result.error = "file contains no YAML documents"
        return result

    base = [d for d in documents if not d.get("correlation")]
    correlations = [d for d in documents if d.get("correlation")]

    # Fast path: everything at once, correlations included.
    try:
        queries, rules = _convert_documents(
            documents, backend_class(**backend_args), output_format
        )
        result.queries = _pair(rules, queries)
        return result
    except Exception:
        pass

    if not base:
        result.error = "file has only correlation rules and this target supports none of them"
        return result

    try:
        base_queries, base_rules = _convert_documents(
            base, backend_class(**backend_args), output_format
        )
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {str(exc).splitlines()[0]}"
        return result

    result.queries = _pair(base_rules, base_queries)

    for document in correlations:
        title, rule_id = _identify(document)
        try:
            # Compiled alongside the base rules so its references resolve; the
            # queries beyond the base set are the correlation's own.
            combined, _ = _convert_documents(
                base + [document], backend_class(**backend_args), output_format
            )
            # Not a positional slice: a correlation folds the base rules it
            # references into its own query, so `combined` can be *shorter*
            # than the base-only output. The correlation's queries are the ones
            # that were not already produced by the base rules alone.
            extra = [query for query in combined if query not in base_queries]
            if not extra:
                raise RuntimeError("backend produced no query for this correlation")
            result.queries.extend(
                ConvertedQuery(title=title, rule_id=rule_id, query=query) for query in extra
            )
        except Exception as exc:
            reason = str(exc).splitlines()[0] if str(exc).strip() else type(exc).__name__
            result.skipped.append(SkippedRule(title=title, rule_id=rule_id, reason=reason))

    return result


def _pair(rules: list[Any], queries: list[str]) -> list[ConvertedQuery]:
    """
    Attach each query to the rule that produced it.

    Three cases, in order of confidence. One query per rule pairs positionally.
    Fewer queries than rules means base rules were folded into correlations, so
    the queries belong to the correlation rules. Anything else — a format like
    savedsearches that renders the whole collection as one artefact — is left
    unattributed rather than mislabelled.
    """
    if len(queries) == len(rules):
        return [
            ConvertedQuery(
                title=str(getattr(rule, "title", "") or ""),
                rule_id=str(getattr(rule, "id", "") or ""),
                query=query,
            )
            for rule, query in zip(rules, queries)
        ]

    correlations = [rule for rule in rules if _is_correlation(rule)]
    if len(queries) == len(correlations) and correlations:
        return [
            ConvertedQuery(
                title=str(getattr(rule, "title", "") or ""),
                rule_id=str(getattr(rule, "id", "") or ""),
                query=query,
            )
            for rule, query in zip(correlations, queries)
        ]

    return [ConvertedQuery(title="", rule_id="", query=query) for query in queries]


def _is_correlation(rule: Any) -> bool:
    """True for a pySigma correlation rule, without importing its class."""
    return type(rule).__name__ == "SigmaCorrelationRule"
