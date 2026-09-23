"""Shared restricted-data matching and deterministic redaction primitives.

Authority-Core and the hybrid controller used to recognize overlapping security
facts through separate implementations. This module is now the canonical
primitive for the narrow benchmark semantics they actually share.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import quote, unquote

from sentinel.core.actions import CandidateAction
from sentinel.core.provenance import Sensitivity
from sentinel.defenses.baselines.common import squash
from sentinel.defenses.baselines.provenance import MIN_OVERLAP, overlaps
from sentinel.defenses.interface import DefenseRequest

_OPAQUE_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,}")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
_WORD = re.compile(r"\S+")
_REDACTION = "[REDACTED RESTRICTED VALUE]"


class FlowTransformation(StrEnum):
    PLAIN = "plain"
    BASE64 = "base64"
    HEX = "hex"
    URL = "url"
    ROT13 = "rot13"
    REVERSED = "reversed"


@dataclass(frozen=True)
class RestrictedRedaction:
    content: str
    source_digests: tuple[str, ...]
    replacements: int


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def opaque_tokens(text: str) -> set[str]:
    return {tok.lower() for tok in _OPAQUE_TOKEN.findall(text)}


def decoded_variants(text: str) -> list[str]:
    variants = [text]
    stripped = "".join(text.split())
    try:
        variants.append(base64.b64decode(stripped + "==", validate=False).decode("utf-8", "ignore"))
    except (binascii.Error, ValueError):
        pass
    if re.fullmatch(r"[0-9a-fA-F]{8,}", stripped):
        try:
            variants.append(bytes.fromhex(stripped).decode("utf-8", "ignore"))
        except ValueError:
            pass
    for run in _BASE64_RUN.findall(text):
        try:
            variants.append(base64.b64decode(run + "==", validate=False).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            pass
    variants.append(unquote(text))
    variants.append(codecs.decode(text, "rot13"))
    variants.append(text[::-1])
    return variants


def transformation_variants(atom: str, transformation: FlowTransformation) -> tuple[str, ...]:
    if transformation is FlowTransformation.PLAIN:
        variants = [atom]
    elif transformation is FlowTransformation.BASE64:
        encoded = base64.b64encode(atom.encode()).decode()
        variants = [encoded, encoded.rstrip("=")]
    elif transformation is FlowTransformation.HEX:
        variants = [atom.encode().hex()]
    elif transformation is FlowTransformation.URL:
        encoded = quote(atom, safe="")
        variants = [encoded] if encoded != atom else []
    elif transformation is FlowTransformation.ROT13:
        encoded = codecs.encode(atom, "rot13")
        variants = [encoded] if encoded != atom else []
    else:
        encoded = atom[::-1]
        variants = [encoded] if encoded != atom else []
    return tuple(dict.fromkeys(value for value in variants if value))


def match_transformation(atom: str, sink_text: str) -> FlowTransformation | None:
    for transformation in FlowTransformation:
        variants = transformation_variants(atom, transformation)
        if transformation is FlowTransformation.HEX:
            lowered = sink_text.lower()
            if any(variant.lower() in lowered for variant in variants):
                return transformation
        elif any(variant in sink_text for variant in variants):
            return transformation
    return None


def restricted_source_texts(request: DefenseRequest) -> tuple[str, ...]:
    records = {record.id: record.provenance for record in request.provenance}
    return tuple(
        item.content
        for item in request.conversation
        if any(
            records[pid].sensitivity is Sensitivity.RESTRICTED
            for pid in item.provenance_ids
            if pid in records
        )
    )


def restricted_payload_hit(
    request: DefenseRequest,
    action: CandidateAction,
    *,
    enable_encoded: bool,
) -> bool:
    sources = restricted_source_texts(request)
    if not sources:
        return False

    payload = action.text_payload()
    squashed_payload = squash(payload)
    opaque_hit = any(
        token in squashed_payload
        for source in sources
        for token in opaque_tokens(source)
    )
    return (
        opaque_hit
        or overlaps(payload, list(sources))
        or (
            enable_encoded
            and any(
                overlaps(variant, list(sources))
                for variant in decoded_variants(payload)
            )
        )
    )


def _replace_variant(text: str, variant: str, transformation: FlowTransformation) -> tuple[str, int]:
    if not variant:
        return text, 0
    if transformation is FlowTransformation.HEX:
        return re.subn(re.escape(variant), _REDACTION, text, flags=re.IGNORECASE)
    count = text.count(variant)
    return (text.replace(variant, _REDACTION), count) if count else (text, 0)


def _longest_verbatim_span(text: str, source: str) -> tuple[int, int] | None:
    tokens = list(_WORD.finditer(text))
    if not tokens:
        return None
    source_norm = squash(source)

    best: tuple[int, int, int] | None = None
    max_words = 24
    for start in range(len(tokens)):
        for end in range(start + 1, min(len(tokens), start + max_words) + 1):
            left = tokens[start].start()
            right = tokens[end - 1].end()
            normalized = squash(text[left:right])
            if len(normalized) < MIN_OVERLAP:
                continue
            if normalized in source_norm:
                score = len(normalized)
                if best is None or score > best[2]:
                    best = (left, right, score)

    if best is not None:
        return best[0], best[1]

    normalized = squash(text)
    if 12 <= len(normalized) < MIN_OVERLAP and normalized in source_norm:
        return 0, len(text)
    return None


def _encoded_run_overlap(run: str, sources: tuple[str, ...], *, hex_run: bool) -> bool:
    try:
        if hex_run:
            if len(run) % 2:
                return False
            decoded = bytes.fromhex(run).decode("utf-8", "ignore")
        else:
            decoded = base64.b64decode(run + "==", validate=False).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return False

    if not decoded:
        return False
    decoded_sq = squash(decoded)
    return any(
        overlaps(decoded, [source])
        or any(token in decoded_sq for token in opaque_tokens(source))
        for source in sources
    )


def redact_restricted_response(
    request: DefenseRequest,
    content: str,
    *,
    enable_encoded: bool = True,
    max_passes: int = 6,
) -> RestrictedRedaction | None:
    sources = restricted_source_texts(request)
    if not sources:
        return None

    current = content
    replacements = 0
    touched: list[str] = []

    for _ in range(max_passes):
        before_pass = current

        for source in sources:
            source_changed = 0
            for token in opaque_tokens(source):
                original_match = next(
                    (
                        raw
                        for raw in _OPAQUE_TOKEN.findall(source)
                        if raw.lower() == token
                    ),
                    token,
                )
                for transformation in FlowTransformation:
                    for variant in transformation_variants(original_match, transformation):
                        current, count = _replace_variant(current, variant, transformation)
                        source_changed += count

            if source_changed:
                replacements += source_changed
                touched.append(_digest(source))

        for source in sources:
            span = _longest_verbatim_span(current, source)
            if span is None:
                continue
            left, right = span
            current = current[:left] + _REDACTION + current[right:]
            replacements += 1
            touched.append(_digest(source))

        if enable_encoded:
            for match in list(_BASE64_RUN.finditer(current))[::-1]:
                run = match.group(0)
                if _encoded_run_overlap(run, sources, hex_run=False):
                    current = current[: match.start()] + _REDACTION + current[match.end() :]
                    replacements += 1
                    touched.extend(_digest(source) for source in sources)

            for match in list(_HEX_RUN.finditer(current))[::-1]:
                run = match.group(0)
                if _encoded_run_overlap(run, sources, hex_run=True):
                    current = current[: match.start()] + _REDACTION + current[match.end() :]
                    replacements += 1
                    touched.extend(_digest(source) for source in sources)

        if current == before_pass:
            break

    if not replacements or current == content:
        return None
    return RestrictedRedaction(
        content=current,
        source_digests=tuple(dict.fromkeys(touched)),
        replacements=replacements,
    )
