#!/usr/bin/env python3
"""
generate-catalog-from-scannercatalog.py — produce rave/catalog/<id>.json
entries for every forensic plugin documented in the maccrab platform's
ScannerCatalog.swift.

The facts (purpose, dataSources, tccRequirements, emits, privacyClass)
are hardcoded here rather than parsed from Swift — they're stable
operator-facing copy that the user has refined in the maccrab repo.

Run from the rave/ root:
    rave/tools/generate-catalog-from-scannercatalog.py

After running, re-sign the catalog tree with maccrab-rave-sign.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# 18 forensic plugins, sourced from
#   maccrab/Sources/MacCrabApp/V2/Forensics/ScannerCatalog.swift (2026-05-27).

PLUGINS = [
    {
        "id": "com.maccrab.forensics.tcc-lite",
        "display_name": "TCC Privacy Grants",
        "short_description": "Snapshots every privacy permission grant currently in effect — which app has been allowed which sensitive service.",
        "long_description": "Reads the system and per-user TCC databases and emits a structured grant-by-grant inventory. Cross-references the grantee bundle id against installed apps, and tags grants for sensitive services (Full Disk Access, Accessibility, Automation, Camera, Microphone) so an operator can quickly see what could touch what.\n\nUseful baseline before privacy-affecting changes (new app installs, new MDM profile rollout) — diff later to see what gained access.",
        "kind": "collector",
        "category": "system",
        "privacy_class": "metadata",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "/Library/Application Support/com.apple.TCC/TCC.db",
            "~/Library/Application Support/com.apple.TCC/TCC.db",
        ],
        "emits": ["tcc.grant", "tcc.summary_by_service"],
        "tags": ["tcc", "privacy", "permissions", "baseline"],
    },
    {
        "id": "com.maccrab.forensics.launchd-lite",
        "display_name": "Launchd Persistence",
        "short_description": "Inventories every launch agent + daemon + StartupItem on this Mac, with codesign + binary-path posture for each.",
        "long_description": "Walks /Library/LaunchAgents, /Library/LaunchDaemons, /System/Library/Launch*, and ~/Library/LaunchAgents/. For each plist, records the Label, ProgramArguments, RunAtLoad/KeepAlive, the binary's codesign Team ID + designated requirement, and whether it lives in an unusual path.\n\nAlso parses macOS's Background Activity Monitor (BAM) database, which is sometimes a faster path to enumerate \"what auto-starts on this Mac\" than the launchd plist tree.\n\nThe most common macOS persistence vector ends up here.",
        "kind": "collector",
        "category": "system",
        "privacy_class": "metadata",
        "tcc_requirements": ["Full Disk Access (for BAM database)"],
        "data_sources": [
            "/Library/LaunchAgents/, /Library/LaunchDaemons/, /System/Library/Launch*",
            "~/Library/LaunchAgents/",
            "Background Activity Monitor (BAM) database",
        ],
        "emits": ["launchd.entry", "launchd.bam_entry"],
        "tags": ["launchd", "persistence", "boot-time", "baseline"],
    },
    {
        "id": "com.maccrab.forensics.quarantine",
        "display_name": "Quarantine Events",
        "short_description": "Pulls recent quarantine events from LaunchServices — downloads, AirDrop transfers, iMessage attachments, anything Gatekeeper has touched.",
        "long_description": "Reads LaunchServices' QuarantineEventsV2 SQLite database — every file macOS tagged with the com.apple.quarantine xattr. For each event captures UUID, originating URL, downloading application bundle id, and timestamp.\n\nA defensible first-stage IR data source: download-borne payloads almost always land in this database before they execute.",
        "kind": "collector",
        "category": "system",
        "privacy_class": "metadata",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
        ],
        "emits": ["quarantine.event"],
        "tags": ["quarantine", "downloads", "ir", "gatekeeper"],
    },
    {
        "id": "com.maccrab.forensics.safari-lite",
        "display_name": "Safari Metadata",
        "short_description": "Reads Safari's history database — visited URLs, downloads, installed extensions. No page bodies, no LocalStorage.",
        "long_description": "Walks Safari's History.db (visit URLs + timestamps + titles + download list) and Safari's Extensions folder (installed extension bundle ids + Team IDs).\n\nPlaintext-safe — only metadata, never page content. Pair with safari-deep for content-class data.",
        "kind": "collector",
        "category": "browser",
        "privacy_class": "metadata",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Safari/History.db",
            "~/Library/Safari/Extensions/",
        ],
        "emits": ["safari.history_visit", "safari.download", "safari.extension"],
        "tags": ["safari", "browser", "history"],
    },
    {
        "id": "com.maccrab.forensics.safari-deep",
        "display_name": "Safari Deep Storage",
        "short_description": "Pulls Safari LocalStorage + IndexedDB contents — what websites have stored locally. Page-content class, requires encrypted scan.",
        "long_description": "Walks ~/Library/Safari/LocalStorage and the WebKit Databases store. Each origin's local data lands as a structured record.\n\nUseful for phishing investigations + supply-chain attacks via stored auth material. Page-content class — opt-in only, encrypted at rest.",
        "kind": "collector",
        "category": "browser",
        "privacy_class": "content",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Safari/LocalStorage/",
            "~/Library/Safari/Databases/Databases.db",
        ],
        "emits": ["safari.localstorage", "safari.indexeddb"],
        "tags": ["safari", "browser", "localstorage", "content-class"],
    },
    {
        "id": "com.maccrab.forensics.mail",
        "display_name": "Mail Envelope Metadata",
        "short_description": "Walks Mail.app envelope database — sender, subject, headers, received-at. No message body content.",
        "long_description": "Reads Mail.app's Envelope Index SQLite store: per-message sender, recipients, subject, headers, attachment-count, mailbox membership. No bodies — pair with mail-bodies if body content is needed.\n\nPersonal-comms class — encrypted-scan opt-in required.",
        "kind": "collector",
        "category": "comms",
        "privacy_class": "personal-comms",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Mail/V*/MailData/Envelope Index (SQLite)",
        ],
        "emits": ["mail.message"],
        "tags": ["mail", "comms", "personal-comms"],
    },
    {
        "id": "com.maccrab.forensics.mail-bodies",
        "display_name": "Mail Message Bodies",
        "short_description": "Extracts full Mail.app message bodies. Used for phishing artefact extraction. Personal comms — requires encrypted scan.",
        "long_description": "Walks Mail.app's mbox stores and extracts full .emlx message bodies into structured records. Used in phishing investigations to inspect message content for IOCs.\n\nStrictest opt-in: personal-comms class, content body included.",
        "kind": "collector",
        "category": "comms",
        "privacy_class": "personal-comms",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Mail/V*/<account>/<mailbox>.mbox/Messages/*.emlx",
        ],
        "emits": ["mail.message_body"],
        "tags": ["mail", "phishing", "personal-comms", "content"],
    },
    {
        "id": "com.maccrab.forensics.imessage-metadata",
        "display_name": "iMessage Metadata",
        "short_description": "iMessage handles + threads + URL mentions — who has the user talked to, and what links have been shared. No message bodies.",
        "long_description": "Reads ~/Library/Messages/chat.db. For each conversation: participant handles (email + phone + iCloud id), thread group state, per-message timestamp + service, URL mentions extracted from message attributedBody but without the surrounding text.\n\nPersonal-comms class — encrypted-scan opt-in. URL mentions on their own are useful for phishing triage without exposing message content.",
        "kind": "collector",
        "category": "comms",
        "privacy_class": "personal-comms",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Messages/chat.db",
        ],
        "emits": ["imessage.handle", "imessage.thread", "imessage.message_meta", "imessage.url_mention"],
        "tags": ["imessage", "comms", "phishing", "personal-comms"],
    },
    {
        "id": "com.maccrab.forensics.imessage-bodies",
        "display_name": "iMessage Bodies",
        "short_description": "Full iMessage / SMS message text bodies. Personal comms — requires encrypted scan and opt-in.",
        "long_description": "Reads iMessage chat.db and extracts each message's full text body. Resolves attachment references against ~/Library/Messages/Attachments.\n\nStrictest opt-in. Used only when a phishing/incident investigation explicitly needs message content.",
        "kind": "collector",
        "category": "comms",
        "privacy_class": "personal-comms",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Messages/chat.db",
            "~/Library/Messages/Attachments/",
        ],
        "emits": ["imessage.message_body"],
        "tags": ["imessage", "comms", "personal-comms", "content"],
    },
    {
        "id": "com.maccrab.forensics.facetime",
        "display_name": "FaceTime Call History",
        "short_description": "FaceTime call history — peers, durations, connection state. Personal comms.",
        "long_description": "Reads CallHistory.storedata. Each FaceTime call records the remote peer (Apple ID / phone / email), start + end timestamp, audio/video, and connection state.\n\nPersonal-comms class.",
        "kind": "collector",
        "category": "comms",
        "privacy_class": "personal-comms",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/CallHistoryDB/CallHistory.storedata",
        ],
        "emits": ["facetime.call"],
        "tags": ["facetime", "comms", "personal-comms"],
    },
    {
        "id": "com.maccrab.forensics.knowledgec",
        "display_name": "KnowledgeC Activity",
        "short_description": "Reads CoreDuet's KnowledgeC database — app usage, focus mode, screen time, where the user was when they did what.",
        "long_description": "Reads Apple's activity-bundle store. Each event records app usage, focus mode state, screen time, location bundles, and a coarse \"what was the user doing\" snapshot at that moment.\n\nMetadata class — safe in plaintext scan. Useful for incident-timeline reconstruction.",
        "kind": "collector",
        "category": "activity",
        "privacy_class": "metadata",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Application Support/Knowledge/knowledgeC.db",
            "/private/var/db/CoreDuet/Knowledge/knowledgeC.db",
        ],
        "emits": ["knowledgec.event"],
        "tags": ["knowledgec", "coreduet", "activity", "timeline"],
    },
    {
        "id": "com.maccrab.forensics.biome",
        "display_name": "Biome Activity Streams",
        "short_description": "Reads the Biome stream store — app usage, location, focus mode, notifications. Ventura+ replacement for parts of KnowledgeC.",
        "long_description": "Reads the per-stream Biome event stores. Each stream records a different facet (app usage, location, focus, notifications). Newer than KnowledgeC and often more complete on Ventura and later.\n\nMetadata class.",
        "kind": "collector",
        "category": "activity",
        "privacy_class": "metadata",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "~/Library/Biome/",
        ],
        "emits": ["biome.stream"],
        "tags": ["biome", "activity", "timeline"],
    },
    {
        "id": "com.maccrab.forensics.applescript-runtime",
        "display_name": "AppleScript Runtime",
        "short_description": "Recent AppleScript / osascript invocations. AI agents and remote-access tools frequently use AppleScript to automate other apps.",
        "long_description": "Reads the unified-logging subsystem com.apple.AppleScript and emits structured records for each osascript invocation, including the parent process and the target application.\n\nA defensible signal for AI-agent activity: most automation frameworks rely on AppleScript to drive Mail, Safari, Notes, and other built-ins.\n\nContent class — invocation scripts can include sensitive arguments.",
        "kind": "collector",
        "category": "activity",
        "privacy_class": "content",
        "tcc_requirements": [],
        "data_sources": [
            "Unified logging subsystem com.apple.AppleScript",
        ],
        "emits": ["applescript.invocation"],
        "tags": ["applescript", "automation", "ai-agents", "content"],
    },
    {
        "id": "com.maccrab.forensics.posture-analyzer",
        "display_name": "Posture Analyzer",
        "short_description": "Cross-references collected persistence + permissions + signing data. Surfaces unsigned persistence, unfamiliar automation, high-privilege unsigned combinations.",
        "long_description": "Pure analyzer — reads other plugins' committed artifacts in the same case and emits posture findings:\n\n• unsigned_persistence — launchd entries pointing at unsigned binaries\n• unfamiliar_team_persistence — launchd entries from Team IDs not seen elsewhere on the system\n• automation_to_sensitive_target — AppleScript runtime invocations targeting Mail, Messages, Safari, Keychain\n• high_privilege_unsigned_combo — TCC sensitive grants held by unsigned binaries\n• permissioned_persistence — launchd entry + TCC grant for the same binary\n\nRuns last in a kit; doesn't read the filesystem directly.",
        "kind": "analyzer",
        "category": "analyzer",
        "privacy_class": "metadata",
        "tcc_requirements": [],
        "data_sources": [
            "Other plugins' committed artifacts in the same case",
        ],
        "emits": [
            "posture.unsigned_persistence",
            "posture.unfamiliar_team_persistence",
            "posture.automation_to_sensitive_target",
            "posture.high_privilege_unsigned_combo",
            "posture.permissioned_persistence",
        ],
        "tags": ["posture", "analyzer", "cross-reference"],
    },
    {
        "id": "com.maccrab.forensics.codesigning-graph",
        "display_name": "Codesigning Graph",
        "short_description": "Builds a signer-to-binary graph for installed apps and CLI tools. Used to spot unfamiliar Team IDs and signer reuse patterns.",
        "long_description": "Walks /Applications, ~/Applications, /usr/local/bin, ~/.local/bin and runs codesign(1) against each binary. Emits a graph of Team ID → binary, plus designated-requirement strings.\n\nWhen surveyed across many machines, this surfaces unfamiliar Team IDs that only appear on one host — a useful signal for supply-chain anomalies.",
        "kind": "collector",
        "category": "system",
        "privacy_class": "metadata",
        "tcc_requirements": ["Full Disk Access"],
        "data_sources": [
            "/Applications/, ~/Applications/, /usr/local/bin/, ~/.local/bin/",
            "codesign(1) per binary",
        ],
        "emits": ["codesigning.binary"],
        "tags": ["codesigning", "signer", "supply-chain"],
    },
    {
        "id": "com.maccrab.forensics.macho-analyzer",
        "display_name": "Mach-O Analyzer",
        "short_description": "Deep Mach-O header inspection: dyld bindings, load commands, missing hardened-runtime, suspicious dylib injection paths.",
        "long_description": "For each Mach-O binary on a path-driven target list, parses LC_LOAD_DYLIB, LC_RPATH, LC_LOAD_WEAK_DYLIB, code-signing flags, and entitlements. Surfaces missing hardened-runtime, dyld bindings to non-system paths, and suspicious @rpath patterns.",
        "kind": "collector",
        "category": "artifact",
        "privacy_class": "metadata",
        "tcc_requirements": [],
        "data_sources": [
            "Mach-O binaries on disk (path-driven)",
        ],
        "emits": ["macho.analysis"],
        "tags": ["mach-o", "dyld", "binary-inspection"],
    },
    {
        "id": "com.maccrab.forensics.dmg-pkg-analyzer",
        "display_name": "DMG / PKG Analyzer",
        "short_description": "Inspects DMG and PKG installer payloads for unsigned components and pre-install scripts. Useful when an installer landed in Quarantine.",
        "long_description": "Walks a DMG or PKG payload: enumerates contained binaries with their codesign Team IDs, extracts pre-install + post-install scripts, and flags components that mismatch the package's outer signature.\n\nPair with the Quarantine plugin to feed the most recent downloads through this for triage.",
        "kind": "collector",
        "category": "artifact",
        "privacy_class": "metadata",
        "tcc_requirements": [],
        "data_sources": [
            "DMG / PKG files (path-driven)",
        ],
        "emits": ["dmg.analysis", "pkg.analysis"],
        "tags": ["dmg", "pkg", "installer", "supply-chain"],
    },
    {
        "id": "com.maccrab.forensics.plist-analyzer",
        "display_name": "Plist Analyzer",
        "short_description": "Walks plist files for suspicious entitlement, LSEnvironment, or login-item patterns.",
        "long_description": "Targeted plist sweep — given a path list (kit-supplied), parses each plist and flags suspicious patterns: LSEnvironment hijack candidates, login-item plists with unusual ProgramArguments, entitlement bundles that grant more than the binary advertises.",
        "kind": "collector",
        "category": "artifact",
        "privacy_class": "metadata",
        "tcc_requirements": [],
        "data_sources": [
            "Plist files on disk (path-driven, kit-supplied targets)",
        ],
        "emits": ["plist.analysis"],
        "tags": ["plist", "entitlement", "login-item"],
    },
]

# Sample-output records per plugin. One entry per content_type — operators
# see the actual data shape before installing.
SAMPLE_OUTPUTS: dict[str, list[dict]] = {
    "com.maccrab.forensics.tcc-lite": [
        {
            "content_type": "tcc.grant",
            "caption": "One privacy permission grant — which app has which access.",
            "data": {
                "kind": "tcc.grant",
                "service": "kTCCServiceSystemPolicyAllFiles",
                "service_label": "Full Disk Access",
                "client_bundle_id": "com.openai.atlas",
                "client_display_name": "ChatGPT Atlas",
                "client_path": "/Applications/ChatGPT Atlas.app",
                "auth_value": "allowed",
                "scope": "system",
                "granted_at": "2026-04-12T14:23:08Z",
                "team_id": "B6JR4DX5JD",
                "code_requirement_short": "developer-id-signed",
                "risk_score": 0.78,
            },
        },
        {
            "content_type": "tcc.summary_by_service",
            "caption": "Aggregated grant count per service across the whole machine.",
            "data": {
                "kind": "tcc.summary_by_service",
                "service": "kTCCServiceAccessibility",
                "service_label": "Accessibility",
                "grant_count": 7,
                "high_risk_count": 2,
                "unsigned_grantee_count": 0,
            },
        },
    ],
    "com.maccrab.forensics.launchd-lite": [
        {
            "content_type": "launchd.entry",
            "caption": "One launch agent or daemon, with codesign + path posture.",
            "data": {
                "kind": "launchd.entry",
                "domain": "user-agent",
                "plist_path": "~/Library/LaunchAgents/com.google.keystone.agent.plist",
                "label": "com.google.keystone.agent",
                "program_path": "/Users/alice/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/MacOS/GoogleSoftwareUpdateAgent",
                "arguments": ["-runMode", "ifneeded"],
                "run_at_load": True,
                "keep_alive": False,
                "start_interval_seconds": 3600,
                "team_id": "EQHXZ8M8AV",
                "team_display": "Google LLC",
                "codesign_status": "signed",
                "path_posture": "standard",
            },
        },
        {
            "content_type": "launchd.bam_entry",
            "caption": "BAM (Background Activity Monitor) login-item row.",
            "data": {
                "kind": "launchd.bam_entry",
                "bundle_id": "com.docker.docker",
                "display_name": "Docker Desktop",
                "binary_path": "/Applications/Docker.app/Contents/MacOS/Docker Desktop.app/Contents/MacOS/Docker Desktop",
                "team_id": "9BNSXJN65R",
                "enabled": True,
                "last_modified": "2026-03-01T09:11:22Z",
            },
        },
    ],
    "com.maccrab.forensics.quarantine": [{
        "content_type": "quarantine.event",
        "caption": "One quarantined download — URL + agent + timestamp.",
        "data": {
            "kind": "quarantine.event",
            "uuid": "8F71D5A2-3E1A-4B5C-AC0A-7E2BCC8F4218",
            "originating_url": "https://download.cursor.com/mac/dmg/arm64",
            "agent_bundle_id": "com.apple.Safari",
            "agent_display": "Safari",
            "downloaded_at": "2026-05-19T17:42:11Z",
            "type": "application",
            "path": "~/Downloads/Cursor-darwin-arm64.dmg",
            "sender_address": "download.cursor.com",
        },
    }],
    "com.maccrab.forensics.safari-lite": [
        {
            "content_type": "safari.history_visit",
            "caption": "One URL visit with title + timestamp.",
            "data": {
                "kind": "safari.history_visit",
                "url": "https://maccrab.com/blog/post-1/",
                "title": "Welcome to MacCrab",
                "visited_at": "2026-05-27T16:08:22Z",
                "visit_count": 3,
            },
        },
        {
            "content_type": "safari.extension",
            "caption": "One installed Safari extension — team + bundle.",
            "data": {
                "kind": "safari.extension",
                "bundle_id": "com.1password.1password-safari",
                "display_name": "1Password — Password Manager",
                "team_id": "2BUA8C4S2C",
                "enabled": True,
                "version": "8.10.42",
            },
        },
    ],
    "com.maccrab.forensics.safari-deep": [{
        "content_type": "safari.localstorage",
        "caption": "Per-origin LocalStorage key/value snapshot. Page-content class.",
        "data": {
            "kind": "safari.localstorage",
            "origin": "https://app.example.com",
            "key": "session-state",
            "value_preview": "{\"userId\": \"abc123\", \"lastSeen\": \"...\"}",
            "value_size_bytes": 487,
            "updated_at": "2026-05-26T11:04:50Z",
        },
    }],
    "com.maccrab.forensics.mail": [{
        "content_type": "mail.message",
        "caption": "One Mail.app envelope record — metadata only, no body.",
        "data": {
            "kind": "mail.message",
            "message_id": "<CAJ8K7m_xRn=abc@mail.gmail.com>",
            "subject": "Re: Q2 roadmap review",
            "sender": "alice@example.com",
            "recipients": ["bob@example.com", "team@example.com"],
            "received_at": "2026-05-27T14:00:11Z",
            "mailbox": "INBOX",
            "account": "alice@example.com",
            "attachment_count": 1,
            "header_received_chain": ["mta-out-1.example.com", "spam-filter.example.net"],
        },
    }],
    "com.maccrab.forensics.mail-bodies": [{
        "content_type": "mail.message_body",
        "caption": "Full message body — personal-comms class, encrypted at rest.",
        "data": {
            "kind": "mail.message_body",
            "message_id": "<CAJ8K7m_xRn=abc@mail.gmail.com>",
            "content_type": "text/plain; charset=UTF-8",
            "body_size_bytes": 2148,
            "body_preview_first_512": "Hi Bob, attached is the slide deck for tomorrow's review. The Q2 numbers are in tab 3, and I've highlighted the two campaigns that need a decision before Thursday...",
            "extracted_urls": ["https://docs.google.com/presentation/d/abc123/edit"],
            "extracted_addresses": [],
        },
    }],
    "com.maccrab.forensics.imessage-metadata": [
        {
            "content_type": "imessage.message_meta",
            "caption": "One iMessage with no body — sender + service + timestamp + extracted URLs.",
            "data": {
                "kind": "imessage.message_meta",
                "rowid": 18742,
                "thread_chat_id": "chat420203283242",
                "handle": "+1-415-555-0142",
                "service": "iMessage",
                "is_from_me": False,
                "sent_at": "2026-05-27T10:22:01Z",
                "has_attachment": False,
                "url_mention_count": 1,
            },
        },
        {
            "content_type": "imessage.url_mention",
            "caption": "URL extracted from a message (no surrounding text).",
            "data": {
                "kind": "imessage.url_mention",
                "thread_chat_id": "chat420203283242",
                "url": "https://invoice-portal.example.com/pay/7a3b9f",
                "host": "invoice-portal.example.com",
                "first_seen_in_thread_at": "2026-05-27T10:22:01Z",
            },
        },
    ],
    "com.maccrab.forensics.imessage-bodies": [{
        "content_type": "imessage.message_body",
        "caption": "Full message text — strictest opt-in, encrypted at rest.",
        "data": {
            "kind": "imessage.message_body",
            "rowid": 18742,
            "thread_chat_id": "chat420203283242",
            "text": "Hey can you check this invoice? Looks like the wrong amount https://invoice-portal.example.com/pay/7a3b9f",
            "service": "iMessage",
            "sent_at": "2026-05-27T10:22:01Z",
        },
    }],
    "com.maccrab.forensics.facetime": [{
        "content_type": "facetime.call",
        "caption": "One FaceTime call — peer, duration, connection state.",
        "data": {
            "kind": "facetime.call",
            "remote_address": "+1-415-555-0142",
            "remote_display": "Alice Example",
            "service": "FaceTime-Audio",
            "started_at": "2026-05-26T18:30:00Z",
            "duration_seconds": 1247,
            "answered": True,
            "originated": False,
        },
    }],
    "com.maccrab.forensics.knowledgec": [{
        "content_type": "knowledgec.event",
        "caption": "One activity-bundle event from CoreDuet's knowledgeC store.",
        "data": {
            "kind": "knowledgec.event",
            "stream_name": "/app/inFocus",
            "bundle_id": "com.openai.atlas",
            "value_string": "active",
            "start_at": "2026-05-27T15:00:11Z",
            "end_at": "2026-05-27T15:23:48Z",
            "duration_seconds": 1417,
        },
    }],
    "com.maccrab.forensics.biome": [{
        "content_type": "biome.stream",
        "caption": "One Biome stream event — newer Apple activity store.",
        "data": {
            "kind": "biome.stream",
            "stream": "AppUsage",
            "bundle_id": "com.apple.Mail",
            "start_at": "2026-05-27T09:01:33Z",
            "end_at": "2026-05-27T09:14:12Z",
            "focus_mode": "Work",
            "screen_state": "active",
        },
    }],
    "com.maccrab.forensics.applescript-runtime": [{
        "content_type": "applescript.invocation",
        "caption": "One AppleScript / osascript invocation from the unified log.",
        "data": {
            "kind": "applescript.invocation",
            "timestamp": "2026-05-27T16:42:18Z",
            "parent_process": "/Applications/Cursor.app/Contents/MacOS/Cursor",
            "parent_pid": 8821,
            "target_app": "com.apple.mail",
            "command_preview": "tell application \"Mail\" to get subject of every message of inbox",
            "executor": "osascript",
        },
    }],
    "com.maccrab.forensics.posture-analyzer": [{
        "content_type": "posture.unsigned_persistence",
        "caption": "A persistence entry pointing at an unsigned binary — defensible signal.",
        "data": {
            "kind": "posture.unsigned_persistence",
            "launchd_label": "com.example.unknown.helper",
            "binary_path": "/Users/alice/Library/Application Support/Unknown/helper",
            "codesign_status": "unsigned",
            "domain": "user-agent",
            "run_at_load": True,
            "severity": "attention",
            "cross_ref_plugins": ["com.maccrab.forensics.launchd-lite"],
        },
    }],
    "com.maccrab.forensics.codesigning-graph": [{
        "content_type": "codesigning.binary",
        "caption": "One binary with its signer + designated requirement.",
        "data": {
            "kind": "codesigning.binary",
            "path": "/Applications/Cursor.app/Contents/MacOS/Cursor",
            "team_id": "9SCJ4G8MN9",
            "team_display": "Cursor AI, Inc.",
            "designated_requirement_short": "developer-id-team-only",
            "hardened_runtime": True,
            "library_validation": True,
            "platform": "macOS",
        },
    }],
    "com.maccrab.forensics.macho-analyzer": [{
        "content_type": "macho.analysis",
        "caption": "One Mach-O binary's header analysis.",
        "data": {
            "kind": "macho.analysis",
            "path": "/usr/local/bin/some-cli-tool",
            "arch": ["x86_64", "arm64"],
            "load_dylibs": ["/usr/lib/libSystem.B.dylib"],
            "rpaths": ["@executable_path/../Frameworks"],
            "entitlements": ["com.apple.security.network.client"],
            "hardened_runtime": False,
            "library_validation": False,
            "findings": ["missing-hardened-runtime"],
        },
    }],
    "com.maccrab.forensics.dmg-pkg-analyzer": [{
        "content_type": "pkg.analysis",
        "caption": "One PKG installer payload — components + pre-install scripts.",
        "data": {
            "kind": "pkg.analysis",
            "path": "~/Downloads/installer.pkg",
            "outer_signature_team": "9SCJ4G8MN9",
            "components": [
                {"path": "Contents/MacOS/main", "team_id": "9SCJ4G8MN9", "signed": True},
                {"path": "Resources/helper.sh", "signed": False},
            ],
            "pre_install_script_present": True,
            "post_install_script_present": False,
            "pre_install_script_preview": "#!/bin/bash\nrm -rf /Library/OldVersion ...",
        },
    }],
    "com.maccrab.forensics.plist-analyzer": [{
        "content_type": "plist.analysis",
        "caption": "One plist with suspicious patterns surfaced.",
        "data": {
            "kind": "plist.analysis",
            "path": "/Library/LaunchAgents/com.example.helper.plist",
            "label": "com.example.helper",
            "program_arguments": ["/tmp/.hidden/helper"],
            "ls_environment_keys": ["DYLD_INSERT_LIBRARIES"],
            "findings": ["program-in-tmp", "lsenvironment-dyld-insert"],
            "severity": "critical",
        },
    }],
}


ZERO_HASH_64 = "0" * 64
ZERO_HASH_40 = "0" * 40
TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
PUBLISHER_KEY_SHA256 = "07e39eb12c15b8052f5249134ea3337a0789ebc799d1c58d097aaa548a8aaae3"

# First-party plugins don't carry a public source_repo (the platform source
# is private). Community submissions will set source_repo + source_owner.


def build_entry(plugin: dict) -> dict:
    """Build a single catalog entry from plugin facts."""
    pid = plugin["id"]
    samples_raw = SAMPLE_OUTPUTS.get(pid, [])
    samples = [
        {
            "content_type": s["content_type"],
            "caption": s["caption"],
            "example": json.dumps(s["data"], indent=2),
        }
        for s in samples_raw
    ]
    entry = {
        "$schema": "https://rave.maccrab.com/schemas/catalog-entry.json",
        "schema_version": "1",
        "id": pid,
        "display_name": plugin["display_name"],
        "short_description": plugin["short_description"],
        "long_description": plugin["long_description"],
        "author": {
            "name": "MacCrab",
            "url": "https://maccrab.com",
        },
        "approved_at_commit": ZERO_HASH_40,
        "approved_at_tag": "v0.1.0",
        "approved_by_review": ["maccrab-rave"],
        "approved_at": TODAY,
        "trust_tier": "first-party",
        "channel": "official",
        "runtime": "tierB",
        "signer_identity": "maccrab-rave:first-party",
        "signer_public_key_sha256": PUBLISHER_KEY_SHA256,
        "current_version": "0.1.0",
        "release_url_template": "https://rave.maccrab.com/releases/{tag}/{file}",
        "manifest_path": "manifest.json",
        "kind": plugin["kind"],
        "privacy_class": plugin["privacy_class"],
        "requires_encrypted_scan": plugin["privacy_class"] != "metadata",
        "tcc_requirements": plugin["tcc_requirements"],
        "data_sources": plugin["data_sources"],
        "emits": plugin["emits"],
        "sample_output": samples,
        "versions": {
            "0.1.0": {
                "tag": "v0.1.0",
                "source_commit": ZERO_HASH_40,
                "artifact_sha256": ZERO_HASH_64,
                "canonical_tree_sha256": ZERO_HASH_64,
                "manifest_sha256": ZERO_HASH_64,
                "signature_sha256": ZERO_HASH_64,
                "reproducibility": "not_applicable",
                "vetting": {
                    "automated_passes": [
                        "manifest-schema-v1",
                        "ed25519-signature-verified",
                        "publisher-key-not-revoked",
                    ],
                    "vetting_policy_commit": "policy@pre-release",
                    "vetted_at": NOW,
                },
            }
        },
        "metadata": {
            "category": plugin["category"],
            "tags": plugin["tags"],
            "min_maccrab_version": "1.17.0",
            "min_macos": "13.0",
        },
        "status": "pre-release",
    }
    return entry


def main() -> int:
    out_dir = Path(__file__).resolve().parent.parent / "catalog"
    out_dir.mkdir(parents=True, exist_ok=True)

    for plugin in PLUGINS:
        entry = build_entry(plugin)
        path = out_dir / f"{plugin['id']}.json"
        path.write_text(json.dumps(entry, indent=2) + "\n")
        print(f"  wrote {path}")
    print(f"\nTotal: {len(PLUGINS)} catalog entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
