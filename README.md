# EFA Phase 2 — Phishing Pattern Detection Engine

## Status: In Development (Pre-Integration)

This repo contains the Phase 2 phishing detection engine for Email Fraud Alert.
These files are **standalone** and do NOT modify any existing EFA production code.

## Architecture

Phase 2 is a deterministic combinatorial pattern engine that detects high-confidence
phishing attacks by requiring **multiple signals** to fire before showing a warning.
No single signal triggers a Phase 2 warning.

## File Structure

```
src/
  phase2-constants.js    - Signal keywords, domain lists, configuration
  phase2-signals.js      - Individual signal detection functions
  phase2-patterns.js     - Five deterministic pattern evaluators
  phase2-engine.js       - Orchestrator, suppression, merged warning, telemetry
```

## The Five Patterns

- **Pattern A** — Credential Harvesting (fake login traps)
- **Pattern B** — Brand Impersonation + Free Hosting Link
- **Pattern C** — HTML Attachment Trap (secure message scams)
- **Pattern D** — Dangerous Attachment Delivery (encrypted/protected files)
- **Pattern E** — Payment Redirect / BEC (wire change attempts)

## Integration

When ready, these functions are inserted into the existing taskpane.js (Outlook)
and content.js (Chrome) as **additive blocks only**. Nothing existing changes.

## Design Docs

Architecture designed by The Amigos (Journey + Claude + ChatGPT).
See conversation history for full spec, suppression mapping, and telemetry schema.
