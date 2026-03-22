---
phase: 1
plan: 1
wave: 1
---

# Plan 1.1: Frontend Registration & Wiring

## Objective
Connect `App.tsx` input to fetch the `/api/analyze` endpoint.

## Context
- .gsd/SPEC.md
- .gsd/ARCHITECTURE.md
- frontend/src/App.tsx
- frontend/README.md

## Tasks

<task type="auto">
  <name>Wire frontend App.tsx to backend</name>
  <files>frontend/src/App.tsx</files>
  <action>
    - Add state for targetUrl, status, analysisData.
    - Export an `AnalyzeResponse` interface that defines the structure expected by the frontend based on the JSON response defined in `TRACE_BUILD_PLAN.md`.
    - Add an `analyzeUrl` async function that fires a POST request to `http://localhost:8000/api/analyze` containing the targetUrl state. 
    - Display loading/pulse indicators when processing.
    - Replace hardcoded Mock values in `App.tsx` with conditionally rendered text derived from `analysisData`. E.g., trust score (94.2), SSL data, Domain Info, URL Analysis, Engine Results, DNS, and AI Explanation.
    - Handle edge cases like empty inputs, invalid JSON returned, or server errors.
  </action>
  <verify>npm run build runs successfully inside frontend directory</verify>
  <done>Frontend dynamically renders API response mapped properly to UI components</done>
</task>

## Success Criteria
- [ ] Submitting a URL makes a POST request to the backend.
- [ ] Dashboard populates with dynamic JSON data and gracefully handles failure states.
