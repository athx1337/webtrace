# SPEC.md — Project Specification

> **Status**: `FINALIZED`

## Vision
TRACE is a full-stack domain intelligence platform that orchestrates concurrent analysis of URLs across DNS records, WHOIS domain data, SSL certificates, and threat intelligence engines, culminating in an AI-generated risk assessment. The frontend will provide a sleek, real-time OP_CENTER terminal interface.

## Goals
1. Wire the existing React frontend UI (`App.tsx`) to the completed FastAPI backend.
2. Implement dynamic fetching from `POST /api/analyze` and render the comprehensive JSON results in the UI cards.
3. Manage frontend loading, error, and empty states appropriately.
4. Ensure the frontend operates smoothly matching the design instructions in `frontend/README.md`.

## Non-Goals (Out of Scope)
- Modifying the Python backend (it is fully complete).
- Writing new backend analysis engines.

## Users
Security analysts, system administrators, and developers needing a quick, trustworthy assessment of a domain's risk profile.

## Constraints
- The backend expects `{"url": "domain.com"}` via POST on port 8000.
- The React app uses Vite and TailwindCSS on port 3000.
- CORS is already enabled on the backend for all origins.

## Success Criteria
- [ ] Submitting a URL in the UI correctly calls the FastAPI backend.
- [ ] The Trust Score dynamically updates based on the API response.
- [ ] AI explanation correctly renders.
- [ ] Engine results, Domain Info, and URL analysis reflect actual scanned data.
