# WADDLE threat modeling games

WADDLE is STRIDE with friendlier names: **W**rong identity (Spoofing), **A**lteration (Tampering), **D**isruption (Denial of Service), **D**enial (Repudiation), **L**eakage of information (Information Disclosure) and **E**levation of privilege.

| Folder | What it is |
|---|---|
| `v1/` | The original game: a mobile app data flow and WADDLE threats |
| `v2/` | The 2026 AI edition: OWASP Top 10 for LLM Apps and for Agentic Apps, each risk mapped to STRIDE and then to WADDLE. Two tracks, a plain-language scenario per node, three controls to choose from, and an explanation after each answer |

Live site: https://damooooooooooh.github.io/waddle-game/

## Run locally

    cd v2
    npm install
    npm run dev

## Deploy

Pushing to `master` runs `.github/workflows/deploy.yml`, which builds `v1` and `v2` and publishes them with a landing page.
One-time setup: repo **Settings → Pages → Source: GitHub Actions**.

Earlier iterations (the neon LLM edition with mini-games is tagged `v2-neon-llm-minigames`) are not part of this site.
