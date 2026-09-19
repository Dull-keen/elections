Assume that all users are bilingual in Russian and English. Always use Russian in READMEs and plots, prefer mostly English in comments and internal docs. Use concise and informal language.

Make the repository AI-friendly and easily reproducible. There should be comments next to code sufficiently explaining its usage and pitfalls. In README docs, assume that the user is non-expert and possibly even non-tecnical.

Do not modify project root README.

Before committing any scripts, make them cross-platform: they should always run on Linux and in principle on Mac and Windows (possibly via WSL or some compatibility layer; prefer Python over bash), but do not go extreme lengths to achieve it and do not bother with cross-platform testing (the user-side AI can make some adjustments of its own).

Do not write down and commit credentials (such as passwords), private conversations (exported chat messages) and sensitive security information (leave it in agent session for responsible disclosure).

Prefer standard Python data stack for analysis.

Point out any anomalies you find.

When updating data during live elections, do quick regression tests against older data and general statistics available on the internet.

All raw data is in data/ along with reproduction steps. Do not overwrite existing data, only read it.

Use Moscow time (GMT+3).
