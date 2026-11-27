# LAB ONLY: attack lab servers

Every package here is an **intentionally malicious, harmless** MCP server used only by the test suite (DESIGN.md §5.9, CLAUDE.md hard rule 4). Each one uses fake canary secrets, reads fixtures only inside its run directory, records "exfiltrated" data only to a local observation log, and makes no network calls. `bulwark-lab` refuses to start without `BULWARK_LAB=1`.

Each server's `payload.txt` holds its frozen attack text (spec 004 AC-20). Payload files are plain ASCII and carry no banner of their own, because this README covers them; they are never edited to fit the detection rules.
