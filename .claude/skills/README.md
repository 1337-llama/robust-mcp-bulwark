# Vendored skills

`ponytail`, `ponytail-review`, `ponytail-audit`, and `ponytail-debt` are copied unchanged from [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) at commit `ebd8654` (MIT, see `PONYTAIL-LICENSE`). Only the skill files are vendored: no hooks, usage ledger, or webhook. These files are instructions every session loads, so treat them as supply chain: an update is a normal reviewed PR that copies the same four `skills/<name>/SKILL.md` files from a newer commit, shows the upstream diff in the PR description, and changes the commit above.
