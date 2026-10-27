# Issue tracker: GitHub

Issues and specs live in `Adam-Goss/death-demos` on GitHub. Use `gh` for issue operations. The Git remote `origin` points to this repository; specify `--repo Adam-Goss/death-demos` on each command for clarity.

## Conventions

- Create: `gh issue create --repo Adam-Goss/death-demos --title "..." --body-file <file>`.
- Read: `gh issue view <number> --repo Adam-Goss/death-demos --json number,title,body,labels,comments`.
- List: `gh issue list --repo Adam-Goss/death-demos --state open --json number,title,body,labels,comments`.
- Comment: `gh issue comment <number> --repo Adam-Goss/death-demos --body-file <file>`.
- Label: `gh issue edit <number> --repo Adam-Goss/death-demos --add-label "..."` or `--remove-label "..."`.
- Close: `gh issue close <number> --repo Adam-Goss/death-demos`.

When a skill says to publish to the issue tracker, create a GitHub issue. When it says to fetch a ticket, read that issue.

## Pull requests as a triage surface

**PRs as a request surface: no.** Change this to `yes` if external PRs should enter the triage queue.

## Wayfinding

The map is a GitHub issue labelled `wayfinder:map`; tickets are child issues labelled `wayfinder:<type>` (`research`, `prototype`, `grilling`, or `task`). Use GitHub sub-issues where available; otherwise link children in the map and put `Part of #<map>` in each child.

Record blockers with GitHub issue dependencies where available; otherwise put `Blocked by: #<n>` near the top of the child issue. The next ticket is the first open, unassigned, unblocked child in map order. Claim it by assigning it to yourself. Resolve it by commenting with the answer, closing it, and adding a short link to the map's decisions.
