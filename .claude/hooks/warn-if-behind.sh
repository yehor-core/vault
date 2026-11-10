#!/bin/bash
# SessionStart hook: tells the agent when this checkout is behind origin/main, so it does not plan from stale
# docs (ROADMAP.md, DECISIONS.md, CLAUDE.md). It never blocks: offline or outside a repository it stays silent.

cd "${CLAUDE_PROJECT_DIR:-.}" 2>/dev/null || exit 0
git fetch --quiet origin 2>/dev/null || exit 0
behind=$(git rev-list --count HEAD..origin/main 2>/dev/null) || exit 0

if [[ "$behind" -gt 0 ]]; then
  branch=$(git symbolic-ref --short -q HEAD || echo 'detached HEAD')
  echo "This checkout ($branch) is $behind commit(s) behind origin/main. Read the docs from origin/main (git show origin/main:<path>), or ask the user to pull."
fi
exit 0
