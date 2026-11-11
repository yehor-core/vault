#!/bin/bash
# SessionStart hook: tells the agent when this checkout is behind origin/main, so it does not plan from stale
# docs (ROADMAP.md, DECISIONS.md, CLAUDE.md), and when its branch's PR was merged into a branch other than main
# (a stacked PR whose base merged first), so its commits never reached main. It never blocks: offline, without
# gh, or outside a repository it stays silent.

# The session's own directory, from the hook input: in a worktree session it is the worktree, while
# CLAUDE_PROJECT_DIR is the main checkout.
[[ -t 0 ]] || dir=$(jq -r '.cwd // empty' 2>/dev/null)
cd "${dir:-${CLAUDE_PROJECT_DIR:-.}}" 2>/dev/null || exit 0
git fetch --quiet origin 2>/dev/null || exit 0
branch=$(git symbolic-ref --short -q HEAD || echo 'detached HEAD')

behind=$(git rev-list --count HEAD..origin/main 2>/dev/null) || exit 0
if [[ "$behind" -gt 0 ]]; then
  echo "This checkout ($branch) is $behind commit(s) behind origin/main. Read the docs from origin/main (git show origin/main:<path>), or ask the user to pull."
fi

ahead=$(git rev-list --count origin/main..HEAD 2>/dev/null) || exit 0
if [[ "$ahead" -gt 0 ]] && command -v gh >/dev/null; then
  bases=$(timeout 15 gh pr list --head "$branch" --state merged --json baseRefName -q '.[].baseRefName' 2>/dev/null)
  if [[ -n "$bases" ]] && ! grep -qx 'main' <<<"$bases"; then
    echo "The PR of $branch was merged into $(head -n1 <<<"$bases"), not main, and $ahead of its commits are not in origin/main. Tell the user: the work may need a new PR to main."
  fi
fi
exit 0
