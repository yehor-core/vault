#!/bin/bash
# PreToolUse hook (Bash): the user keeps pushing to main and merging PRs for themselves.
# Pushing a feature branch stays allowed: every ticket pushes its own branch and opens a PR. After a rebase,
# the agent updates its branch with --force-with-lease, which refuses to overwrite commits it hasn't seen.

input=$(cat)
command=$(jq -r '.tool_input.command // empty' <<<"$input")
cwd=$(jq -r '.cwd // empty' <<<"$input")

block() {
  echo "BLOCKED: $1. The user pushes to main and merges PRs themselves: push your feature branch and open a PR." >&2
  exit 2
}

if grep -qE '(^|[^[:alnum:]_-])gh[[:space:]]+pr[[:space:]]+merge([[:space:]]|$)' <<<"$command"; then
  block "merging a pull request"
fi

# The push itself: from "git" to the end of its simple command, so "git push x && git checkout main" isn't misread.
push=$(grep -oE '(^|[^[:alnum:]_-])git([[:space:]][^|;&]*)?[[:space:]]push([[:space:]][^|;&]*)?' <<<"$command")
if [[ -n "$push" ]]; then
  # --force-with-lease passes: --force must be followed by "=", a space or the end, and it is followed by "-".
  if grep -qE '[[:space:]](--force|-f)(=|[[:space:]]|$)|[[:space:]]\+[^[:space:]]' <<<"$push"; then
    block "force-pushing without a lease (after a rebase, use git push --force-with-lease)"
  fi
  if grep -qE '[[:space:]:/](main|master)([[:space:]]|$)' <<<"$push"; then
    block "pushing to main"
  fi
  branch=$(git -C "${cwd:-.}" symbolic-ref --short -q HEAD 2>/dev/null)
  if [[ "$branch" == "main" || "$branch" == "master" ]]; then
    block "pushing while on $branch"
  fi
fi

exit 0
