#!/bin/bash
# PreToolUse hook (Bash): the user keeps pushing to main, force-pushing and merging PRs for themselves.
# Pushing a feature branch stays allowed: every ticket pushes its own branch and opens a PR.

input=$(cat)
command=$(jq -r '.tool_input.command // empty' <<<"$input")
cwd=$(jq -r '.cwd // empty' <<<"$input")

block() {
  echo "BLOCKED: $1. The user pushes to main, force-pushes and merges PRs themselves: push your feature branch and open a PR." >&2
  exit 2
}

if grep -qE '(^|[^[:alnum:]_-])gh[[:space:]]+pr[[:space:]]+merge([[:space:]]|$)' <<<"$command"; then
  block "merging a pull request"
fi

# The push itself: from "git" to the end of its simple command, so "git push x && git checkout main" isn't misread.
push=$(grep -oE '(^|[^[:alnum:]_-])git([[:space:]][^|;&]*)?[[:space:]]push([[:space:]][^|;&]*)?' <<<"$command")
if [[ -n "$push" ]]; then
  if grep -qE '[[:space:]](--force|--force-with-lease|-f)(=|[[:space:]]|$)|[[:space:]]\+[^[:space:]]' <<<"$push"; then
    block "force-pushing"
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
