#!/usr/bin/env bash
set -euo pipefail

# Requires: gh (authenticated via GITHUB_TOKEN env var; gh reads it
# automatically, no `gh auth login` needed), jq, python3 (PyYAML).
# One evidence file per repository in config/scope.yaml, plus a manifest; see
# evidence/lib/collect.sh.
#
# EVENT collector: it covers ONE UTC day (RSC_DATE, default yesterday; see lib/day_window.py)
# and the evidence holds exactly the pull requests merged in [day 00:00:00Z, next day
# 00:00:00Z). A day with no merge is a complete, empty collection, and it passes: what
# guards against a silent gap is that the repository was reached, the pages were read
# down to the day and nothing was capped. Rerunning for a past date recovers a missed day.
# Approvals, checks and the exemption facts are read as they are when the collector runs
# (a late /lgtm or a changed branch protection is not rewound), which the record states.
#
# Orders by UPDATED_AT (GitHub has no MERGED_AT sort), page after page until a page is
# entirely older than the start of the day (a PR merged on the day was updated on or after
# it), at most 20 pages of 50. A day deeper than that in a busy repository fails the
# collection instead of being truncated (known-gaps.yaml).

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
source "$(cd "$(dirname "$0")" && pwd)/lib/collect.sh"
AUTOMATION_CONFIG="${RSC_AUTOMATION_CONFIG:-${RSC_ROOT}/config/automation.yaml}"
rsc_day_window || exit 1

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set (gh CLI reads it for GraphQL auth)." >&2
  exit 1
fi

# Prow (OpenShift CI) approves through `/lgtm` (a reviewer) and `/approve` (an
# OWNERS approver) commands that set the `lgtm` and `approved` labels, so
# GitHub's reviewDecision is mostly empty. Prow also reads commands in review
# bodies, and (review_acts_as_lgtm) treats an approving review as /lgtm. What
# the team's merge gate (Tide) requires is both labels, so a Prow approval
# counts here only when:
#   - both the `lgtm` and `approved` labels are present, AND
#   - a non-author, non-bot account has an unretracted `/lgtm` or `/approve`
#     in a comment or review body made BEFORE the merge (a command on a closed
#     PR does nothing), so the label is attributable to a person.
# A bot that applies the labels to its own PR leaves no such command and so has
# no approver; author_is_bot says so. Automation identities (config/automation.yaml)
# are never counted as approvers of other people's PRs.
#
# automated_change records the facts the policy needs to decide whether a PR may
# count as approved by automation (see config/automation.yaml): the author is
# allowlisted, the repo's Tide config has a dedicated query for that author, the
# approval labels are present, the merge bot merged it, and every commit is
# authored by that identity with a valid signature. The collector only reports the
# facts; the Rego decides. `summary` counts how many PRs satisfy all five, so
# reports can say how many merges relied on the exemption.
# GitHub approving reviews by non-authors count directly.
#
# Status checks: only the checks the branch protection REQUIRES are judged, not the
# last commit's overall rollup (which, on a merged PR, includes items that never
# resolve: the merge bot's own `tide` status stays pending after the merge, optional
# contexts are queued, neutral or skipped). For every required context the
# collector records its result on the PR's last commit:
#   success   a successful status, or a check run that concluded success
#   failure   a failed or errored status; a check run that failed, timed out, was
#             cancelled, failed to start, needs action or is stale
#   pending   a status still pending/expected; a check run not yet completed
#   neutral   a check run that concluded neutral or skipped. GitHub itself lets these
#             satisfy a required check; here only `success` counts as passed, so they
#             are reported (the check did not actually assert anything)
#   missing   the required context never reported on that commit
# When the same context appears more than once the worst result is kept. Required
# contexts are read from the CURRENT branch protection, which may differ from the
# configuration at merge time. A PR whose contexts could not all be read (more than
# the paging bound) is marked checks_complete=false, never passed.
#
# Private repositories: a fine-grained token cannot read check runs (there is no
# Checks permission for it), and GitHub then also refuses the GraphQL `contexts`
# connection. The collector falls back to the REST commit statuses, which are what
# Prow's `ci/prow/*` checks are, and records check_runs_readable=false. A required
# context found among the statuses is judged as usual. One that is not becomes
# `unknown` (we cannot tell whether a check run satisfied it) and the PR is
# checks_complete=false: never a pass, and never a violation.
#   unknown   a required context not among the statuses while check runs are unreadable
#
# Normalized per PR: approved_by (non-author, non-bot accounts), approval_sources,
# author_is_bot and required_checks, so the Rego never needs to know about GitHub
# or Prow.

# GraphQL returns the first 100 status contexts of a PR's last commit. For a PR with
# more, page through the rest up to a bound (RSC_CONTEXT_PAGES_MAX extra pages of
# 100); if more remain, that PR keeps hasNextPage and is reported incomplete.
RSC_CONTEXT_PAGES_MAX="${RSC_CONTEXT_PAGES_MAX:-4}"

# Args: owner name raw-json-array-of-PR-nodes. Prints the array with contexts filled in.
rsc_fill_contexts() {
  local owner="$1" name="$2" raw="$3" idx oid after more n page
  local path='.commits.nodes[0].commit.statusCheckRollup.contexts'
  for idx in $(jq -r "to_entries[] | select(.value${path}.pageInfo.hasNextPage == true) | .key" <<<"${raw}"); do
    oid="$(jq -r ".[${idx}].commits.nodes[0].commit.oid" <<<"${raw}")" || return 1
    after="$(jq -r ".[${idx}]${path}.pageInfo.endCursor" <<<"${raw}")" || return 1
    more=true
    n=0
    while [[ "${more}" == true && "${n}" -lt "${RSC_CONTEXT_PAGES_MAX}" ]]; do
      page="$(rsc_retry gh api graphql -f query='
        query($owner: String!, $name: String!, $oid: GitObjectID!, $after: String) {
          repository(owner: $owner, name: $name) {
            object(oid: $oid) { ... on Commit { statusCheckRollup {
              contexts(first: 100, after: $after) {
                pageInfo { hasNextPage endCursor }
                nodes { __typename ... on StatusContext { context state } ... on CheckRun { name conclusion status } }
              } } } }
          }
        }' -f owner="${owner}" -f name="${name}" -f oid="${oid}" -f after="${after}")" || return 1
      jq -e '.data.repository.object.statusCheckRollup.contexts != null and (.errors | not)' <<<"${page}" >/dev/null || return 1
      raw="$(jq --argjson i "${idx}" --argjson p "${page}" '
        .[$i].commits.nodes[0].commit.statusCheckRollup.contexts |=
          (.nodes += $p.data.repository.object.statusCheckRollup.contexts.nodes
           | .pageInfo = $p.data.repository.object.statusCheckRollup.contexts.pageInfo)' <<<"${raw}")" || return 1
      more="$(jq -r '.data.repository.object.statusCheckRollup.contexts.pageInfo.hasNextPage' <<<"${page}")"
      after="$(jq -r '.data.repository.object.statusCheckRollup.contexts.pageInfo.endCursor' <<<"${page}")"
      n=$((n + 1))
    done
  done
  printf '%s' "${raw}"
}

# Fallback when GraphQL refuses the contexts connection (see the header): fill each
# PR merged on the day from the REST combined status of its last commit. The
# combined status holds the latest state of every status context. Args: repo
# raw-json-array day-start day-end. Prints the array with contexts filled in.
rsc_rest_contexts() {
  local repo="$1" raw="$2" start="$3" end="$4" idx oid st
  for idx in $(jq -r --arg s "${start}" --arg e "${end}" 'to_entries[] | select(.value.mergedAt >= $s and .value.mergedAt < $e) | .key' <<<"${raw}"); do
    oid="$(jq -r ".[${idx}].commits.nodes[0].commit.oid // empty" <<<"${raw}")" || return 1
    [[ -n "${oid}" ]] || continue
    st="$(rsc_retry gh api "repos/${repo}/commits/${oid}/status?per_page=100")" || return 1
    jq -e '.statuses != null' <<<"${st}" >/dev/null || return 1
    raw="$(jq --argjson i "${idx}" --argjson s "${st}" '
      .[$i].commits.nodes[0].commit.statusCheckRollup.contexts =
        {pageInfo: {hasNextPage: (($s.total_count // 0) > ($s.statuses | length)), endCursor: null},
         nodes: [$s.statuses[] | {__typename: "StatusContext", context: .context, state: (.state | ascii_upcase)}]}' <<<"${raw}")" || return 1
  done
  printf '%s' "${raw}"
}

collect_repo() {
  local repo="$1" out="$2" owner="${1%%/*}" name="${1##*/}" base_ref after="" page raw="[]" pages=0 tide automation required mode=graphql errf rollup_fields runs_readable=true
  base_ref="$(rsc_default_branch "${repo}")" || return 1
  tide="$(rsc_tide_gate "${repo}" "${base_ref}")" || return 1
  automation="$(python3 "${RSC_LIB_DIR}/automation_config.py" "${AUTOMATION_CONFIG}")" || return 1
  required="$(rsc_required_checks "${repo}" "${base_ref}")" || return 1

  local query='
      query($owner: String!, $name: String!, $baseRefName: String!, $after: String) {
        repository(owner: $owner, name: $name) {
          pullRequests(states: MERGED, baseRefName: $baseRefName, first: 50, after: $after,
                        orderBy: {field: UPDATED_AT, direction: DESC}) {
            pageInfo { hasNextPage endCursor }
            nodes {
              number
              mergedAt
              updatedAt
              author { login __typename }
              mergedBy { login }
              labels(first: 50) { nodes { name } }
              latestOpinionatedReviews(first: 50) { nodes { state author { login __typename } } }
              comments(first: 100) { pageInfo { hasNextPage } nodes { author { login __typename } body createdAt } }
              reviews(first: 50) { pageInfo { hasNextPage } nodes { author { login __typename } body submittedAt } }
              commits(last: 1) { nodes { commit { oid statusCheckRollup { __ROLLUP__ } } } }
              allCommits: commits(first: 100) { totalCount nodes { commit { author { user { login } } signature { isValid } } } }
            }
          }
        }
      }'
  rollup_fields='state contexts(first: 100) {
                pageInfo { hasNextPage endCursor }
                nodes { __typename ... on StatusContext { context state } ... on CheckRun { name conclusion status } }
              }'
  errf="$(mktemp)"

  # Pages are ordered by UPDATED_AT (GitHub has no MERGED_AT sort). Keep going
  # until a page reaches PRs last updated before the day began, so a busy repo is
  # not silently truncated. A PR merged on the day was updated on or after its start.
  while :; do
    local args=(-f owner="${owner}" -f name="${name}" -f baseRefName="${base_ref}")
    [[ -n "${after}" ]] && args+=(-f after="${after}")
    if ! page="$(rsc_retry gh api graphql -f query="${query//__ROLLUP__/${rollup_fields}}" "${args[@]}" 2>"${errf}")"; then
      if [[ "${mode}" == graphql ]] && grep -q "Resource not accessible" "${errf}"; then
        # Contexts are forbidden for this token (private repository): use REST statuses.
        mode=rest
        runs_readable=false
        rollup_fields="state"
        continue
      fi
      cat "${errf}" >&2
      rm -f "${errf}"
      return 1
    fi
    # A GraphQL error (e.g. no access) can still exit 0 from gh; treat it as failure.
    jq -e '.data.repository != null and (.errors | not)' <<<"${page}" >/dev/null || return 1
    raw="$(jq -s '.[0] + .[1].data.repository.pullRequests.nodes' <(echo "${raw}") <(echo "${page}"))" || return 1
    pages=$((pages + 1))
    jq -e '.data.repository.pullRequests.pageInfo.hasNextPage' <<<"${page}" >/dev/null || break
    jq -e --arg c "${DAY_START}" '[.data.repository.pullRequests.nodes[].updatedAt] | (length > 0 and min >= $c)' <<<"${page}" >/dev/null || break
    [[ "${pages}" -lt 20 ]] || { echo "more than 20 pages of merged PRs" >&2; return 1; }
    after="$(jq -r '.data.repository.pullRequests.pageInfo.endCursor' <<<"${page}")"
  done

  rm -f "${errf}"
  if [[ "${mode}" == rest ]]; then
    raw="$(rsc_rest_contexts "${repo}" "${raw}" "${DAY_START}" "${DAY_END}")" || return 1
  else
    raw="$(rsc_fill_contexts "${owner}" "${name}" "${raw}")" || return 1
  fi

  jq --arg ar "${AR_ID}" --arg repo "${repo}" --arg base_ref "${base_ref}" \
    --arg day "${DAY_DATE}" --arg day_start "${DAY_START}" --arg day_end "${DAY_END}" \
    --argjson required "${required}" --argjson runs_readable "${runs_readable}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson tide "${tide}" --argjson automation "${automation}" '
    def base: sub("\\[bot\\]$"; "");
    # Result of one status context or check run (see the header for the mapping).
    def result_of:
      if .__typename == "StatusContext" then
        (if .state == "SUCCESS" then "success"
         elif (.state == "FAILURE" or .state == "ERROR") then "failure"
         else "pending" end)
      elif .status != "COMPLETED" then "pending"
      elif .conclusion == "SUCCESS" then "success"
      elif (.conclusion == "NEUTRAL" or .conclusion == "SKIPPED") then "neutral"
      else "failure" end;
    def severity: {"failure": 3, "pending": 2, "neutral": 1, "success": 0};
    # A person: not a GitHub Bot and not one of our allowlisted automation identities.
    def human($a): $a != null and $a.login != null and ($a.__typename != "Bot")
      and (($automation.change_authors | index($a.login | base)) == null);
    # Final state per commenter and command: the last of /x or /x cancel wins.
    def commanders($author; $merged_at):
      [ ((.comments.nodes | map({author, body, at: .createdAt}))
         + (.reviews.nodes | map({author, body, at: .submittedAt})))
        | sort_by(.at)[] | select(human(.author) and .at <= $merged_at)
        | .author.login as $login
        | .body | split("\n")[] | gsub("\r"; "")
        | capture("^/(?<cmd>lgtm|approve)(?<cancel> cancel)?[ \t]*$") | {login: $login, cmd, cancel: (.cancel != null and .cancel != "")} ]
      | group_by([.login, .cmd]) | map(last | select(.cancel | not) | .login)
      | unique | map(select(. != $author));
    {
      assessment_requirement: $ar,
      generated_at: $generated_at,
      repository: $repo,
      base_ref: $base_ref,
      covers_date: $day,
      window: {start: $day_start, end: $day_end},
      branch_protected: $required.protected,
      check_runs_readable: $runs_readable,
      required_contexts: $required.contexts,
      summary: null,
      pull_requests: [
        .[]
        | select(.mergedAt >= $day_start and .mergedAt < $day_end)
        | (.author.login) as $author
        | ([.labels.nodes[].name]) as $labels
        | ([.latestOpinionatedReviews.nodes[]
            | select(.state == "APPROVED" and human(.author) and .author.login != $author)
            | .author.login]) as $reviewers
        | (($labels | index("lgtm")) != null and ($labels | index("approved")) != null) as $labelled
        | (.commits.nodes[0].commit.statusCheckRollup // null) as $roll
        | ([($roll.contexts.nodes // [])[] | {name: (.context // .name), result: result_of}]) as $ctx
        | ([$required.contexts[] | . as $c
            | ([$ctx[] | select(.name == $c) | .result]) as $rs
            | {context: $c,
               result: (if ($rs | length) == 0 then (if $runs_readable then "missing" else "unknown" end)
                        else ($rs | max_by(severity[.])) end)}]) as $rc
        | (.allCommits.nodes) as $commits
        | {
            author_allowlisted: (($automation.change_authors | index($author | base)) != null),
            gate_defined: (($tide.author_queries | index($author | base)) != null),
            gate_labels_present: $labelled,
            merged_by_merge_automation: ((.mergedBy.login // "" | base) as $m | ($automation.merge_automation | index($m)) != null),
            all_commits_by_author: (($commits | length) > 0 and .allCommits.totalCount == ($commits | length)
              and all($commits[]; (.commit.author.user.login // "" | base) == ($author | base) and .commit.signature.isValid == true))
          } as $auto
        | (if ($labels | index("lgtm")) != null and ($labels | index("approved")) != null
           then commanders($author; .mergedAt) else [] end) as $prow
        | {
            number: .number,
            merged_at: .mergedAt,
            author: $author,
            author_is_bot: (.author.__typename == "Bot"),
            automated_change: $auto,
            merged_by: .mergedBy.login,
            approved_by: ($reviewers + $prow | unique),
            approval_sources: ([(if ($reviewers | length) > 0 then "github-review" else empty end),
                                (if ($prow | length) > 0 then "prow" else empty end)]),
            history_truncated: (.comments.pageInfo.hasNextPage or .reviews.pageInfo.hasNextPage),
            required_checks: $rc,
            checks_complete: ((($roll.contexts.pageInfo.hasNextPage // false) | not)
                              and ($rc | all(.[]; .result != "unknown"))),
            # Debugging only: the overall rollup is NOT judged (see the header).
            status_check_state: ($roll.state // "NONE")
          }
      ]
    }
    | .summary = {merged: (.pull_requests | length),
                  automation_exempt: ([.pull_requests[] | select(.automated_change | all(.[]; . == true))] | length),
                  exemption_approved: $automation.exemption_approved}
  ' <<<"${raw}" >"${out}" || return 1
}

rsc_collect_all
