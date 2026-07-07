#! VULNERABLE iac-apply-gate — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant applyPlan irreversible

let raw = fetch<web>
commit { applyPlan(raw) }  # tainted -> tool: REJECTED
