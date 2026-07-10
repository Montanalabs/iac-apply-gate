#! IaC apply gate — untrusted a plan output can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires applyPlan — the iac apply gate sink
#! @effect io
#! @irreversible
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant applyPlan irreversible

type ChangeSet = Additive | Replace | Destroy
type Decision = Apply(ChangeSet) | Reject

let raw = fetch<web>  # UNTRUSTED a plan output — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
commit { applyPlan(d) }  # act on the trusted decision only
