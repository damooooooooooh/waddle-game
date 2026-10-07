// Shown after an answer. `why` explains why the right control works; `trap` explains why the
// tempting wrong ones fail. Keyed by threat id.
export const EXPLANATIONS = {
  "user-injection": {
    why: "The model cannot tell instructions from data, so no prompt wording is a security boundary. Enforcing permissions outside the model means a successful injection still cannot read what the user is not allowed to see.",
    trap: "Prompt rules and phrase blocklists are bypassed by rewording. Hiding the chat box does nothing about the attack.",
  },
  "user-paste-pii": {
    why: "Once data reaches a third party you cannot take it back. Redacting at the boundary, plus policy and no-retention terms, stops the leak before it happens.",
    trap: "Warnings rely on people remembering, and keeping every prompt forever grows the pile of sensitive data you must protect.",
  },
  "user-flood": {
    why: "Every request costs money and capacity. Per-user quotas, token caps and a kill-switch put a ceiling on what one caller can spend or take down.",
    trap: "A bigger model or no timeout makes each abusive request more expensive, and the provider will bill you for the abuse.",
  },
  "orch-encoded-jailbreak": {
    why: "Attackers rephrase, encode and translate, so a single filter always loses. Layered semantic guardrails, least privilege and continuous red-teaming limit the damage when one layer fails.",
    trap: "A longer blocklist is a game of whack-a-mole, and temperature changes randomness, not obedience.",
  },
  "orch-system-prompt": {
    why: "Anything in a prompt can be coaxed out of the model. Secrets and access rules belong in code and a secrets manager, so a leaked prompt reveals nothing sensitive.",
    trap: "Telling the model to keep the prompt secret is just another instruction the attacker can talk around.",
  },
  "orch-agent-loop": {
    why: "Loops are normal for agents, so the control is a budget: max steps, timeouts and spend limits stop a runaway task from becoming a denial of wallet.",
    trap: "More retries or a bigger model just burn more tokens faster.",
  },
  "rag-indirect-injection": {
    why: "A retrieved document is attacker-controllable data. Labelling and sanitising it, keeping it apart from instructions and limiting what it can trigger stops hidden text from steering the model.",
    trap: "Trusting indexed content because it is internal ignores that anyone who can write to the source can write to your prompt.",
  },
  "rag-poisoned-kb": {
    why: "Poisoned data stays in the index and keeps working. Provenance checks, reviewed sources and versioned indexes let you stop bad data going in and roll back if it does.",
    trap: "Auto-ingesting everything or relying on the model to spot lies lets one bad document steer every answer.",
  },
  "rag-tenant-leak": {
    why: "Similarity search has no idea who is asking. Per-tenant partitions and ACL filters at query time make sure only permitted chunks can ever be retrieved.",
    trap: "Asking the model to ignore other tenants' chunks comes after the leak, and encrypting the disk does not stop authorised queries returning the wrong data.",
  },
  "model-memorization": {
    why: "Models can regurgitate training data. Removing PII before training, testing for memorisation and filtering outputs address the source and the exit.",
    trap: "Hoping the model will not repeat what it learned is not a control.",
  },
  "model-hub-download": {
    why: "A model file can run code or hide a backdoor. Vetted sources, hashes and signatures, safe formats and an ML-BOM prove what you are running came from where you think.",
    trap: "Popularity and stars are easy to fake, and a familiar name does not prove provenance.",
  },
  "model-hallucination": {
    why: "Models produce plausible text, not verified facts. Grounding with sources, checking packages against real registries and a human review catch confident mistakes before they cost you.",
    trap: "A disclaimer or a lower temperature does not make the answers true.",
  },
  "model-finetune-backdoor": {
    why: "A backdoor can hide behind a trigger phrase and pass normal tests. Tracking data provenance, scanning datasets and testing for triggers before release gives you a chance to find it.",
    trap: "Normal accuracy tests never use the trigger, so a backdoored model looks healthy.",
  },
  "tools-malicious-plugin": {
    why: "A plugin runs with your agent's rights and can change in an update. Pinning versions, reviewing updates, sandboxing and watching egress limit what a bad one can do.",
    trap: "Auto-updating or trusting a plugin because it is popular hands control to whoever publishes the next version.",
  },
  "tools-excess-permissions": {
    why: "The model will eventually be tricked or wrong, so what it can do is what an attacker can do. Minimal, per-user permissions enforced downstream cap the blast radius.",
    trap: "Admin rights so the agent never fails, or a prompt asking it to behave, put the whole trust decision on the model.",
  },
  "tools-no-approval": {
    why: "Irreversible or high-value actions need a second pair of eyes. Human approval, spend limits and an audit trail make mistakes catchable and attributable.",
    trap: "Full autonomy only works while the model is never wrong or fooled, which you cannot promise.",
  },
  "out-xss": {
    why: "Model output is attacker-influenced text. Encoding it for where it lands and using a strict CSP stop it turning into script in a user's browser.",
    trap: "Telling the model not to output HTML can be overridden, and trusting its output skips the control that matters.",
  },
  "out-sql-exec": {
    why: "Generated SQL is untrusted input to your database. A read-only least-privilege role and validated or parameterised queries mean a bad query cannot change or leak much.",
    trap: "Running generated SQL with the app's own account means any prompt injection becomes a database injection.",
  },
  "out-markdown-image": {
    why: "A rendered image URL can carry stolen data out with no click. Blocking or proxying external images and allowlisting domains closes that exfiltration channel.",
    trap: "Asking users not to click does not help, because the browser fetches the image automatically.",
  },
  "out-autopublish": {
    why: "A false public claim can cause real harm. Human review, sources, labels and accuracy tests put a person in the path for high-stakes content.",
    trap: "Publishing first and fixing later, or adding a small disclaimer, leaves the harm done.",
  },
  "id-shared-token": {
    why: "One shared admin account means any agent can do anything, and you cannot tell them apart. Per-agent, short-lived, task-scoped credentials limit what a tricked agent can reach and make its actions attributable.",
    trap: "Rotating the shared token slowly or telling the agent not to look at payroll leaves the privilege in place.",
  },
  "id-confused-deputy": {
    why: "If the agent acts on its own broad rights, the user borrows them. Delegating the end user's identity and checking authorization outside the model means the agent can never do more than the person could.",
    trap: "Trusting the agent to decide whose data is whose is exactly the decision an attacker will try to manipulate.",
  },
  "core-goal-hijack-email": {
    why: "Anything the agent reads can contain instructions. Keeping the goal outside the content, checking plans against it and requiring approval for outbound actions stops a hidden message rewriting what the agent does.",
    trap: "Asking the model to ignore hidden text or stripping HTML misses the many other ways to hide instructions.",
  },
  "core-goal-drift-web": {
    why: "A web page should not be able to change the objective. Pinning the goal, validating each step against it and asking a human before spending stops a competing instruction reaching the purchase tool.",
    trap: "Free re-planning and polished-looking pages are exactly what a hijack relies on.",
  },
  "core-rogue-drift": {
    why: "You cannot stop what you cannot see. A baseline, drift monitoring, decision logs and a kill-switch let you detect a misbehaving agent and shut it down.",
    trap: "More reward or the agent's own report encourages and hides the drift instead of catching it.",
  },
  "mem-persistent-poison": {
    why: "Memory outlives the conversation, so a planted fact keeps steering behaviour. Validating writes, tracking provenance, isolating per user and expiring entries stops one user rewriting policy for everyone.",
    trap: "Storing everything and sharing memory across users makes poisoning easy and wide.",
  },
  "mem-summary-poison": {
    why: "A summary turns untrusted text into something that looks like the agent's own knowledge. Separating trusted from untrusted context and re-checking privileges from the identity system stops a planted claim becoming fact.",
    trap: "Summarising harder or trusting the model's summary just launders the planted line more thoroughly.",
  },
  "tool-delete-everything": {
    why: "A general raw-SQL tool turns every model mistake into an incident. Narrow, parameterised tools with least privilege and confirmation for destructive calls keep a slip small.",
    trap: "Warning the agent to be careful, or giving it admin rights, does not stop a bad query from running.",
  },
  "tool-exfil-via-tool": {
    why: "Even a read-only fetch can carry data out in the URL. Allowlisting destinations, inspecting arguments and logging calls close that channel and make attempts visible.",
    trap: "Blocking one word or allowing any HTTPS destination leaves countless ways to smuggle data out.",
  },
  "tool-mcp-malicious": {
    why: "An MCP server is code and prompt text from someone else, running with your agent's rights. Vetting, pinning by hash, sandboxing and reviewing updates stop a later change from becoming an attack.",
    trap: "Auto-updating and trusting download counts means the next release can turn malicious unnoticed.",
  },
  "tool-agent-card-spoof": {
    why: "A name and description are claims anyone can make. Only accepting signed cards from an approved registry proves who published the agent you delegate to.",
    trap: "Choosing the most official-sounding or fastest agent rewards the attacker who copies the best.",
  },
  "tool-codegen-rce": {
    why: "Code the model writes is untrusted code. Running it in a sandbox with no secrets, no network and resource limits means a poisoned input cannot reach your credentials.",
    trap: "Keyword scans are easy to evade, and running as the agent's user hands the code all its access.",
  },
  "tool-shell-injection": {
    why: "Ticket text should become an argument, never part of a command line. Fixed commands, validated arguments, an allowlist and a sandbox stop injected shell syntax running.",
    trap: "Filtering one character misses the others, and running as root makes any slip far worse.",
  },
  "a2a-spoofed-peer": {
    why: "Being on the internal network proves nothing. Mutual TLS or signed messages, authorisation per sender role and nonces stop forged or replayed task requests.",
    trap: "Trusting the claimed sender or hiding the bus address is security by assumption.",
  },
  "a2a-sniffed-channel": {
    why: "Messages between agents are an attack surface like any API. Encrypting and signing them, sharing only needed fields and validating schemas stops reading and tampering in transit.",
    trap: "Assuming a private network is safe or passing the whole record gives an eavesdropper everything.",
  },
  "a2a-cascade-bad-data": {
    why: "In a chain of agents one confident mistake becomes everyone's input. Validation between agents and circuit breakers contain it before it spreads.",
    trap: "More agents sharing the same bad data just agree with each other faster.",
  },
  "a2a-retry-storm": {
    why: "Unlimited retries amplify a small slowdown into an outage. Retry budgets with backoff, rate limits and circuit breakers make failures fail safe.",
    trap: "Retrying forever or removing timeouts keeps the load on a system that is already struggling.",
  },
  "human-persuasive-agent": {
    why: "The agent controls what the approver sees. Showing the real action and risk and verifying high-risk changes independently means a persuasive pitch cannot stand in for evidence.",
    trap: "Letting the agent write its own justification or making Approve quicker helps the attacker.",
  },
  "human-approval-fatigue": {
    why: "Too many prompts teach people to click through. Reserving approval for high-risk actions, showing clear diffs and recording who approved what keeps oversight real and accountable.",
    trap: "Approving everything or adding Approve all removes the very attention approval depends on.",
  },
  "human-rogue-no-kill": {
    why: "You cannot contain or investigate an agent you cannot identify. Unique identities, detailed logs and a tested kill-switch let you trace actions and stop the agent quickly.",
    trap: "Shared accounts and waiting for complaints mean the problem runs for days before anyone notices.",
  },
};
