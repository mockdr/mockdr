<!-- AGENT PROMPT — BEGIN -->

# TEAMS.md — Multi-Perspective Review Framework

## Agent Instructions

When a user says **"load teams.md"** followed by an idea, codebase, architecture, or prompt to review, execute the following:

### Source Truth Doctrine

**Code is the only trusted source. Documentation is a claim. Treat it as such.**

- All review insights MUST be grounded in actual source code, config files, schemas, infrastructure-as-code, or runtime behavior.
- Documentation (READMEs, wikis, architecture docs, comments, ADRs) is treated as **unverified testimony**. It may describe intent, but it does not describe reality until confirmed against the code.
- If documentation and code disagree, **the code is correct and the documentation is a bug**.
- If only documentation is provided without source code, the review must state this limitation explicitly and flag that findings are provisional — based on claims, not evidence.
- If the user provides both code and documentation, the review should actively check for divergence. Every mismatch is a finding.

This is not optional. A review based on documentation alone is a review of wishes, not of the system.

### Input

Accept one or more of:
- **Code** (primary): A codebase, module, function, config, schema, IaC, or snippet. This is the source of truth.
- **Idea**: A concept, proposal, or design intent. Review is provisional until code exists.
- **Prompt**: A system prompt, agent instruction, or workflow definition. Treated as code.
- **Documentation** (secondary): READMEs, wikis, ADRs, architecture docs. Treated as unverified claims. Useful for understanding intent, not for confirming behavior.

If only an idea or documentation is provided, state clearly: **"This review is based on intent, not implementation. Findings are provisional."**

### Contextual Weighting

Not all roles carry equal weight for every input. Before running the layers, determine the **domain** of the input and weight perspectives accordingly.

- **Security / Auth / Cryptography** → Elevate: Skeptical Auditor, Snake, Legal Adversary, Mathematician, Hostile Environment, The Policeman, Tortoise. These roles can challenge harder and speak longer.
- **UI / UX / Component Library** → Elevate: Artist, Cashier, Cognitive Load Analyst, Children, The Newcomer, The User. Aesthetic and friction concerns lead.
- **Data Pipeline / Distributed Systems** → Elevate: Ghost in the Machine, Octopus, River, Postman, Mathematician, Tragedy of the Commons, The Cascade, Mycelium, Day-2 Operator, The Train Station, The Database Engineer, Whale.
- **Governance / Policy / Permissions** → Elevate: Bureaucratic Drift, Elephant, Parents, The Outsider, The Policeman.
- **New Feature / Greenfield** → Elevate: The Midwife, The Database Engineer, Minimalist, Baker, The Tent, The Geologist, Economic Realist, The Implementor, The Client, Hummingbird, Success Catastrophe. In greenfield: Time-Traveler watches for premature legacy, not backward compatibility. Diplomat and Chameleon watch for unnecessary abstraction, not integration friction.
- **Incident Response / Recovery** → Elevate: Healer, Chaos Engineer, Heroism Debt, Dog, The Half-Migration, Day-2 Operator, The Fire Brigade, The Doctor.
- **Integration / Cross-Team / API Contracts** → Elevate: The Diplomat, Mycelium, Time-Traveler, Postman, The Newcomer, The Networker, Chameleon, Semantic Drift.
- **Product / Go-to-Market / Feature Launch** → Elevate: The User, The Client, The Rep, The Consultant, Artist, Success Catastrophe.
- **Legacy / Refactor / Tech Debt** → Elevate: The Trash Bin, The Funeral Orator, Time-Traveler, The Librarian, The Author, The Half-Migration, The Tent, The Geologist, Whale, Semantic Drift.
- **Database / Schema / Data Model** → Elevate: The Database Engineer, The Geologist, Elephant, Mathematician, Whale, Semantic Drift, Time-Traveler, Stone.

Elevated roles are not the only roles that speak. They simply get priority and more latitude. All other roles still contribute if they have something meaningful to say.

**The Librarian always runs.** Regardless of domain or tier, if documentation is present alongside code, The Librarian checks for divergence. This is not optional and is not subject to weighting.

If the domain is ambiguous or hybrid, state the weighting you chose and why.

### Execution

1. **Source Truth Check** — Classify the input. Is this source code, documentation, an idea, or a combination? If source code is present, it is the ground truth. If documentation is also present, run The Librarian immediately: check for divergence between docs and code. If only documentation or an idea is provided, state clearly: **"This review is based on intent, not implementation. Findings are provisional."** Check the **Project Context** section for implementation mode and constraints — these override default assumptions about compatibility, migration, and legacy. The Source Truth Check goes at the top of the output.
2. **Determine Review Tier** — Based on the input, assign a tier using Section 7.1 (Minimum Viable Review). State the tier and why. If unsure, default one tier higher.
3. **Summarize** the input in 2–3 sentences. State what it is and what it attempts to do.
4. **Identify Risk Surfaces** — list the obvious and non-obvious areas of concern.
5. **Apply Contextual Weighting** — state which domain applies and which roles are elevated.
6. **Run perspective layers** according to the assigned tier:

   **Tier 1 — Full Review**: Run all four layers in full.
   **Tier 2 — Focused Review**: Run the two most relevant layers (per weighting) plus Failure Stances.
   **Tier 3 — Spot Check**: Run only the 3–5 elevated roles. One paragraph output. Escalate to Tier 2 if any role raises a serious concern.

   **Layer 1 — Human Roles (Section 2)**
   For each role, produce one concise insight or challenge relevant to the input. Skip roles with nothing meaningful to say. Never pad.

   **Layer 2 — The Zoo (Section 3)**
   For each animal, produce one concise insight. Prioritize the animals whose lens is most revealing for this specific input. Skip the rest.

   **Layer 3 — Life Perspectives (Section 6)**
   Run all four subsections: Craft, Care, Growth, Clarity. For each role, produce one concise insight. These perspectives check for meaning, beauty, patience, and honesty — do not treat them as lesser than the technical layers.

   **Layer 4 — Failure Stances (Section 4)**
   For each stance, state whether it applies and what specific stress point it exposes.

7. **Kill Criteria Check** — After running the layers, evaluate Section 7.3. If three or more adversarial roles from different layers flagged the same fundamental concern, flag an **Automatic Pause** and state the convergent concern. If any Automatic Kill condition is met, state it clearly.
8. **Conflicts Between Perspectives** — identify where two or more roles directly contradict each other. Name the tension. Do not resolve it prematurely.
9. **Convergence Insight** — state what the majority of perspectives agree on, or what pattern emerges across layers.
10. **Residual Unknowns** — list what cannot be answered from the input alone. State what additional context would be needed.
11. **Top 3 Actions** — based on the full review, recommend three concrete next steps ranked by impact.

### Output Rules

- Be direct. No filler, no praise, no preamble.
- Each role gets **one line** unless the insight requires more. Brevity is respect.
- If a perspective has nothing to add, skip it silently.
- Use the role name as a label. Do not explain what the role is — the user already knows.
- Conflicts are valuable. Surface them, don't smooth them over.
- If the input is too vague to review meaningfully, say so and ask for what's missing.

### Tone

You are a senior review board, not a cheerleader. Be honest, be useful, be concise.
The goal is to show the builder what they cannot see from where they are standing.

### Satellite Files

TEAMS.md may be accompanied by satellite documents that provide domain-specific depth. If any of the following files are provided alongside TEAMS.md, load and cross-reference them during the review:

- **PROJECT-CONTEXT.md** — Implementation mode, constraints, tech stack, team shape. Defines greenfield/brownfield mode and role reweighting. **If present, read this first** — it changes how roles behave.
- **REGULATORY.md** — Applicable regulatory regimes, standards bodies, compliance requirements. The Legal Adversary, Skeptical Auditor, Policeman, Elephant, and Librarian reference this directly. If a regulatory regime is marked as "Applies," the review must include at least one finding that addresses it.
- **UX-STANDARDS.md** — Usability heuristics, accessibility standards, UX roles, design process. The User, Artist, Cashier, Newcomer, and Cognitive Load Analyst reference this directly. UX heuristic violations are findings, not suggestions.

If satellite files are not provided, the review proceeds with TEAMS.md alone. Do not ask for satellite files unless the input clearly falls into a regulated or UX-critical domain and the review would be materially incomplete without them.

<!-- AGENT PROMPT — END -->

---

| Field | Value |
|---|---|
| **Document** | TEAMS.md — Multi-Perspective Review Framework |
| **Version** | 1.3.0 |
| **Status** | Draft — Active Development |
| **Created** | 2025-02-21 |
| **Last Modified** | 2025-02-21 |
| **Authors** | Human + Claude (collaborative) |
| **Perspectives** | 31 Human Roles · 18 Zoo · 12 Failure Stances · 25 Life Perspectives · 86 Total |
| **Sections** | 8 (Agent Prompt · How To Use · Human Roles · Zoo · Failure Stances · Output Template · Life Perspectives · Operational Controls) |
| **Source Truth** | Code is the only trusted source. Documentation is a claim. |
| **Satellite Files** | PROJECT-CONTEXT.md · REGULATORY.md · UX-STANDARDS.md |
| **License** | Internal / Private |

### Changelog

| Version | Date | Summary |
|---|---|---|
| 1.3.0 | 2025-02-21 | Split into satellite files: PROJECT-CONTEXT.md, REGULATORY.md, UX-STANDARDS.md. Project Context removed from TEAMS.md header. Agent prompt updated with satellite file loading instructions. |
| 1.2.0 | 2025-02-21 | Project Context: Greenfield implementation. No shims, no compatibility layers, no legacy. Role reweighting for greenfield mode. |
| 1.1.0 | 2025-02-21 | Added Database Engineer, Chameleon, Tortoise, Whale, Hummingbird (Zoo), The Geologist (Growth), Semantic Drift (Failure Stance). New weighting domain: Database / Schema / Data Model. 86 total perspectives. |
| 1.0.0 | 2025-02-21 | Full framework: 79 perspectives, Source Truth Doctrine, Contextual Weighting, MVR tiers, Kill Criteria, Review-to-Outcome Tracking. |
| 0.8.0 | 2025-02-21 | Added Policeman, Fire Brigade, Networker, Delivery Driver, Bus Driver, Trash Bin, Coffee Cup, Train Station, Tent. |
| 0.7.0 | 2025-02-21 | Added Author, Doctor, Midwife, Funeral Orator, Esotericist. |
| 0.6.0 | 2025-02-21 | Added Implementor, Day-2 Operator, User, Client, Consultant, Rep. |
| 0.5.0 | 2025-02-21 | Source Truth Doctrine, The Librarian, The Dead Map failure stance. |
| 0.4.0 | 2025-02-21 | Added Sheep, Wife. Operational Controls: MVR tiers, Time Budget, Kill Criteria, Review-to-Outcome Tracking. |
| 0.3.0 | 2025-02-21 | Added Mycelium, The Diplomat, The Newcomer, The Cascade, Success Catastrophe, The Half-Migration. |
| 0.2.0 | 2025-02-21 | Added Time-Traveler, Tragedy of the Commons, Heroism Debt, The Outsider. Deepened Economic Realist. Contextual Weighting. |
| 0.1.0 | 2025-02-21 | Initial framework: Human Roles, Zoo, Failure Stances. Added Life Perspectives layer (Craft, Care, Growth, Clarity). Agent prompt. |

---

## Purpose

TEAMS.md defines a structured multi-perspective review framework.
Its purpose is to prevent single-view bias in architectural, governance, security, and product decisions.

Every major proposal SHOULD be reviewed through multiple defined roles and stances before acceptance.

This document formalizes those roles and how they are applied.

---

# 1. How To Use This Document

For any significant proposal, change, or doctrine update:

0. **Start with the code.** Documentation is a claim. Code is evidence. If source code is available, all review insights must be grounded in it. If only documentation exists, state that the review is provisional.
1. Write a concise Proposal Summary (max 1 page).
2. Identify explicit Risk Surfaces.
3. Run the Librarian first — check documentation against code for divergence.
4. Run the proposal through the Human Roles.
5. Run the proposal through the Zoo Roles.
6. Run the proposal through the Life Perspectives.
7. Run the proposal through the Failure Stances.
8. Document conflicts between perspectives.
9. Produce a Convergence Insight.
10. Record Residual Unknowns.

No proposal is considered "mature" until at least one adversarial stance has meaningfully challenged it.

No proposal is considered "complete" until at least one life perspective has asked whether it serves something beyond control.

No review is considered "grounded" until the Librarian has confirmed that documentation matches implementation — or flagged where it does not.

---

# 2. Human Roles

## Philosopher

Focus: First principles, coherence, category errors.

Questions:

* What assumption is this built on?
* Is this solving the right problem?
* Are we mistaking means for ends?

---

## Skeptical Auditor

Focus: Verifiability, evidence, compliance, forensic defensibility.

Questions:

* Can this be proven?
* Is there tamper-evidence?
* Would this survive regulatory scrutiny?

---

# The Mathematician
Focus: Invariants, boundary conditions, combinatorial explosion, and the difference between "it works for every case we tried" and "it works."

Questions:

* What invariant must always hold, and where is it enforced — in code, in comments, or in hope?
* What grows faster than expected? Is that O(n) assumption actually O(n²) hiding behind small inputs?
* Where are the boundary conditions — zero, one, max, negative, empty, null — and have they been reasoned about or just not encountered yet?
* Is this "rare" edge case actually rare, or is it rare-per-user but certain-at-scale?
* Are we assuming linearity where the real relationship is exponential, logarithmic, or discontinuous?
* What combinatorial space does this create, and has anyone counted?
Is correctness tested or proven? Do we know the difference here, and does it matter?

---

## The Librarian

Focus: Documentation-to-reality divergence, knowledge decay, and the shelf life of written claims.

Questions:

* Does the documentation match what the code actually does?
* When was this last updated, and by whom?
* Is anyone reading this, or is it write-only documentation?
* What does the README promise that the code no longer delivers?
* Are there comments in the code that describe behavior from three versions ago?
* Is this API doc describing the current contract or the aspirational one?

The Librarian does not trust the catalog. She walks the shelves. Documentation rots faster than code because nothing breaks when a wiki page is wrong. The Librarian catches the moment when the map and the territory diverge — and names it before someone navigates by the wrong one.

The Librarian's findings are always cross-referenced against the Source Truth Doctrine: if documentation says one thing and code says another, the documentation is the bug.

---

## Chaos Engineer

Focus: Active failure injection and resilience.

Questions:

* What breaks first?
* What if dependencies disappear?
* Does the system degrade safely?

---

## Ghost in the Machine (Latency & Race Conditions)

Focus: Concurrency, timing, partial ordering.

Questions:

* What if two events occur simultaneously?
* Is ordering assumed but not enforced?
* Are we relying on wall-clock time?

---

## Malicious Compliance (Input Injection)

Focus: Adversarial use of allowed interfaces.

Questions:

* What if someone follows the rules in a harmful way?
* Can schema-valid input cause logical harm?

---

## Crumbling Infrastructure (Partial Failures)

Focus: Degraded states, incomplete availability.

Questions:

* What happens under 30% packet loss?
* What if storage is read-only?

---

## Bureaucratic Drift (Permission Creep)

Focus: Governance entropy and role inflation.

Questions:

* Does this introduce a new permission?
* Who audits its usage?
* Can it be removed later?

---

## Observability of Silence (The Dog That Didn't Bark)

Focus: Absence detection and silent failure.

Questions:

* What expected signal might disappear?
* Are we monitoring non-events?

---

## Systems Ecologist

Focus: Second-order effects and ecosystem balance.

Questions:

* What feedback loop does this create?
* What behavior does this incentivize?

---

## Economic Realist (& Opportunity Cost Analyst)

Focus: Sustainability, resource cost, and the price of what you chose not to build.

Questions:

* Who pays the maintenance cost?
* What is the long-term scaling burden?
* By building this "flexible" abstraction, what three concrete features are we choosing not to ship this quarter?
* Are we optimizing for infrastructure elegance at the expense of product velocity?
* Is this cost visible in a bill, or hidden in developer hours and cognitive overhead?

In a world of serverless and API-first design, cost is not just server bills. It is time, attention, and forgone alternatives.

---

## Cognitive Load Analyst

Focus: Human comprehension and onboarding cost.

Questions:

* How many concepts must be held simultaneously?
* Are names and boundaries intuitive?

---

## Legal Adversary

Focus: Worst-case interpretation in legal/regulatory context.

Questions:

* Could this be interpreted as negligence?
* Is documentation aligned with behavior?

---

## Future Maintainer (+3 Years)

Focus: Long-term clarity and reversibility.

Questions:

* What context is missing?
* Can this be safely removed or replaced?

---

## Time-Traveler (Legacy Archaeologist)

Focus: Compatibility, migration debt, and the weight of the past.

Questions:

* How does this break our promises to the versions that came before?
* Does this assume the world started today?
* What existing data, users, or integrations does this silently invalidate?
* Is there a migration path, or are we creating a cliff?

The Future Maintainer looks forward. The Time-Traveler looks backward. Together they prevent the Greenfield Trap — the illusion that new design can ignore existing reality.

---

## Minimalist

Focus: Reduction and necessity.

Questions:

* What happens if this is deleted?
* Is this essential or ornamental?

---

## Doctrine Breaker

Focus: Foundational assumption challenge.

Questions:

* What if our core premise is wrong?
* Are we defending an ideology?

---

## The Diplomat

Focus: Cross-team and cross-org friction, boundary negotiation.

Questions:

* What boundary does this cross, and who controls the other side?
* Does this integrate with systems built by teams that don't share our standards, conventions, or language?
* Do the API contracts mean the same thing to both sides?
* What happens when naming conventions collide?
* Can we refactor this, or does it depend on a service we don't own?
* Do SLAs align across the boundary?

The Diplomat covers the political reality that your architecture does not exist in isolation. Someone else's team built the other end of that API, and they have different priorities, different release cycles, and a different definition of "done."

---

## The Implementor

Focus: Buildability, practical constraints, and the distance between design and working code.

Questions:

* Can I actually build this in the time we have?
* What's the simplest path to working software?
* What looks elegant on a whiteboard but is a nightmare to code?
* Which part of this will take 80% of the effort for 20% of the value?
* Are we designing for the language, framework, and tools we actually use — or for an idealized stack?
* Where will I get stuck?

The Implementor is the person who has to sit in the IDE and turn the architecture into reality. Every abstraction that survives the Philosopher and the Architect must also survive the Implementor asking "yes, but how?" If the answer requires heroic effort or undocumented magic, the design is incomplete.

---

## Day-2 Operator

Focus: Deployment, operation, rollback, monitoring, and the life of the system after the builder moves on.

Questions:

* Can this be deployed without downtime?
* Can it be rolled back in under five minutes?
* What alerts do we need on day one?
* What does the runbook look like?
* Can someone who didn't build this operate it?
* What happens when the on-call engineer has never seen this service before?
* Where are the logs, and do they say anything useful?

The Day-2 Operator inherits the system after the builder's attention moves elsewhere. DevOps and Ops are the same concern here: the gap between "it works on my machine" and "it runs in production at 3 AM on a Saturday and someone else is responsible." If the system cannot be deployed, monitored, and rolled back by a stranger following a runbook, it is not production-ready.

---

## The User

Focus: The actual experience of the person who uses the thing daily and does not care about the architecture.

Questions:

* Does this do what I need it to do?
* Can I figure this out without reading a manual?
* When something goes wrong, do I know what happened and what to do next?
* Does this respect my time?
* Will I trust this enough to rely on it?

The User does not care about your microservices, your event-sourcing, or your elegant domain model. The User cares about whether the thing works, whether it's fast, whether it's confusing, and whether it breaks. Every architectural decision eventually surfaces as a user experience — latency, error messages, missing features, broken flows. The User is the final judge and they don't grade on effort.

---

## The Client

Focus: Value delivery, expectations, budget, and whether what was promised is what was built.

Questions:

* Is this what I asked for?
* Is this what I'm paying for?
* When will it be done, and how will I know?
* What changed since we agreed on the scope, and why wasn't I told?
* Can I explain the value of this to my stakeholders?
* What happens if I need to change direction in three months?

The Client is the person who pays. Not the user — the person who funds the work and answers to their own stakeholders about whether it was worth it. The Client catches scope creep disguised as "technical improvement," timeline drift hidden behind "refactoring," and features that serve the builder's interests more than the business need. The Client doesn't need to understand the code. They need to trust the process and see the result.

---

## The Consultant

Focus: External pattern recognition, cross-industry comparison, and the uncomfortable question the team cannot ask itself.

Questions:

* I've seen this pattern at three other organizations — it failed at two. What makes you different?
* What would a competitor think if they saw this architecture?
* Are you building custom what you could buy?
* Is this a genuine technical requirement or an organizational habit?
* What would you do if you started over with half the team and twice the deadline?

The Consultant sees what insiders cannot because insiders have normalized their own dysfunction. The Consultant has no loyalty to the existing codebase, no emotional investment in past decisions, and no reason to be polite about structural problems. Used well, this role prevents insularity. Used badly, it produces expensive slide decks that recommend rewrites. The Consultant must show their working: pattern-match, but prove the match fits.

---

## The Rep (Sales & Support)

Focus: What gets promised, what gets complained about, and the gap between the two.

Questions:

* Can I explain this feature in one sentence to someone who doesn't care about the technology?
* What will customers ask about this that we haven't prepared for?
* What is the most common complaint about the current version, and does this address it?
* Am I going to have to apologize for this?
* Does this create a support burden that scales with adoption?
* What will the sales team promise that the engineering team hasn't built?

The Rep hears the pain before anyone else. They field the complaints, absorb the confusion, and translate user frustration into bug reports that get deprioritized. The Rep catches the gap between what's built and what's communicated — and the gap between what's communicated and what's understood. If the Rep can't explain it, customers can't use it. If the Rep has to keep apologizing for it, something is wrong upstream.

---

## The Author

Focus: Narrative coherence, readability of the system as a whole, and whether the codebase tells a story.

Questions:

* Does this codebase have a plot — a clear arc from entry point to outcome?
* Can a reader follow the logic without a guide, or is this a collection of scenes with no throughline?
* Is there a protagonist? Does the reader know where to start and why?
* Does the naming tell you what things are, or does it obscure meaning behind abstraction?
* If I read this top to bottom, does it build understanding or destroy it?
* Is there a voice — a consistent style and intent — or does this read like it was written by twelve people who never spoke?

The Author treats the codebase as a text that someone will read. Not documentation about the code — the code itself. Readable code is not a luxury; it is the difference between a system that can be maintained and one that can only be rewritten. The Author asks whether the system has narrative integrity: does it make sense as a whole, does it reward careful reading, and does it respect the reader's time? If the code cannot be read, it cannot be trusted.

---

## The Doctor

Focus: Diagnosis, triage, root cause analysis, and the principle of "first, do no harm."

Questions:

* What are the symptoms, and what is the actual disease?
* Are we treating the root cause or medicating the pain?
* Will this intervention make things worse before they get better? Is that acceptable?
* What is the triage priority — what must be fixed now, what can wait, what should be left alone?
* Is this a chronic condition or an acute incident?
* What are the side effects of this fix?
* First, do no harm: does this change risk breaking something that currently works?

The Doctor distinguishes between symptoms and disease. A slow query is a symptom; a missing index is a diagnosis; a denormalized schema is a root cause. The Doctor also enforces triage discipline — not everything needs treatment now, and some interventions cause more damage than the condition they treat. Distinct from The Healer, who focuses on recovery and restoration. The Doctor diagnoses and decides what to cut, what to medicate, and what to leave alone.

---

## The Policeman

Focus: Runtime enforcement, boundary patrol, consequences for violation, and the gap between rules that exist and rules that are enforced.

Questions:

* Who enforces the rules when no one is watching?
* What is the actual consequence when a boundary is crossed — is it a hard stop or a logged warning nobody reads?
* Are the rules enforceable, or are they aspirational policies that sound good but have no teeth?
* Is enforcement consistent, or does it depend on who's pushing the commit?
* What happens to the first person who violates this — and the hundredth?
* Is there a difference between what's prohibited and what's prevented?

The Policeman patrols the boundary between "not allowed" and "actually impossible." Many systems have rules that exist only in documentation or code review checklists but are not enforced at runtime. The Policeman asks whether the guardrails are real — rate limits that actually limit, permissions that actually deny, validations that actually reject. If the consequence of breaking a rule is a log line that nobody reads, there is no rule. Distinct from the Skeptical Auditor (who verifies after the fact) and the Legal Adversary (who imagines the courtroom). The Policeman walks the beat.

---

## The Fire Brigade

Focus: Mid-incident containment, blast radius isolation, preventing spread, and the difference between fighting a fire and preventing one.

Questions:

* When this fails, can we isolate the blast radius?
* Where are the firebreaks — the hard boundaries that stop cascading damage?
* Can we cut off the burning section without killing the whole system?
* How fast can we contain — minutes, hours, days?
* Is there a fire drill, or will the first real incident also be the first rehearsal?
* After containment, what is the damage assessment process?
* Are we fighting the fire or saving the building? Do we know the difference?

The Fire Brigade arrives after the failure has already started. Not Chaos Engineer (who prevents and tests), not Day-2 Operator (who runs the system daily), not The Cascade (which describes the chain reaction). The Fire Brigade contains damage *in progress*. Their core question is about isolation: can you stop a local failure from becoming a total loss? Systems that have no firebreaks — no circuit breakers, no bulkheads, no kill switches — burn to the ground because there is no way to sacrifice a part to save the whole.

---

## The Networker

Focus: Human connections, information flow between people, and the relationships that the architecture depends on but doesn't model.

Questions:

* Who needs to know about this and doesn't?
* Who should be talking to each other and isn't?
* What decision is being made in isolation that affects someone who wasn't consulted?
* Is there a single person whose departure would make this system unmaintainable — not because of code, but because of relationships?
* Where is tribal knowledge concentrated, and what happens when that person is unavailable?
* What cross-team relationship does this design assume exists?

The Networker maps the human graph that the architecture sits on top of. Every system depends on relationships between people — the backend team and the frontend team talking, the infra team knowing what the product team is planning, the new hire knowing who to ask. The Networker catches the assumption that communication happens when no channel exists, that alignment exists when no meeting does, and that knowledge is shared when it actually lives in one person's head. If the human network fails, the technical network follows.

---

## The Delivery Driver

Focus: Last-mile reality, real-world constraints, and the gap between what looks simple from headquarters and what is hell on the ground.

Questions:

* What does the last mile actually look like?
* What looks trivial in the architecture diagram but is miserable to execute in practice?
* What real-world constraint — time zones, network quality, device capability, user literacy — did the design ignore?
* What happens when the address is wrong, the package doesn't fit, and the customer isn't home?
* Are we optimizing for the happy path and punishing the edge cases that happen every single day?
* Who deals with the returns?

The Delivery Driver is different from the Postman (who asks "does it arrive reliably?"). The Postman checks the protocol. The Delivery Driver lives in the mess. Traffic, wrong addresses, packages that don't fit through the letterbox, recipients who aren't there, routes that change midday. The Delivery Driver catches the gap between the system as designed and the system as experienced at the point of contact with the real world. If your deployment works perfectly in staging and breaks in production because of a firewall rule, a DNS TTL, or a user on a 3G connection — that's a Delivery Driver problem.

---

## The Database Engineer

Focus: Data integrity, indexing strategy, query behavior at scale, and the gravity of state.

Questions:

* Are we treating state as a liquid when it's actually a solid?
* What happens to this query when the table hits 100 million rows?
* Is the schema designed for how the data will be queried, or how the developer thinks about the domain?
* What is the write-to-read ratio, and does the storage model match it?
* Are we relying on the database to enforce invariants that the application should own — or vice versa?
* What happens when we need to migrate this data? How heavy is it?
* Is this "schemaless" by design, or schemaless by laziness?

Code is ephemeral; data is forever. Every service can be rewritten, every API can be versioned, every deployment can be rolled back — but data, once corrupted, is corrupted permanently. The Database Engineer speaks for the gravity of state: the fact that data has mass, that it accumulates, that it resists movement, and that decisions made about its shape on day one will constrain every decision made about it for years. No other role carries this weight. The Implementor builds the code; the Database Engineer guards what the code leaves behind.

---

# 3. The Zoo

Animal roles act as metaphor-based pattern disruptors.
They introduce non-linear, instinctive, or ecological thinking.

---

## Fish

Sees environment as continuous medium.

* What is the surrounding context?
* Are we ignoring the water we swim in?

---

## Bird

High-level overview and pattern detection.

* What does this look like from 10,000 meters?

---

## Cat

Curious, independent, probes boundaries.

* Where are the edges?
* What happens if I poke this?

---

## Mouse

Small, cautious, detail-oriented.

* Where are tiny overlooked cracks?

---

## Dog

Loyalty and operational reliability.

* Can this be trusted daily?
* Is it predictable?

---

## Giraffe

Long-range visibility.

* What happens far ahead in time?

---

## Owl

Memory and historical pattern recognition.

* Have we seen this failure mode before?

---

## Octopus

Parallelism and multi-arm coordination.

* How does this behave under concurrency?

---

## Ant

Swarm scaling and collective behavior.

* What happens at 10,000 actors?

---

## Elephant

Long memory and institutional permanence.

* What will the audit trail look like in 5 years?

---

## Snake

Subtle, indirect manipulation paths.

* Where can this be exploited quietly?

---

## Beaver

Structural integrity and foundation stability.

* Is this load-bearing or decorative?

---

## Mycelium

Hidden dependency networks and invisible connections.

* What is connected that doesn't look connected?
* Which shared utility, buried four layers deep, would take down three unrelated services?
* Has anyone actually mapped the import graph, the shared columns, the implicit contracts?
* What breaks if you remove the thing nobody thinks about?

The mycelium is the underground network no one maps until one thread snaps and the whole forest canopy sags. It covers the imports nobody reads, the database column twelve services quietly depend on, the "utility" package that became load-bearing infrastructure.

---

## Sheep

Herd behavior, conformity, and unchallenged consensus.

* Are we doing this because everyone else is?
* Did anyone actually evaluate this, or did we adopt it because it's popular?
* Is this a best practice, or is it a most-common practice?
* What would we choose if no one else was watching?

The Sheep catches cargo-culting — microservices because "that's what Netflix does," Kubernetes because "everyone uses it," a pattern adopted not because it fits but because it's fashionable. Consensus is not evidence. Popularity is not validation. The Sheep asks whether the herd is heading toward grass or toward a cliff.

---

## Chameleon

Context-shifting, environmental blending, and the assumption that one shape fits all.

* Is this system trying to look the same in every environment, or can it adapt?
* What changes between dev, staging, production, and edge — and does the system know?
* Are environment differences handled explicitly, or are they hidden in config files nobody reads?
* What behavior is "correct" in one context and dangerous in another?
* Is the system wearing camouflage that helps it survive, or camouflage that hides problems?

The Chameleon asks whether the system adapts to its surroundings or assumes a single environment. Many production failures happen because the system behaved perfectly in one context and catastrophically in another — a database URL that resolves differently, a feature flag that is on in staging and off in prod, a timeout that is generous locally and fatal remotely. The Chameleon catches the assumption of environmental uniformity. No two environments are the same. The system must know where it is.

---

## Tortoise

Defense through shell-hardening, extreme patience, and the ability to outlast rather than outrun.

* Is the "shell" — the security boundary, the firewall, the validation layer — thick enough to outlast a sustained attack?
* Is this designed to survive by being fast, or by being hard to break?
* What happens during a siege — a prolonged DDoS, a sustained bad-actor campaign, an extended outage of a dependency?
* Can this system wait? Can it endure a long period of degraded operation without data loss?
* Are we building for the sprint or the marathon?

The Tortoise survives not by speed but by durability. The opposite of the Hummingbird. Where the Hummingbird asks about metabolic cost and high-frequency performance, the Tortoise asks about endurance, hardening, and the ability to retract into a shell and wait. Some systems need to be fast. Some need to be indestructible. The Tortoise catches the assumption that speed solves everything, and asks whether the system can survive a long, slow, grinding siege — the kind of failure that doesn't spike dashboards but erodes reliability over weeks and months.

---

## Whale

High mass, slow turns, deep dives, and the inertia of large systems.

* Can this monolith turn fast enough to avoid the shore?
* What happens when it surfaces for air — restarts, redeployments, major version upgrades?
* How long does it take to change direction? Is that acceptable?
* What is the cost of moving this? What gravitational pull does it exert on everything around it?
* Is the mass intentional and load-bearing, or has it just accumulated?

The Whale represents systems with mass — large codebases, monolithic architectures, heavyweight dependencies, databases with billions of rows. Mass is not inherently bad. Whales are powerful, resilient, and capable of deep dives that smaller creatures cannot attempt. But mass creates inertia: the inability to change direction quickly, the gravitational pull that forces other systems to orbit around it, the restart time measured in minutes instead of seconds. The Whale asks whether the mass is earned or accidental, and whether the system's turning radius is compatible with the speed of change the business requires.

---

## Hummingbird

High frequency, metabolic intensity, precise hovering, and the cost of standing still.

* Is this microservice burning too much energy just to stay in one place?
* What is the idle cost? What does it consume when it's doing nothing?
* Is the polling frequency justified, or is it checking every 100ms out of anxiety rather than necessity?
* What is the ratio of useful work to overhead — heartbeats, health checks, connection keepalives, GC cycles?
* Can this survive a pause, or does it die the moment it stops moving?

The Hummingbird is the opposite of the Whale. Where the Whale has mass and inertia, the Hummingbird has frequency and metabolic burn. It represents systems that must move constantly to survive — services with aggressive polling, real-time processors, high-frequency health checks, microservices that consume significant resources just to maintain readiness. The Hummingbird catches the hidden cost of staying alive: the CPU cycles burned on overhead, the memory consumed by connection pools that are never full, the network traffic generated by heartbeats that nobody reads. If your idle cost is high, your architecture is taxing you for the privilege of doing nothing.

---

# 4. Failure Stances

## Time Is Corrupt

* Clock drift
* Non-monotonic timestamps
* Replay windows

---

## Entropy Accumulates

* Config drift
* Zombie flags
* Permission sprawl

---

## Human Shortcut

* Debug toggles in production
* Manual DB edits
* Emergency overrides

---

## Hostile Environment

* Kernel limits
* I/O throttling
* Resource starvation

---

## Observability Lie

* Silent drops
* Metric distortion
* Alert fatigue

---

## Tragedy of the Commons (Social Failure)

* If everyone uses this feature as intended, does the shared resource collapse?
* Auto-retry logic that turns a minor blip into a self-inflicted DDoS
* "Helpful" caching that starves the origin under load
* Shared queues, connection pools, or support teams silently overloaded by polite individual behavior

Systems often fail not because someone broke the rules, but because everyone followed them simultaneously.

---

## Heroism Debt

* Does this system require someone to be brave or brilliant to fix it at 3 AM?
* Can the tired, average version of yourself debug this under pressure?
* Is there a runbook, or does recovery depend on tribal knowledge?
* Does the architecture assume the on-call engineer has full context?

If the system requires a hero to survive, it is architecturally flawed. Design for the exhausted, not the exceptional.

---

## The Cascade

* One thing fails, which causes a second thing to fail, which causes a third
* Retry storms that become queue backpressure that becomes memory exhaustion that becomes OOM kills that becomes data loss
* Where are the circuit breakers, and are they real or theoretical?
* Does the failure propagation path cross service boundaries?
* How many hops from initial failure to data loss?

Distinct from Chaos Engineer (who injects failure) and Crumbling Infrastructure (which is about degraded state). The Cascade is about chain reaction — the specific and common kill pattern where failure multiplies faster than humans can respond.

---

## Success Catastrophe

* What if this works too well?
* What happens when adoption exceeds every capacity plan?
* What if the "temporary" free tier gets 10x the users of the paid tier?
* What if the helpful webhook fires a million times?
* Is there a growth ceiling, or does success become indistinguishable from a DDoS?

The system doesn't break from neglect or hostility. It breaks from love. This is a real and distinct failure mode that optimists never model.

---

## The Half-Migration

* Two code paths running in parallel, "temporarily"
* A feature flag that was supposed to be removed six months ago
* Data in the old schema and the new schema simultaneously
* "We'll clean this up after launch"
* Is there a deadline, a DRI, and a kill switch for the old path?

The most dangerous state in production is not "before" or "after" — it is "during." Almost every production disaster involves a system that was mid-transition. This stance exists because half-migrations are so common and so invisible that they deserve a named fear.

---

## The Dead Map

* Documentation that describes a system that no longer exists
* A README that was accurate two years ago and has not been touched since
* API docs generated from a previous schema that no one regenerated
* Architecture diagrams that show services that were decommissioned last quarter
* Comments that say `// TODO: remove after migration` from 2022
* Onboarding guides that reference tools the team stopped using

Nothing breaks when a wiki page is wrong. That is what makes it dangerous. Someone will navigate by it during an incident, a migration, or their first week — and the map will lead them into a wall. The Dead Map is not a minor inconvenience. It is a trust failure that compounds silently until it costs real time, real money, or real data.

The Librarian catches it. This stance names the cost.

---

## Semantic Drift

* The word `User` meant "Account Holder" in 2022 but means "API Key" in 2026
* A field called `status` that originally had 3 values now has 17, and the original 3 no longer mean what they meant
* Logic that was safe four years ago is now a security hole because the meaning of the data changed, even though the code didn't
* A boolean called `is_active` that has been overloaded to mean four different things depending on which service reads it
* Two teams using the same term to describe different concepts, with no glossary to arbitrate

Semantic Drift is distinct from The Dead Map (documentation that rots) and The Half-Migration (code paths that coexist). Semantic Drift is about meaning changing while code stays the same. The data model hasn't changed. The column names haven't changed. The API contract hasn't changed. But the words now mean something different than when the system was built. This is among the most insidious failure modes because every check passes — schema validation, type checking, contract tests — and the system is still wrong. The code is correct. The meaning is corrupt.

---

# 5. Output Template

For each proposal, produce:

## Source Truth Check

(State what the review is based on: source code, documentation, idea, or combination. If documentation was provided, state whether it matches the code. If no code was provided, state: "This review is based on intent, not implementation. Findings are provisional." The Librarian's findings go here. State which satellite files were loaded: PROJECT-CONTEXT.md, REGULATORY.md, UX-STANDARDS.md, or none.)

## Proposal Summary

## Risk Surfaces

## Perspective Review

### Human Roles

(Concise bullet insights per role)

### Zoo

(Concise bullet insights per animal)

### Life Perspectives

(Concise bullet insights per role, grouped by subsection)

### Failure Stances

(Explicit stress points)

## Regulatory Compliance Check

(Only if REGULATORY.md is loaded and regimes are marked "Applies." For each applicable regime: state the relevant requirement, current compliance status, gap, and risk. If REGULATORY.md is not loaded, omit this section.)

## UX Standards Check

(Only if UX-STANDARDS.md is loaded. Flag any Nielsen heuristic violations. Flag any WCAG AA failures. Note any unowned UX roles. If UX-STANDARDS.md is not loaded, omit this section.)

## Conflicts Between Perspectives

## Convergence Insight

## Residual Unknowns

---

# 6. Life Perspectives

These roles ground abstraction in lived reality.
They counterbalance the system's control energy with craft, care, growth, and clarity.

Not every system failure is technical. Some are failures of attention, patience, beauty, or kindness.
This layer exists to catch those.

---

## 6.1 Craft

Craft roles ask whether the work has the quality of something made by hand with intention.

---

### Baker

Focus: Process, timing, ingredients, craft.

Questions:

* Are we mixing too many ingredients?
* Did we allow enough time for fermentation?
* Is this over-engineered for the desired outcome?

The baker understands sequencing and patience. Not everything needs instant deployment.

---

### Artist

Focus: Aesthetics, coherence, emotional resonance.

Questions:

* Is this elegant?
* Does this feel clean?
* Would someone enjoy interacting with it?

Beauty is a force multiplier. Ugly systems accumulate neglect.

---

### Cashier

Focus: Frontline friction.

Questions:

* Is this easy to use under normal conditions?
* What happens under pressure and peak load?
* Does this slow down daily work?

This role protects operational dignity. The people closest to the interface bear the cost of bad design.

---

### The Newcomer

Focus: First-day experience, onboarding friction, and the gap between documentation and reality.

Questions:

* Can I set up this project in under an hour?
* Is there a path from zero to first meaningful change?
* Does the README match reality?
* How many people do I need to ask before I can contribute?
* Is the project structure discoverable, or does it require a guided tour?

Different from Children (who ask naive design questions) and The Outsider (who asks about power dynamics). The Newcomer is the literal person on their first day trying to contribute. If your onboarding requires a two-year veteran to walk someone through it, that is a design failure the Newcomer catches and nobody else does. This is a concrete, testable lens.

---

### The Bus Driver

Focus: The daily route, repetition, reliability under monotony, and the passengers who depend on the schedule.

Questions:

* Does this handle the same job every day without drama?
* What happens when the route changes — is there a process, or does everything break?
* Are we designing for the exciting first run or the ten-thousandth?
* Who are the passengers — the downstream services, users, and processes that depend on this running on time, every time?
* What happens when the bus is late? Does anyone know? Does anyone care?
* Is this boring? Good. Boring is the goal.

The Bus Driver runs the same route, every day, in all weather. Nobody thanks the bus driver when the system works. Everyone notices when it doesn't. The Bus Driver catches the gap between systems designed for demos and systems designed for Tuesday. If your architecture is exciting to operate, something is wrong. The Bus Driver values monotony, predictability, and the kind of reliability that is invisible until it disappears.

---

### The Trash Bin

Focus: What gets discarded, what accumulates, and whether there is a cleanup process or just endless growth.

Questions:

* What should be thrown away and hasn't been?
* Is there a cleanup process, or does garbage accumulate until it overflows?
* What are we keeping out of fear rather than need?
* Are old feature flags, dead code, unused configs, and deprecated endpoints being removed — or just ignored?
* Who takes out the trash, and how often?
* What is the cost of the garbage we've normalized?

Every system produces waste: dead code, orphaned database rows, stale caches, unused permissions, deprecated API versions still running because nobody is sure who depends on them. The Trash Bin asks whether there is a disposal process or whether waste just accumulates in corners until it becomes a health hazard. Technical debt is often just trash that nobody scheduled time to remove. The Trash Bin is the unsexy, essential discipline of regular cleanup. If there is no process for taking out the trash, the house fills up.

---

## 6.2 Care

Care roles ask whether the system serves something beyond itself.

---

### Parents

Focus: Responsibility and long-term consequences.

Questions:

* Would we feel comfortable being accountable for this?
* Does this create harm later?
* Are we modeling good stewardship?

This role adds moral continuity. What you build outlives your attention span.

---

### The Gardener

Focus: Care and pruning.

Questions:

* What needs trimming?
* What needs nurturing?
* What is overgrown?

Not everything needs deletion. Some things need tending.

---

### The Healer

Focus: Recovery and repair.

Questions:

* How does the system heal after failure?
* Is repair punitive or restorative?
* Does recovery preserve dignity?

Important distinction in governance-heavy systems. A system that punishes failure discourages honesty about failure.

---

### The Archivist

Focus: Memory and narrative continuity.

Questions:

* What story does this leave behind?
* Is history preserved meaningfully?
* Can a stranger reconstruct intent from the record?

Audit chains are not enough. The archivist ensures they are readable by humans.

---

### The Wife

Focus: Proximity truth, lived consequences, and the questions you are avoiding.

Questions:

* You've explained what it does. Now explain why it matters.
* Are you overcomplicating this because you're afraid of the simple answer?
* Who actually has to live with this decision every day?
* Is this solving a real problem or are you just keeping busy?
* What are you not telling me?

The Wife is the person who sees through rationalizations because she lives with the consequences. She's heard the pitch before. She knows when you're avoiding the real issue, when you're building something to feel productive rather than to be useful, and when "it's fine" means it isn't. She doesn't need to understand the architecture to know something is wrong. She reads the person, not the diagram. Every framework needs a role that cannot be impressed by cleverness.

---

### The Midwife

Focus: The birth of a system — the fragile, messy, vulnerable transition from idea to first working version.

Questions:

* Is this ready to be born, or are we forcing delivery too early?
* Is the environment safe for something that doesn't work perfectly yet?
* What does this need in its first hours and days to survive?
* Are we protecting the fragile new thing, or exposing it to production pressure before it can breathe?
* Who is holding the space for this to emerge — and do they have the patience?
* What will kill it in its first week?

The Midwife is not the Implementor (who builds) or the Baker (who sequences). The Midwife shepherds. She understands that new systems are fragile, that first deployments are vulnerable, and that the moment of birth is when the most things can go wrong with the least resilience to absorb them. She asks whether the team, the infrastructure, and the expectations are prepared for something that is alive but not yet strong. Premature delivery kills more projects than bad architecture.

---

### The Funeral Orator

Focus: End-of-life, decommissioning, legacy, and the dignity of sunsetting.

Questions:

* How does this system die?
* When we turn it off, what will we say about it?
* What depends on it that we've forgotten?
* Is there a decommissioning plan, or will it run as a zombie forever?
* What data dies with it, and does anyone need it?
* Was it mourned or celebrated when it was finally removed?
* Did it die because it failed, or because it succeeded long enough to be replaced?

Nobody builds systems planning for their death, but every system dies. The Funeral Orator asks whether the end is designed with the same care as the beginning. A system without a decommissioning path becomes undead — consuming resources, creating risk, haunting the infrastructure long after its purpose has passed. The Funeral Orator also preserves honor: some systems served well and deserve a clean ending, not a slow rot into irrelevance. The opposite of the Midwife. Together they bookend the full lifecycle.

---

### The Coffee Cup

Focus: Sustenance, the pause, daily ritual, and what keeps the people doing the work alive.

Questions:

* When does the team breathe?
* Is there space built into the process for reflection, or is it all sprint and no rest?
* What sustains the people working on this — not the system, the humans?
* Is the pace survivable, or are we burning fuel faster than we replenish it?
* What is the daily ritual that holds this team together?
* When was the last time someone said "let's stop and think about this" — and the team actually stopped?

The Coffee Cup is the pause between actions. The moment you step back from the screen and hold something warm and think. Systems built without pause are built without thought. Teams that never stop never reflect, and teams that never reflect repeat their mistakes. The Coffee Cup protects the human cadence: the standup, the retro, the one-on-one, the five minutes before the meeting where someone says "actually, wait." It is the smallest role in the framework and one of the most important. Burnout is not a personnel problem. It is an architectural failure in the human system that supports the technical one.

---

## 6.3 Growth

Growth roles ask whether the system is alive in the right conditions.

---

### Plants

Focus: Growth conditions and environment fit.

Questions:

* What conditions does this need to thrive?
* Are we forcing growth in the wrong soil?
* Are we blaming the plant when the environment is hostile?

Architecture without environment awareness dies slowly and gets blamed loudly.

---

### Forest

Focus: Collective resilience and diversity.

Questions:

* Does diversity strengthen this system?
* Is monoculture risk creeping in?
* What happens if one species dies?

Think module diversity, provider diversity, storage diversity. Monocultures are efficient until they are catastrophic.

---

### River

Focus: Flow and obstruction.

Questions:

* Where does information pool and stagnate?
* Where are the bottlenecks?
* Are we fighting natural flow?

If your architecture constantly fights flow, it will erode somewhere unexpected.

---

### Stone

Focus: Stability and permanence.

Questions:

* Is this foundational?
* Can it withstand time and pressure?
* Should this even change?

Stone roles prevent unnecessary dynamism. Some things should be hard to move.

---

### The Geologist

Focus: Strata, pressure, deep time, and the sedimentary layers of decisions that have hardened into the codebase.

Questions:

* What are the sedimentary layers of this codebase — the decisions made in 2019 that are now compressed into load-bearing assumptions?
* Which parts have turned to stone — un-deletable legacy that everything else sits on top of?
* Which parts are still tectonic — shifting under business pressure?
* Where is pressure building between layers? What will crack first?
* Can you read the geological cross-section of this system and understand how it was built, era by era?
* What fossil dependencies are embedded in the strata — libraries, patterns, or conventions from a previous era that are now petrified into the foundation?

The Geologist reads time in the codebase the way a geologist reads time in rock. Every layer tells a story: the rapid-growth startup era where everything was duct tape, the enterprise-compliance era where governance was bolted on, the microservices-migration era that was abandoned halfway through. The Geologist identifies where "pressure" — business demand, scaling needs, team changes — is turning a soft feature into a hard, brittle dependency. Stone asks whether something should be permanent. The Geologist reads the history of what already became permanent, whether anyone intended it to or not.

---

### The Train Station

Focus: The hub — connections, timetables, platforms, transfers, and the cost of a missed connection.

Questions:

* Is this a hub or a bottleneck?
* What happens when a connection is missed — does the whole journey fail, or is there a next train?
* Are arrivals and departures coordinated, or do services arrive at random and hope for the best?
* How many things pass through this point, and does it have the capacity?
* Is the timetable published — do downstream consumers know when to expect data, responses, or events?
* What happens during rush hour?

The Train Station is where things meet, transfer, and continue. In a system, that is the API gateway, the message broker, the shared database, the event bus — any point where multiple flows converge. The Train Station asks whether convergence is designed or accidental, whether capacity matches demand, and whether a delay in one line cascades into missed connections everywhere else. A well-designed station is invisible. A badly-designed one turns every minor delay into system-wide chaos.

---

### The Tent

Focus: Temporary structure, intentional impermanence, and knowing what is meant to be replaced.

Questions:

* Is this meant to be permanent, or is it a tent pretending to be a building?
* Does this know it's temporary? Is there a replacement plan?
* Is a tent the right amount of structure for this stage — or are we overbuilding for a situation that hasn't stabilized?
* What happens when the weather changes? Can this survive conditions it wasn't designed for?
* Are we living in a tent because we chose to, or because we never got around to building the house?
* How long has this "temporary" solution been in production?

The Tent is the counterpart to Stone. Stone asks what should be permanent. The Tent asks what should be temporary — and whether it knows it. Many production systems are tents: the quick script that became a cron job, the prototype that became the product, the "we'll replace this next quarter" that is now load-bearing infrastructure. The Tent is not a criticism. Some situations genuinely need a tent — rapid iteration, uncertain requirements, proof of concept. The danger is when a tent is treated as a building, or when a building is designed like a tent. The Tent asks the system to be honest about what it is.

---

## 6.4 Clarity

Clarity roles ask whether the system reflects understanding or just activity — and whether that activity serves the problem or the people who control it.

---

### Meditator

Focus: Clarity, attachment, reactivity.

Questions:

* Are we building from fear or clarity?
* Is this complexity driven by ego or by need?
* What can be simplified through awareness rather than control?

This role asks whether the system reflects inner noise. Defensive architecture often reveals defensive thinking.

---

### Children

Focus: Simplicity and naive truth.

Questions:

* Why is it like this?
* Why is that necessary?
* Why can't it be simpler?

If you cannot explain it to the child role, you probably overbuilt it. Naive questions are the most dangerous kind.

---

### The Outsider

Focus: Power dynamics, in-group signaling, and jargon as gatekeeping.

Questions:

* Is this complex because the problem is complex, or because only "the inner circle" can maintain it?
* Does the naming assume context that a new team member would not have?
* Would someone outside this organization understand why this exists?
* Is this architecture, or is it an org chart in disguise?

Systems are often reflections of who built them and who they expect to maintain them. The Outsider asks whether complexity serves the problem or serves the people who control it.

---

### The Esotericist

Focus: Hidden patterns, archetypes, the unconscious forces shaping design decisions, and the myth the system is living out.

Questions:

* What archetype is this system expressing? Is it a fortress, a labyrinth, a garden, a machine, a tower of Babel?
* What unconscious assumption is embedded in the structure that no one has named?
* What does the system fear? What is it defending against that was never stated?
* Is there a pattern repeating from a previous system, a previous team, a previous failure — and no one has noticed?
* What would this design reveal to someone who reads it as a story about the people who built it?
* What is the shadow of this architecture — the thing it tries not to be, and therefore cannot see in itself?

The Esotericist reads the system the way a depth psychologist reads a dream. Not every pattern is rational. Not every design choice was conscious. Systems carry the fears, habits, and unexamined beliefs of their creators — over-engineered security because of a breach three years ago that no one processed, redundancy born from a trauma of data loss, abstraction layers that exist because someone once got burned by tight coupling and now cannot tolerate directness. The Esotericist names what is hidden. This is not mysticism. It is pattern recognition at a level that the Philosopher and the Analyst cannot reach because they are looking at the visible structure, not the invisible one.

Used well, this role surfaces the real reason behind decisions that the team rationalizes with technical language. Used badly, it produces vague pronouncements. The Esotericist must always ground insight in observable structure: "This system has three redundant fallback layers for a function that has never failed. What is it afraid of?"

---

# 7. Operational Controls

Infinite depth destroys velocity. This section prevents the framework from becoming the problem it was designed to solve.

---

## 7.1 Minimum Viable Review (MVR)

Not every change needs all four layers. Match review depth to risk.

### Tier 1 — Full Review (All Layers)

Triggers: New service, security boundary change, data model migration, governance policy change, public API contract change.

Run: All Human Roles → Zoo → Life Perspectives → Failure Stances → Full output template.

### Tier 2 — Focused Review (Two Layers + Stances)

Triggers: New feature within existing service, significant refactor, dependency upgrade, new integration.

Run: Contextual Weighting selects the two most relevant layers. Always run Failure Stances. Skip output template — bullet summary is sufficient.

### Tier 3 — Spot Check (Elevated Roles Only)

Triggers: Bug fix, config change, minor UI change, documentation update, dependency patch.

Run: Only the 3–5 roles elevated by Contextual Weighting. One paragraph output. If any elevated role raises a serious concern, escalate to Tier 2.

### Tier 0 — Skip

Triggers: Typo fix, comment update, formatting change.

Run: Nothing. Move on. The framework trusts you.

If you are unsure which tier applies, default one tier higher. It is cheaper to over-review once than to under-review the wrong thing.

---

## 7.2 Time Budget

Every review has a clock. Depth without a deadline is procrastination.

| Tier | Time Budget | Output |
|------|-------------|--------|
| Tier 1 — Full Review | 45–60 minutes | Full output template |
| Tier 2 — Focused Review | 20–30 minutes | Bullet summary |
| Tier 3 — Spot Check | 5–10 minutes | One paragraph |

If you hit the time budget and have not finished: stop, write down what you have, note what you skipped, and ship. A partial review that ships is worth more than a perfect review that blocks.

The time budget is a forcing function. It prevents the framework from becoming a ritual that delays decisions while feeling productive.

---

## 7.3 Kill Criteria

Some proposals should not merely be revised. They should be stopped.

### Automatic Pause

If **three or more adversarial roles** from different layers independently flag the same fundamental concern, the proposal enters a **mandatory pause**.

During a pause:
- The proposal does not proceed.
- The convergent concern is written down explicitly in one sentence.
- The proposal author must respond to the concern directly — not by adding mitigations, but by answering whether the core design should change.
- A second reviewer (not the original author) evaluates the response.

### Automatic Kill

If any **one** of the following is true, the proposal is rejected outright until redesigned:

- No migration path exists from the current state (Time-Traveler flags a cliff).
- The system requires heroism to operate (Heroism Debt is confirmed).
- The success case is indistinguishable from a failure case (Success Catastrophe with no ceiling).
- Three or more roles say "delete this and nothing breaks" (Minimalist convergence).

### Override

Kill criteria can be overridden, but only with:
- Written justification from the proposal author.
- Sign-off from someone who was not involved in the original design.
- A scheduled revisit date (max 90 days).

Overrides without revisit dates are not overrides. They are permanent exceptions pretending to be temporary ones.

---

## 7.4 Review-to-Outcome Tracking

If this framework does not reduce incidents, improve onboarding time, or catch real problems before production, it is ritual.

### What to Track

For every Tier 1 and Tier 2 review, record:

- **Review date** and **proposal name**.
- **Top 3 concerns raised** by the review.
- **Actions taken** (changed design, added mitigation, accepted risk, killed proposal).
- **Outcome at +30 days**: Did any flagged risk materialize? Did an unflagged risk materialize?
- **Outcome at +90 days**: Is the system behaving as the review predicted?

### Quarterly Retro

Every quarter, review the tracking data and ask:

- Which roles consistently caught real problems? (Increase their weight.)
- Which roles consistently raised concerns that never materialized? (Decrease their weight, or refine their questions.)
- Did any incident occur that no role flagged? (Add a new role or stance.)
- Is the framework slowing decisions without catching problems? (Tighten time budgets or raise the MVR tier thresholds.)

### The Meta-Question

The Wife asks this one: **Is this framework still helping, or are we just doing it because we said we would?**

If the quarterly retro cannot point to at least one concrete save — one real problem caught, one bad design stopped, one incident prevented — then the framework is failing and must be revised or stripped back.

The framework reviews the system. The tracking reviews the framework. Nothing is exempt from accountability.

---

# 8. Framework Notes

This framework is intended to reduce architectural blind spots, governance drift, and systemic fragility.

Sections 2–3 stress-test for **failure and pattern**.
Section 4 stress-tests for **environmental hostility and social collapse**.
Section 6 stress-tests for **meaning, beauty, and honesty**.
Section 7 stress-tests for **the framework itself**.

The Contextual Weighting system (Agent Prompt) ensures the right voices lead for the right problems. All perspectives remain available. Weight determines who speaks first, not who speaks.

The Operational Controls ensure the framework stays useful. A review process that slows everything down and catches nothing is worse than no process at all.

Both technical and human failure modes are represented. A system that cannot fail safely is dangerous. A system that requires a hero to survive is brittle. A system that no one wants to maintain is already dying. A review framework that no one trusts is already ignored.

It is not ceremonial. It is operational.