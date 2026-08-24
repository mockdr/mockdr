# UX-STANDARDS.md

| Field | Value |
|---|---|
| **Document** | UX-STANDARDS.md — UX Design Standards, Roles & Institutions |
| **Version** | 1.0.0 |
| **Parent** | TEAMS.md v1.3.0 |
| **Last Modified** | 2025-02-21 |

---

## How This Document Is Used

When TEAMS.md is loaded alongside this file, the following roles reference it directly:

- **The User** — checks whether the design respects the person using it.
- **Artist** — checks whether the design is coherent and beautiful.
- **Cashier** — checks whether the interface works under pressure.
- **The Newcomer** — checks whether first contact is survivable.
- **Children** — checks whether the design can be understood simply.
- **Cognitive Load Analyst** — checks whether the interface respects human limits.
- **The Rep** — checks whether the experience matches what was communicated.
- **The Author** — checks whether the interface tells a readable story.
- **The Delivery Driver** — checks whether the UX survives real-world conditions (slow networks, small screens, accessibility needs).

**If a UX heuristic is consistently violated, it should be flagged as a finding with the same severity as a technical bug.** Bad UX is not a cosmetic issue. It is a functional failure experienced by the user.

---

## 1. UX Design Roles

A proper UX process involves specialized roles. In a small team, one person may hold several. In a review, each lens should still be applied even if there is no dedicated person.

### Core Roles

| Role | Focus | TEAMS.md Parallel |
|---|---|---|
| **UX Researcher** | Talks to actual users. Runs interviews, usability tests, surveys. Without this, UX is guesswork with nice fonts. | The User, The Rep |
| **UX Designer** | Interaction flows, wireframes, prototypes. Structural thinking. | Artist, Cognitive Load Analyst |
| **UI Designer** | Visual layer. Color, typography, spacing, the thing people see. | Artist |
| **Information Architect** | How content and navigation are structured. Where things live and why. | The Author, Cognitive Load Analyst |
| **Interaction Designer** | Micro-interactions, transitions, feedback. What happens when you click, hover, wait. | Cashier, Artist |
| **Content Strategist / UX Writer** | The words. Error messages, labels, onboarding copy. Massively undervalued. | The Author, The Rep, Children |
| **Accessibility Specialist** | WCAG compliance, screen readers, keyboard navigation, color contrast, cognitive accessibility. | The Delivery Driver, The Outsider |
| **Service Designer** | The full journey, not just the screen. Before and after the digital touchpoint. | Systems Ecologist, Parents |
| **Design System Lead** | Component library, tokens, patterns. Consistency at scale. | Baker, The Bus Driver |
| **Usability Tester** | Watches real people fail and documents why. The most humbling role. | The User, Children |

### The Key Insight

If you don't have a dedicated person for a role, the role still exists. The question is whether anyone is doing it, or whether it's falling through the cracks. In greenfield, establish which UX lenses are covered and which are unowned.

---

## 2. Usability Heuristics

### Nielsen's 10 Usability Heuristics (NNG)

The closest thing UX has to commandments. Every interface review should check against these.

| # | Heuristic | What It Means | What Violation Looks Like |
|---|---|---|---|
| 1 | **Visibility of System Status** | The system always keeps users informed about what is going on. | Loading with no indicator. Actions with no feedback. Silent failures. |
| 2 | **Match Between System and Real World** | Use language and concepts familiar to the user, not internal jargon. | Error messages with HTTP status codes. Labels that use database field names. |
| 3 | **User Control and Freedom** | Users need a clearly marked "emergency exit" — undo, cancel, back. | No undo. Destructive actions without confirmation. No way to go back. |
| 4 | **Consistency and Standards** | Follow platform conventions. Same action, same result, everywhere. | A button that says "Submit" in one form and "Send" in another. Mixed icon styles. |
| 5 | **Error Prevention** | Design to prevent errors before they happen. | Free-text input where a dropdown would work. No validation until after submission. |
| 6 | **Recognition Rather Than Recall** | Minimize memory load. Make options visible. | Navigation that requires remembering codes. No breadcrumbs. |
| 7 | **Flexibility and Efficiency of Use** | Accelerators for experts. Shortcuts, defaults, customization. | No keyboard shortcuts. No way to set defaults. Every action takes the same number of clicks. |
| 8 | **Aesthetic and Minimalist Design** | Every extra unit of information competes with relevant information. | Cluttered dashboards. Information overload. Decorative elements that add no meaning. |
| 9 | **Help Users Recognize, Diagnose, and Recover from Errors** | Error messages in plain language, indicating the problem and suggesting a solution. | "Error 500." "Invalid input." "Something went wrong." |
| 10 | **Help and Documentation** | Even if the system can be used without docs, help should be searchable and task-focused. | No help. Help that is a PDF manual. Help that doesn't match the current version. |

---

## 3. Accessibility Standards

### WCAG 2.2 — The Four Principles (POUR)

| Principle | Meaning | Key Requirements |
|---|---|---|
| **Perceivable** | Information must be presentable in ways all users can perceive. | Text alternatives for images. Captions for video. Sufficient color contrast (4.5:1 for normal text). Content readable without CSS. |
| **Operable** | Interface must be operable by all users. | Full keyboard navigability. No time limits (or adjustable). No content that causes seizures. Skip navigation links. |
| **Understandable** | Information and operation must be understandable. | Readable text. Predictable navigation. Input assistance (labels, error identification, suggestions). |
| **Robust** | Content must be robust enough for diverse user agents, including assistive technology. | Valid HTML. ARIA roles used correctly. Compatible with screen readers. |

### Conformance Levels

| Level | Meaning | Typical Requirement |
|---|---|---|
| **A** | Minimum. Basic accessibility. | Required for any public-facing product. |
| **AA** | Standard. The legal baseline in the EU (EAA/BFSG/BITV). | **This is the target unless stated otherwise.** |
| **AAA** | Ideal. Not required but aspirational. | Rarely achievable across an entire site. Target for critical flows. |

### Accessibility Checklist (Minimum)

- [ ] All images have meaningful `alt` text (or `alt=""` for decorative)
- [ ] All form inputs have associated `<label>` elements
- [ ] Color contrast meets 4.5:1 (normal text) / 3:1 (large text)
- [ ] Full keyboard navigation (Tab, Enter, Escape, Arrow keys)
- [ ] Focus indicators are visible
- [ ] No information conveyed by color alone
- [ ] Page language is declared (`lang` attribute)
- [ ] Headings are hierarchical and semantic (`h1` → `h2` → `h3`)
- [ ] Error messages identify the field and suggest correction
- [ ] Skip-to-content link exists
- [ ] No auto-playing media
- [ ] Touch targets are at least 44x44px
- [ ] Responsive down to 320px width without horizontal scroll

---

## 4. Standards Bodies & Institutions

### Primary References

| Institution | What They Provide | URL |
|---|---|---|
| **Nielsen Norman Group (NNG)** | Usability heuristics, research methodology, UX benchmarking | nngroup.com |
| **W3C / WAI** | WCAG, ARIA, accessibility standards | w3.org/WAI |
| **ISO 9241** | Ergonomics of human-system interaction (Part 210: human-centered design) | iso.org |
| **ISO 25010** | Software quality model including usability as a quality characteristic | iso.org |
| **Design Council (UK)** | Double Diamond process model (Discover, Define, Develop, Deliver) | designcouncil.org.uk |

### Professional & Educational

| Institution | What They Provide |
|---|---|
| **UXPA** (User Experience Professionals Association) | Professional body, conferences, certification |
| **Interaction Design Foundation (IxDF)** | Education, reference material, widely used |
| **ACM SIGCHI** | Academic research on human-computer interaction |
| **IDEO** | Design thinking methodology, influential in service design |

### Legal / Regulatory (UX-Specific)

| Standard | Jurisdiction | Key Requirement |
|---|---|---|
| **European Accessibility Act (EAA)** | EU | Digital products and services must meet accessibility standards. Enforcement from June 2025. |
| **BFSG** (Barrierefreiheitsstärkungsgesetz) | Germany | German implementation of EAA. Products/services placed on market after June 28, 2025. |
| **BITV 2.0** | Germany | Federal accessibility regulation for public sector. Based on WCAG. |
| **EN 301 549** | EU | European standard for ICT accessibility. Referenced by EAA. |
| **DIN EN ISO 9241-110** | Germany | German adoption of ISO usability standard. Dialogue principles. |

---

## 5. Design Process Integration

### When to Apply UX Review in the Development Cycle

| Phase | UX Activity | TEAMS.md Roles Active |
|---|---|---|
| **Before coding** | User research, personas, journey maps, wireframes | The User, UX Researcher, Service Designer |
| **During design** | Prototypes, usability testing, accessibility audit | Artist, Interaction Designer, Accessibility Specialist |
| **During build** | Component review, pattern adherence, content review | Baker, Cashier, The Author, Design System Lead |
| **Before launch** | Full usability test, accessibility audit, real-device testing | The Delivery Driver, The Newcomer, The Rep |
| **After launch** | Analytics, feedback loops, iteration | The User, Systems Ecologist, The Coffee Cup |

### Greenfield-Specific UX Considerations

In greenfield:

- **Establish the design system before building features.** Components first, screens second. This is the Baker's sequencing applied to design.
- **Define the accessibility target (WCAG AA) on day one.** Retrofitting accessibility is 10x harder than building it in.
- **Name things from the user's perspective, not the developer's.** The Content Strategist and The Author catch this.
- **Prototype before you build.** The cheapest usability test is the one run on a wireframe.
- **Test with real users as early as possible.** The User role in TEAMS.md is an approximation. It is not a substitute for actual user research.

---

*This document is a reference, not a process. It tells the reviewer what standards exist and what to check against. The process lives in TEAMS.md.*