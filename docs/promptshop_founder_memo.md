# PromptShop Founder / CTO Memo

## Positioning

AgentGate should be presented to PromptShop as the trust engine behind a
curated AI solutions marketplace, not as a generic security scanner.

The product story is simple:

1. a seller submits a solution
2. PromptShop verifies declared behavior before publication
3. a reviewer gets a publish recommendation with evidence
4. buyers get stronger trust signals on the listing

## Why this fits PromptShop

PromptShop already has to solve a trust problem if it wants to curate and
recommend third-party AI solutions with confidence:

- what does this solution actually do?
- what data can it access?
- what integrations does it call?
- does its real runtime behavior match the listing copy?

AgentGate gives PromptShop a concrete answer to those questions.

## The strongest pitch

"PromptShop Verified" is a workflow powered by AgentGate that helps PromptShop
verify seller-submitted AI solutions before they are listed or sold.

## Demo narrative

Use the demo to show:

- a clean support listing that is ready to publish
- a suspicious listing that requires manual review
- a stealth exfiltration listing that gets blocked

The value is not only the verdict. The value is the review surface:

- declared vs observed domains
- declared vs observed tools
- customer data access summary
- reviewer action items
- buyer-facing trust card inputs

## What to emphasize in conversation

- This improves PromptShop's curation and review workflow.
- It gives enterprise buyers a stronger trust story.
- It turns security into a product advantage for the marketplace.
- It is realistic to integrate into seller onboarding and listing approval.

## Practical next steps for PromptShop

1. Run AgentGate as part of seller submission intake.
2. Store the JSON result in a reviewer queue.
3. Show a compact trust summary on approved listings.
4. Require rescans whenever a seller updates a solution image or manifest.
