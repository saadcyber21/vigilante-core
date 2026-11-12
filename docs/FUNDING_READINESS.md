# Vigilante Core: funding-readiness brief

## The pitch

**Vigilante Core is an evidence-first AI security operations assistant for small teams. It turns an incoming alert into a concise investigation brief that shows the exact event fields behind its assessment, separates facts from hypotheses, and suggests safe next steps. It is self-hosted, and humans retain control of response decisions.**

This is the intended positioning, not a claim that the current product already outperforms other SOC tools. The current code is an early MVP. Baseline severity scoring remains deterministic. An opt-in AI brief is now implemented, but it needs a configured provider and real-world validation.

## Why it can be different

The product should compete on **inspectable reasoning and customer control**, not on an unsupported promise of autonomous security. The brief asks an AI model to cite specific alert fields, classifies confidence, separates hypotheses from observations, and includes limitations. The API validates that every evidence citation maps to a real payload path and exactly matches the supplied value. Model/provider metadata and generated/failed status are audit logged. Only an analyst-triggered analysis sends the selected alert to the configured provider; the provider key stays on the server. The model cannot execute the suggested actions.

This provides an initial technical wedge, not yet a defensible moat. The moat would have to come from trusted integrations, customer-specific workflow learning, evaluation data, explainability and deployment choices that users value enough to pay for.

## Best initial customer to test

Start with a narrowly defined customer: a small organization that has security alerts but no 24/7 SOC, and already uses one or two common alert sources. Interview likely buyers before committing to an industry. The current product is single-deployment and is not SaaS-grade multi-tenant, independently certified, or an enterprise SIEM replacement. Do not sell it as any of those things.

## Evidence the Sharks will ask for

Do not invent revenue, savings, accuracy, customers, or market-size numbers. Before a serious pitch, recruit a handful of design partners and test real workflows with permission. Measure time from alert arrival to a reviewed investigation, analyst acceptance or correction rate, evidence citation accuracy, and false or unsupported claims. Record paid pilot commitments, renewals, and the actual security tools customers already use. Show a working end-to-end demo on synthetic data and disclose what is not live.

A first credible milestone is a small number of active pilots plus repeated measured improvement in investigation time without a rise in unsupported claims. Next, convert pilots into paid usage, define a simple pricing model tied to customer value, and obtain security/privacy review for the deployment model. Until then, the pitch is an early product seeking validation, not a proven investment opportunity.

## 60-second pitch draft

“Small teams receive security alerts but often lack the staff to investigate each one quickly. Vigilante Core is a self-hosted, evidence-first AI investigation assistant. An analyst selects an alert and gets a short brief with the exact event fields supporting each observation, clearly marked hypotheses, confidence, limitations, and safe next steps. Unlike a black-box recommendation, the evidence can be checked; unlike an autonomous response agent, it cannot take action. We’re validating the workflow with [number] design partners and measuring [verified result]. We plan to charge [validated pricing] to [specific buyer]. We’re seeking [amount] for [specific milestones], and we’re offering [equity percentage] based on a valuation we can justify.”

Replace every bracket with verified facts. Do not use the pitch until the customer, result, pricing, funding amount, and equity offer are real and reviewed with appropriate legal and financial advisers.

## Next 90 days

1. Pick one alert source and one narrow customer profile; interview prospective buyers before expanding features.
2. Run an opt-in pilot with synthetic data first, then customer-approved data under clear provider/privacy terms.
3. Build a labeled evaluation set with expected evidence paths and analyst-reviewed outcomes; report citation precision and failure cases.
4. Measure investigation time against the customer's current workflow and document the baseline.
5. Convert at least some pilot interest into paid pilots or written purchase intent; record retention and usage.
6. Improve deployment, data handling, recovery, and security posture before making enterprise claims.
7. Update the demo, one-page deck, and pitch only with evidence from the pilots.

## Not yet production or enterprise ready

This upgrade adds the on-demand AI investigation loop, exact payload-evidence checks, stored analyst feedback, aggregate quality signals, and a request-body limit. It does **not** add native SIEM/EDR connectors, background ingestion queues, automated model benchmarking on a labeled corpus, multi-tenant SaaS isolation, schema migrations, distributed rate limiting, audit/data-retention controls, high availability, or independent security certification. The current product should remain a single-organization self-hosted pilot until those deployment and security gaps are designed and tested. Do not claim SOC 2, compliance, enterprise readiness, analyst-grade accuracy, or autonomous response.

**Funding reality:** no code change can make a Shark Tank investment likely or guarantee selection. ABC asks for an investable business or product and entrepreneurs seeking investment. Customer proof, a clear business model, founder readiness, and credible financials are still needed. Shark Tank is a US program; confirm the current casting rules and legal eligibility directly with the official application before applying.
