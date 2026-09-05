// @ts-check
/**
 * Linked attacks: the list of campaigns, and one campaign with its members
 * and the merged relationship graph.
 */
import { api } from "../api.js";
import { html, mount, must } from "../dom.js";
import { formatDate, plural } from "../format.js";
import { severityForScore } from "../labels.js";
import { casesTable } from "../ui/cases-table.js";
import { createGraph, graphLegend } from "../ui/graph.js";
import { categoryChip, chip, emptyState, pageHead, riskBar, section, skeleton } from "../ui/primitives.js";

/** @typedef {import('../types.js').Campaign} Campaign */

/**
 * @param {Campaign} campaign
 */
function campaignCard(campaign) {
  return html`<a class="card card--pad card--link campaign-card" href="#/campaigns/${encodeURIComponent(campaign.id)}">
    <div class="campaign-card__head"><b class="truncate">${campaign.name}</b>${riskBar(campaign.max_risk, severityForScore(campaign.max_risk))}</div>
    <div class="hint">${plural(campaign.email_ids.length, "email")} · last seen ${formatDate(campaign.updated_at)}</div>
    <div class="cluster section__spacer"></div>
    <div class="cluster">${Object.keys(campaign.categories).map(categoryChip)}</div>
    <div class="hint subsection">${campaign.countries.join(", ") || "no locations"}</div>
  </a>`;
}

/** @type {import('../router.js').View} */
export async function campaignsView(container) {
  mount(
    container,
    html`${pageHead(
        "Linked attacks",
        "When two emails share the same sending computer, sender, link or attachment, they were almost certainly sent by the same person. MailTrace groups them automatically so you can see the whole campaign instead of one email at a time.",
      )}
      <div id="campaigns">${skeleton(2)}</div>`,
  );
  const campaigns = await api.listCampaigns();
  mount(
    must("#campaigns", container),
    campaigns.length > 0
      ? html`<div class="grid grid--cards">${campaigns.map(campaignCard)}</div>`
      : emptyState(
          "No linked attacks yet",
          "A group appears automatically once two checked emails share something strong, such as the same sending computer or the same link.",
        ),
  );
}

/** @type {import('../router.js').View} */
export async function campaignView(container, id) {
  mount(container, skeleton(3));
  const { campaign, emails, graph } = await api.getCampaign(id);
  mount(
    container,
    html`<a href="#/campaigns" class="back-link">← Back to linked attacks</a>
      ${pageHead(
        campaign.name,
        `${plural(campaign.email_ids.length, "email")} linked together · worst risk ${campaign.max_risk} · first seen ${formatDate(campaign.created_at)}`,
      )}
      ${section(
        "What links them",
        html`<div class="cluster">${campaign.indicators.length > 0 ? campaign.indicators.map((indicator) => chip(indicator, "neutral", { mono: true })) : html`<span class="hint">—</span>`}</div>`,
        { note: "These exact things appear in more than one of the emails below." },
      )}
      ${section("The emails", casesTable(emails))}
      ${section("All of it on one map", html`<div id="graph" class="graph graph--tall"></div>${graphLegend()}`, {
        note: "Every email in this group drawn together. Circles sitting between two emails are the shared pieces of the attacker's setup, which is exactly what an investigator follows.",
      })}`,
  );
  return createGraph(must("#graph", container), graph);
}
