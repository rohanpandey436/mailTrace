// @ts-check
/** Linked attacks: the campaign list, and one campaign with its merged graph. */
import { api } from "../api.js";
import { formatDate, plural } from "../format.js";
import { useAsync } from "../hooks.js";
import { severityForScore } from "../labels.js";
import { Fragment, html } from "../react.js";
import { CasesTable } from "../ui/cases-table.js";
import { GraphLegend, RelationshipGraph } from "../ui/graph.js";
import { categoryChip, chip, emptyState, errorState, pageHead, riskBar, section, skeleton } from "../ui/primitives.js";

/** @typedef {import('../types.js').Campaign} Campaign */

/**
 * @param {{ campaign: Campaign }} props
 */
function CampaignCard({ campaign }) {
  return html`<a class="card card--pad card--link campaign-card" href=${`#/campaigns/${encodeURIComponent(campaign.id)}`}>
    <div class="campaign-card__head">
      <b class="truncate">${campaign.name}</b>${riskBar(campaign.max_risk, severityForScore(campaign.max_risk))}
    </div>
    <div class="hint">${plural(campaign.email_ids.length, "email")} · last seen ${formatDate(campaign.updated_at)}</div>
    <div class="cluster section__spacer"></div>
    <div class="cluster">${Object.keys(campaign.categories).map((category) => html`<${Fragment} key=${category}>${categoryChip(category)}</>`)}</div>
    <div class="hint subsection">${campaign.countries.join(", ") || "no locations"}</div>
  </a>`;
}

export function CampaignsView() {
  const { data, error, loading, reload } = useAsync(() => api.listCampaigns(), []);
  const body = () => {
    if (error) return errorState(error, reload);
    if (loading || !data) return skeleton(2);
    if (data.length === 0) {
      return emptyState(
        "No linked attacks yet",
        "A group appears automatically once two checked emails share something strong, such as the same sending computer or the same link.",
      );
    }
    return html`<div class="grid grid--cards">${data.map((campaign) => html`<${CampaignCard} key=${campaign.id} campaign=${campaign} />`)}</div>`;
  };
  return html`<${Fragment}>
    ${pageHead(
      "Linked attacks",
      "When two emails share the same sending computer, sender, link or attachment, they were almost certainly sent by the same person. MailTrace groups them automatically so you can see the whole campaign instead of one email at a time.",
    )}
    ${body()}
  </>`;
}

/**
 * @param {{ campaignId: string }} props
 */
export function CampaignView({ campaignId }) {
  const { data, error, loading, reload } = useAsync(() => api.getCampaign(campaignId), [campaignId]);
  if (error) return errorState(error, reload);
  if (loading || !data) return skeleton(3);

  const { campaign, emails, graph } = data;
  return html`<${Fragment}>
    <a href="#/campaigns" class="back-link">← Back to linked attacks</a>
    ${pageHead(
      campaign.name,
      `${plural(campaign.email_ids.length, "email")} linked together · worst risk ${campaign.max_risk} · first seen ${formatDate(campaign.created_at)}`,
    )}
    ${section(
      "What links them",
      html`<div class="cluster">
        ${campaign.indicators.length > 0
          ? campaign.indicators.map((indicator, index) => chip(indicator, "neutral", { mono: true, key: index }))
          : html`<span class="hint">—</span>`}
      </div>`,
      { note: "These exact things appear in more than one of the emails below." },
    )}
    ${section("The emails", html`<${CasesTable} items=${emails} />`)}
    ${section("All of it on one map", html`<${Fragment}><${RelationshipGraph} graph=${graph} tall /><${GraphLegend} /></>`, {
      note: "Every email in this group drawn together. Circles sitting between two emails are the shared pieces of the attacker's setup, which is exactly what an investigator follows.",
    })}
  </>`;
}
