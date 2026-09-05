// @ts-check
/**
 * The shapes the backend returns, mirrored from backend/app/schemas.py.
 *
 * Only the fields the dashboard reads are declared. No runtime content: it
 * exists so `import('./types.js').AnalysisResult` resolves to a real type.
 */

/** @typedef {'Legitimate' | 'Suspicious' | 'Impersonated' | 'Phishing' | 'Fraud-Related'} ThreatCategory */
/** @typedef {'info' | 'low' | 'medium' | 'high' | 'critical'} Severity */
/** @typedef {'open' | 'quarantined' | 'blocked'} CaseStatus */
/**
 * @typedef {'spoofed_domain' | 'lookalike_domain' | 'compromised_account'
 *   | 'direct_attacker_infrastructure' | 'legitimate_sender' | 'undetermined'} SourceType
 */
/** @typedef {'email' | 'address' | 'domain' | 'ip' | 'asn' | 'url' | 'attachment' | 'campaign'} NodeType */
/** @typedef {'payment_diversion' | 'fake_invoice' | 'credential_harvesting' | 'executive_impersonation'} BecPatternName */

/**
 * @typedef {object} Finding
 * @property {string} id
 * @property {string} module
 * @property {Severity} severity
 * @property {string} title
 * @property {string} detail
 */

/**
 * @typedef {object} AddressInfo
 * @property {string} display_name
 * @property {string} address
 * @property {string} domain
 */

/**
 * @typedef {object} AttachmentMeta
 * @property {string} filename
 * @property {number} size
 * @property {string} sha256
 * @property {boolean} mime_mismatch
 * @property {boolean} has_macros
 * @property {boolean} double_extension
 * @property {number} shannon_entropy
 * @property {boolean} high_entropy
 * @property {Severity} risk
 * @property {string[]} reasons
 */

/**
 * @typedef {object} GeoInfo
 * @property {string} country
 * @property {string} country_code
 * @property {string} region
 * @property {string} city
 * @property {number | null} lat
 * @property {number | null} lon
 * @property {string} isp
 * @property {string} org
 * @property {string} asn
 * @property {boolean} is_tor_exit
 * @property {string[]} blacklists
 */

/**
 * @typedef {object} Hop
 * @property {number} index
 * @property {string} from_host
 * @property {string} from_ip
 * @property {string} by_host
 * @property {string | null} timestamp
 * @property {number | null} delay_seconds
 * @property {boolean} is_private_ip
 * @property {GeoInfo | null} geo
 */

/**
 * @typedef {object} AuthResult
 * @property {string} spf
 * @property {string} dkim
 * @property {string} dmarc
 */

/**
 * @typedef {object} HeaderAnalysis
 * @property {Hop[]} hops
 * @property {string} originating_ip
 * @property {number | null} originating_hop_index
 * @property {string} origin_reasoning
 * @property {boolean} return_path_mismatch
 * @property {boolean} reply_to_mismatch
 * @property {boolean} display_name_spoof
 * @property {string} display_name_brand
 * @property {AuthResult} auth
 */

/**
 * @typedef {object} UrlInfo
 * @property {string} url
 * @property {string} anchor_text
 * @property {boolean} anchor_mismatch
 * @property {Severity} risk
 * @property {string[]} reasons
 */

/**
 * @typedef {object} BecPattern
 * @property {BecPatternName} pattern
 * @property {number} confidence
 * @property {string[]} evidence
 */

/**
 * @typedef {object} TokenWeight
 * @property {string} token
 * @property {number} weight
 */

/**
 * @typedef {object} NlpAnalysis
 * @property {number} word_count
 * @property {number} urgency_score
 * @property {string[]} urgency_phrases
 * @property {string[]} financial_terms
 * @property {string[]} credential_terms
 * @property {string[]} threat_terms
 * @property {boolean} generic_greeting
 * @property {boolean} requests_reply_not_click
 * @property {ThreatCategory} ml_category
 * @property {Record<string, number>} ml_probabilities
 * @property {string[]} ml_top_terms
 * @property {TokenWeight[]} shap_weights
 * @property {TokenWeight[]} lime_weights
 * @property {number} lime_fidelity
 * @property {BecPattern[]} bec_patterns
 */

/**
 * @typedef {object} DomainIntel
 * @property {string} domain
 * @property {string} role
 * @property {string} registrar
 * @property {number | null} age_days
 * @property {boolean} has_mx
 * @property {boolean} is_free_mail
 * @property {boolean} is_disposable
 * @property {string} lookalike_of
 * @property {string} lookalike_technique
 * @property {string[]} reputation
 * @property {string} source
 */

/**
 * @typedef {object} InfraAnalysis
 * @property {GeoInfo | null} origin_geo
 * @property {boolean} tor_exit
 * @property {boolean} vpn_or_proxy
 * @property {boolean} hosting_provider
 * @property {boolean} blacklisted
 */

/**
 * @typedef {object} RelatedIncident
 * @property {string} email_id
 * @property {string} subject
 * @property {string} sender
 * @property {number} risk_score
 * @property {string[]} shared_indicators
 */

/**
 * @typedef {object} ThreatIntel
 * @property {string[]} indicators
 * @property {RelatedIncident[]} related_incidents
 */

/**
 * @typedef {object} Attribution
 * @property {SourceType} source_type
 * @property {number} confidence
 * @property {string[]} reasoning
 */

/**
 * @typedef {object} GraphNode
 * @property {string} id
 * @property {NodeType} type
 * @property {string} label
 * @property {Severity} risk
 */

/**
 * @typedef {object} GraphEdge
 * @property {string} source
 * @property {string} target
 * @property {string} relation
 */

/**
 * @typedef {object} AttributionGraph
 * @property {GraphNode[]} nodes
 * @property {GraphEdge[]} edges
 */

/**
 * The five Stage 4 pillars, each 0-100.
 * @typedef {object} RiskBreakdown
 * @property {number} auth
 * @property {number} text
 * @property {number} url
 * @property {number} network
 * @property {number} entropy
 */

/**
 * @typedef {object} Verdict
 * @property {ThreatCategory} category
 * @property {number} confidence
 * @property {number} risk_score
 * @property {Severity} severity
 * @property {RiskBreakdown} breakdown
 * @property {ThreatCategory} ml_category
 * @property {ThreatCategory} rule_category
 * @property {boolean} dual_validation_agreement
 * @property {string[]} recommended_actions
 */

/**
 * The LIME explanation, fitted when a case is opened rather than during ingest.
 * @typedef {object} LimeReport
 * @property {boolean} available
 * @property {string} method
 * @property {TokenWeight[]} weights
 * @property {number} fidelity
 * @property {number} n_samples
 * @property {ThreatCategory} category
 * @property {string[]} agreement_with_shap
 */

/**
 * @typedef {object} CustodyEvent
 * @property {number} seq
 * @property {string} timestamp
 * @property {string} actor
 * @property {string} action
 * @property {string} hash
 */

/**
 * @typedef {object} CustodyChain
 * @property {CustodyEvent[]} events
 * @property {boolean} valid
 */

/**
 * @typedef {object} Alert
 * @property {string} id
 * @property {string} created_at
 * @property {string} email_id
 * @property {string} subject
 * @property {string} sender
 * @property {ThreatCategory} category
 * @property {number} risk_score
 * @property {Severity} severity
 * @property {boolean} acknowledged
 */

/**
 * @typedef {object} Campaign
 * @property {string} id
 * @property {string} name
 * @property {string} created_at
 * @property {string} updated_at
 * @property {string[]} email_ids
 * @property {string[]} indicators
 * @property {number} max_risk
 * @property {Record<string, number>} categories
 * @property {string[]} countries
 */

/**
 * @typedef {object} AnalysisResult
 * @property {string} id
 * @property {string} filename
 * @property {{ subject: string, date: string | null, sender: AddressInfo, text_body: string, raw_sha256: string }} email
 * @property {HeaderAnalysis} headers
 * @property {{ urls: UrlInfo[] }} urls
 * @property {{ attachments: AttachmentMeta[] }} attachments
 * @property {NlpAnalysis} nlp
 * @property {DomainIntel[]} domains
 * @property {InfraAnalysis} infrastructure
 * @property {ThreatIntel} intel
 * @property {Attribution} attribution
 * @property {AttributionGraph} graph
 * @property {Verdict} verdict
 * @property {Finding[]} findings
 * @property {string | null} campaign_id
 */

/**
 * @typedef {object} CaseSummary
 * @property {string} id
 * @property {string} filename
 * @property {string} subject
 * @property {string} sender
 * @property {ThreatCategory} category
 * @property {number} risk_score
 * @property {Severity} severity
 * @property {string} analyzed_at
 * @property {string} originating_ip
 * @property {string} origin_country
 * @property {CaseStatus} status
 */

/**
 * @typedef {object} CaseDecision
 * @property {CaseStatus} status
 * @property {string[]} indicators
 * @property {CustodyEvent[]} history
 */

/**
 * @typedef {object} DashboardStats
 * @property {number} total_emails
 * @property {number} high_risk
 * @property {number} campaigns
 * @property {number} alerts_open
 * @property {Record<string, number>} by_category
 * @property {Array<{ country: string, count: number }>} top_countries
 */

/**
 * @typedef {object} Health
 * @property {boolean} network
 * @property {boolean} native_engine
 * @property {boolean} zero_persistence
 */

/**
 * @typedef {object} AnalyzeResponse
 * @property {AnalysisResult[]} results
 * @property {Alert[]} alerts
 */

/**
 * What a finished analysis job reports. A summary, not the whole result: the
 * case is in the database by then, so the detail is read from /api/emails.
 * @typedef {object} JobSummary
 * @property {string} email_id
 * @property {string} filename
 * @property {string} category
 * @property {number} risk_score
 * @property {string} severity
 * @property {number} processing_ms
 * @property {string | null} alert_id
 */

/**
 * One queued message. `state` is Celery's own vocabulary, passed through:
 * PENDING, STARTED, SUCCESS, FAILURE, RETRY, REVOKED.
 * @typedef {object} JobStatus
 * @property {string} job_id
 * @property {string} filename
 * @property {string} state
 * @property {JobSummary | null} [result]
 * @property {string | null} [error]
 */

/**
 * @typedef {object} AsyncAnalyzeResponse
 * @property {JobStatus[]} jobs
 * @property {string} queue how these tasks execute, as /api/health reports it
 */

/**
 * @typedef {object} EmailListResponse
 * @property {CaseSummary[]} items
 * @property {number} total
 */

/**
 * @typedef {object} CampaignDetail
 * @property {Campaign} campaign
 * @property {CaseSummary[]} emails
 * @property {AttributionGraph} graph
 */

/**
 * @typedef {object} CustodyVerification
 * @property {boolean} valid
 * @property {string} head_hash
 */

export {};
