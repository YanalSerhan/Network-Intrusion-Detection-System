/**
 * Threat intel enrichment panel.
 *
 * Distinguishes three states that look alike but mean different things:
 * not enriched yet, enriched with no opinion, and enriched but partial because
 * a provider failed. Collapsing them into one "no data" message would let an
 * analyst read a provider outage as a clean verdict.
 */
import type { ThreatIntel, ThreatVerdict } from "../api/types";
import { Empty } from "./States";
import styles from "./ThreatIntelPanel.module.css";

const VERDICT_LABELS: Record<ThreatVerdict, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  clean: "Clean",
  unknown: "Unknown",
};

export function ThreatIntelPanel({ intel }: { intel: ThreatIntel | null }) {
  if (!intel) {
    return (
      <Empty message="Not enriched yet. Internal-only traffic is never sent to third parties; otherwise use “Enrich now”." />
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.summary}>
        <span className={`${styles.verdict} ${styles[intel.verdict]}`}>
          {VERDICT_LABELS[intel.verdict]}
        </span>
        <span className={styles.ip}>{intel.ip}</span>
        {intel.reputation_score !== null && (
          <span className={styles.score}>Reputation {intel.reputation_score.toFixed(0)}/100</span>
        )}
      </div>

      <dl className={styles.definitions}>
        <div>
          <dt>Location</dt>
          <dd>
            {intel.geo
              ? [intel.geo.city, intel.geo.region, intel.geo.country].filter(Boolean).join(", ") ||
                "—"
              : "—"}
          </dd>
        </div>
        <div>
          <dt>Network</dt>
          <dd>
            {intel.asn ? [intel.asn.asn, intel.asn.organisation].filter(Boolean).join(" ") : "—"}
          </dd>
        </div>
        <div>
          <dt>Registrant</dt>
          <dd>{intel.whois?.registrant ?? "—"}</dd>
        </div>
        <div>
          <dt>Abuse contact</dt>
          <dd>
            {intel.whois?.abuse_email ? (
              <a href={`mailto:${intel.whois.abuse_email}`}>{intel.whois.abuse_email}</a>
            ) : (
              "—"
            )}
          </dd>
        </div>
      </dl>

      {intel.providers_failed.length > 0 && (
        <p className={styles.partial} role="status">
          Partial result: {intel.providers_failed.join(", ")} did not respond.
        </p>
      )}
    </div>
  );
}
