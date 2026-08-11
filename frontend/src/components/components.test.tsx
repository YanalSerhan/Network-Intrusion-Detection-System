/**
 * Component tests.
 *
 * These assert the accessibility and correctness properties the components
 * exist to provide — that severity is readable without colour, that tables
 * announce their columns — rather than snapshotting markup, which would break
 * on every styling change without catching a real regression.
 */
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import type { AlertSummary, PacketView, ThreatIntel } from "../api/types";
import { AlertTable } from "./AlertTable";
import { BarList } from "./BarList";
import { PacketViewer } from "./PacketViewer";
import { SeverityBadge } from "./SeverityBadge";
import { ThreatIntelPanel } from "./ThreatIntelPanel";

function alert(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    alert_id: "11111111-1111-1111-1111-111111111111",
    timestamp: "2026-08-11T10:00:00Z",
    last_seen: "2026-08-11T10:05:00Z",
    severity: "critical",
    source: "detector",
    rule_triggered: "TcpPortScanDetector",
    src_ip: "45.155.205.233",
    dst_ip: "10.0.0.1",
    protocol: "tcp",
    confidence: 0.83,
    tactic: "TA0043",
    status: "new",
    occurrences: 26,
    ...overrides,
  };
}

describe("SeverityBadge", () => {
  it("names the severity rather than relying on colour", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("covers every severity level", () => {
    for (const severity of ["info", "low", "medium", "high", "critical"] as const) {
      const { unmount } = render(<SeverityBadge severity={severity} />);
      expect(screen.getByText(new RegExp(severity, "i"))).toBeInTheDocument();
      unmount();
    }
  });
});

describe("AlertTable", () => {
  it("exposes column headers so cells are announced with their meaning", () => {
    render(
      <MemoryRouter>
        <AlertTable alerts={[alert()]} caption="Recent" />
      </MemoryRouter>,
    );

    const table = screen.getByRole("table");
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((cell) => cell.textContent);

    expect(headers).toContain("Severity");
    expect(headers).toContain("Source");
    expect(headers).toContain("Confidence");
  });

  it("links each row to its detail view", () => {
    render(
      <MemoryRouter>
        <AlertTable alerts={[alert()]} caption="Recent" />
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: "TcpPortScanDetector" })).toHaveAttribute(
      "href",
      "/alerts/11111111-1111-1111-1111-111111111111",
    );
  });

  it("renders a dash for missing addresses instead of an empty cell", () => {
    render(
      <MemoryRouter>
        <AlertTable alerts={[alert({ src_ip: null, dst_ip: null })]} caption="Recent" />
      </MemoryRouter>,
    );
    expect(screen.getAllByText("—")).toHaveLength(2);
  });
});

describe("BarList", () => {
  it("prints counts as text, not only as bar length", () => {
    render(
      <BarList
        items={[
          { label: "45.155.205.233", value: 412 },
          { label: "10.0.0.4", value: 87 },
        ]}
        emptyLabel="none"
      />,
    );

    expect(screen.getByText("412")).toBeInTheDocument();
    expect(screen.getByText("87")).toBeInTheDocument();
  });

  it("shows an explanation when empty", () => {
    render(<BarList items={[]} emptyLabel="No sources yet." />);
    expect(screen.getByText("No sources yet.")).toBeInTheDocument();
  });
});

describe("ThreatIntelPanel", () => {
  const intel: ThreatIntel = {
    ip: "45.155.205.233",
    verdict: "malicious",
    reputation_score: 93,
    geo: { country: "Russia", country_code: "RU", region: "Moscow", city: "Moscow" },
    asn: { asn: "AS64512", organisation: "EvilCorp", isp: "Evil ISP" },
    whois: {
      network_name: "EVIL-NET",
      cidr: "45.155.205.0/24",
      registrant: "EvilCorp",
      abuse_email: "abuse@evil.example",
    },
    providers_queried: ["abuseipdb", "whois"],
    providers_failed: [],
  };

  it("distinguishes not-yet-enriched from a clean verdict", () => {
    render(<ThreatIntelPanel intel={null} />);
    expect(screen.getByText(/Not enriched yet/)).toBeInTheDocument();
  });

  it("shows the verdict and attribution", () => {
    render(<ThreatIntelPanel intel={intel} />);
    expect(screen.getByText("Malicious")).toBeInTheDocument();
    expect(screen.getByText(/Moscow, Moscow, Russia/)).toBeInTheDocument();
    expect(screen.getByText(/AS64512 EvilCorp/)).toBeInTheDocument();
  });

  it("warns when a provider failed, so an outage is not read as clean", () => {
    render(<ThreatIntelPanel intel={{ ...intel, providers_failed: ["abuseipdb"] }} />);
    expect(screen.getByText(/Partial result/)).toBeInTheDocument();
  });
});

describe("PacketViewer", () => {
  const packet: PacketView = {
    timestamp: "2026-08-11T10:00:00Z",
    src_ip: "45.155.205.233",
    dst_ip: "10.0.0.1",
    src_port: 51234,
    dst_port: 443,
    protocol: "tcp",
    length: 74,
    raw_summary: "TCP SYN",
    fields: { tcp_flags: { syn: true } },
  };

  it("renders the summary and decoded fields", () => {
    render(<PacketViewer packet={packet} index={0} />);
    expect(screen.getByText("Packet 1")).toBeInTheDocument();
    expect(screen.getByText("TCP SYN")).toBeInTheDocument();
    expect(screen.getByText("tcp_flags")).toBeInTheDocument();
  });

  it("labels the hex pane as decoded metadata, not captured bytes", () => {
    render(<PacketViewer packet={packet} index={0} />);
    expect(screen.getByText(/decoded metadata/)).toBeInTheDocument();
  });
});
