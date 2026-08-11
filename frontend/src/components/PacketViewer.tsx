/**
 * Packet evidence viewer: summary, decoded fields and a hex pane.
 *
 * The system stores parsed metadata rather than raw frames (ADR 5), so the hex
 * pane renders the packet's decoded representation. It is labelled as such —
 * showing a synthesised dump as if it were captured bytes would mislead an
 * analyst during an investigation, which is precisely when that matters.
 */
import type { PacketView } from "../api/types";
import styles from "./PacketViewer.module.css";

const BYTES_PER_ROW = 16;

/** Render bytes as offset / hex / printable-ASCII columns, as `xxd` does. */
function hexDump(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += BYTES_PER_ROW) {
    const slice = Array.from(bytes.slice(offset, offset + BYTES_PER_ROW));
    const hex = slice
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(BYTES_PER_ROW * 3 - 1, " ");
    const ascii = slice
      .map((byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : "."))
      .join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`);
  }
  return lines.join("\n");
}

function encode(packet: PacketView): Uint8Array {
  const text = JSON.stringify(
    {
      src: `${packet.src_ip ?? "?"}:${packet.src_port ?? 0}`,
      dst: `${packet.dst_ip ?? "?"}:${packet.dst_port ?? 0}`,
      proto: packet.protocol,
      len: packet.length,
      ...packet.fields,
    },
    null,
    1,
  );
  return new TextEncoder().encode(text);
}

export function PacketViewer({ packet, index }: { packet: PacketView; index: number }) {
  return (
    <article className={styles.packet}>
      <header className={styles.header}>
        <h3 className={styles.title}>Packet {index + 1}</h3>
        <span className={styles.meta}>
          {packet.protocol.toUpperCase()} · {packet.length} bytes ·{" "}
          {new Date(packet.timestamp).toLocaleTimeString()}
        </span>
      </header>

      <p className={styles.summary}>{packet.raw_summary}</p>

      {Object.keys(packet.fields).length > 0 && (
        <dl className={styles.fields}>
          {Object.entries(packet.fields).map(([section, value]) => (
            <div key={section} className={styles.field}>
              <dt>{section}</dt>
              <dd>{JSON.stringify(value)}</dd>
            </div>
          ))}
        </dl>
      )}

      <details className={styles.details}>
        <summary>Hex view</summary>
        <p className={styles.caveat}>
          Rendered from the packet's decoded metadata. Raw frames are kept in PCAP, not the
          database.
        </p>
        <pre className={styles.hex}>{hexDump(encode(packet))}</pre>
      </details>
    </article>
  );
}
