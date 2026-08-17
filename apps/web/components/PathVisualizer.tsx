function hopsFromContext(context: string): string[] {
  const match = context.match(/Traffic flows through:\s*(.+)$/i);
  if (match) {
    return match[1].split("->").map((hop) => hop.trim()).filter(Boolean);
  }
  return [];
}

export default function PathVisualizer({ context }: { context: string }) {
  const hops = hopsFromContext(context);
  if (!hops.length) {
    return <p className="muted">{context || "No topology query yet."}</p>;
  }
  return (
    <div>
      <div className="path">
        {hops.map((hop, i) => (
          <span key={`${hop}-${i}`} style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <span className={hop.includes("FW") ? "node fw" : "node"}>{hop}</span>
            {i < hops.length - 1 ? <span className="arrow">→</span> : null}
          </span>
        ))}
      </div>
      <p className="muted" style={{ marginTop: 12 }}>
        {context}
      </p>
    </div>
  );
}
