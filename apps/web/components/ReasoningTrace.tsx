export default function ReasoningTrace({ steps }: { steps: string[] }) {
  if (!steps.length) {
    return <p className="muted">Waiting for the agent to think…</p>;
  }
  return (
    <div>
      {steps.map((step, i) => (
        <div className="trace-item mono" key={i}>
          {step}
        </div>
      ))}
    </div>
  );
}
