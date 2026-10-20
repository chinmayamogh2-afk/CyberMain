/** Animated SVG score ring. Colour reflects the grade, value is the real score. */
export function ScoreRing({ score, grade, size = 150 }: { score: number; grade: string; size?: number }) {
  const r = size / 2 - 12;
  const c = 2 * Math.PI * r;
  const offset = c - (score / 100) * c;
  const colour = score >= 90 ? '#34d399' : score >= 75 ? '#38bdf8' : score >= 60 ? '#facc15' : score >= 40 ? '#fb923c' : '#f43f5e';
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(148,163,184,0.1)" strokeWidth="10" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={colour} strokeWidth="10" strokeLinecap="round"
        strokeDasharray={c} strokeDashoffset={offset} transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1), stroke 0.4s' }} />
      <text x="50%" y="46%" textAnchor="middle" className="fill-slate-100" style={{ fontSize: size * 0.26, fontWeight: 700 }}>{score}</text>
      <text x="50%" y="64%" textAnchor="middle" fill={colour} style={{ fontSize: size * 0.12, fontWeight: 600 }}>GRADE {grade}</text>
    </svg>
  );
}
