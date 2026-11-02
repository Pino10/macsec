/** MacSec's mark: a glass shield with a radar and the engine's iris. It sweeps while tests run. */
export default function Logo({ size = 40, running = false }: { size?: number; running?: boolean }): React.JSX.Element {
  return (
    <svg className="logo" data-running={running} width={size} height={size} viewBox="0 0 1024 1024" aria-hidden>
      <defs>
        <linearGradient id="lg-bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#1a1d44" />
          <stop offset="1" stopColor="#05060d" />
        </linearGradient>
        <linearGradient id="lg-ion" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#38e1ff" />
          <stop offset="1" stopColor="#8b6cff" />
        </linearGradient>
        <linearGradient id="lg-sweep" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#38e1ff" stopOpacity="0" />
          <stop offset="1" stopColor="#38e1ff" stopOpacity="0.6" />
        </linearGradient>
        <clipPath id="lg-hex">
          <path d="M512 214 L770 363 L770 661 L512 810 L254 661 L254 363 Z" />
        </clipPath>
      </defs>
      <rect x="64" y="64" width="896" height="896" rx="208" fill="url(#lg-bg)" />
      <rect x="65" y="65" width="894" height="894" rx="207" fill="none" stroke="#fff" strokeOpacity="0.16" strokeWidth="8" />
      <path d="M512 214 L770 363 L770 661 L512 810 L254 661 L254 363 Z" fill="#fff" fillOpacity="0.08" stroke="#fff" strokeOpacity="0.55" strokeWidth="16" strokeLinejoin="round" />
      <g clipPath="url(#lg-hex)">
        <g className="logo-sweep">
          <path d="M512 512 L742 512 A230 230 0 0 0 675 349 Z" fill="url(#lg-sweep)" />
        </g>
      </g>
      <circle cx="512" cy="512" r="104" fill="none" stroke="url(#lg-ion)" strokeWidth="40" />
      <circle cx="512" cy="512" r="46" fill="#9ff0ff" />
      <circle cx="660" cy="396" r="30" fill="#ff3d7f" />
    </svg>
  )
}
