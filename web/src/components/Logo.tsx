/** CopperHound mark: a hound's head on a copper tile. */
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient id="ch-copper" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#f3b07c" />
          <stop offset=".5" stopColor="#c8703f" />
          <stop offset="1" stopColor="#7a3a1c" />
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="60" height="60" rx="14" fill="url(#ch-copper)" />
      <path
        fill="#1d1410"
        d="M16 48 C13 38 13 27 18 20 C22 14 30 12 35 15 C38 17 40 20 43 21 L53 24 C56.5 25 58 28 57 31.5 C56 34.5 53 35.5 50 35.5 C49 39 46 41.5 42 41.5 L38 41.5 C37 46 38 51 40 55 L21 55 C19.5 52.5 17.5 50.5 16 48 Z"
      />
      <path fill="#6b3218" d="M27 18 C21 20 18 28 19 38 C20 46 23 51 27 50 C31 49 31 42 31 34 C31 27 32 21 27 18 Z" />
      <circle cx="38.5" cy="24" r="1.9" fill="#f3b07c" />
      <circle cx="55" cy="27.6" r="1.9" fill="#f3b07c" />
    </svg>
  );
}
