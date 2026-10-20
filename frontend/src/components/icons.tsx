// Minimal inline SVG icon set — no icon-font dependency. Each is 1em, currentColor.
type P = { className?: string };
const S = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className ?? 'h-4 w-4'}>{children}</svg>
);
export const IconShield = (p: P) => <S {...p}><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z" /></S>;
export const IconGrid = (p: P) => <S {...p}><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></S>;
export const IconFlask = (p: P) => <S {...p}><path d="M9 3h6M10 3v6l-5 9a2 2 0 002 3h10a2 2 0 002-3l-5-9V3" /></S>;
export const IconTarget = (p: P) => <S {...p}><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="4" /><circle cx="12" cy="12" r="0.5" /></S>;
export const IconBug = (p: P) => <S {...p}><rect x="8" y="6" width="8" height="12" rx="4" /><path d="M12 2v4M5 9H3M5 14H3M21 9h-2M21 14h-2M6 5l2 2M18 5l-2 2M6 19l2-2M18 19l-2-2" /></S>;
export const IconWrench = (p: P) => <S {...p}><path d="M14 7a4 4 0 00-5 5l-6 6 2 2 6-6a4 4 0 005-5l-2 2-2-2 2-2z" /></S>;
export const IconList = (p: P) => <S {...p}><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" /></S>;
export const IconKey = (p: P) => <S {...p}><circle cx="8" cy="8" r="4" /><path d="M11 11l8 8M16 16l2-2M19 19l2-2" /></S>;
export const IconDoc = (p: P) => <S {...p}><path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z" /><path d="M14 3v6h6" /></S>;
export const IconActivity = (p: P) => <S {...p}><path d="M3 12h4l3 8 4-16 3 8h4" /></S>;
export const IconUsers = (p: P) => <S {...p}><circle cx="9" cy="8" r="3" /><path d="M3 20a6 6 0 0112 0M16 6a3 3 0 010 6M21 20a6 6 0 00-5-5.9" /></S>;
export const IconLock = (p: P) => <S {...p}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 018 0v3" /></S>;
export const IconGlobe = (p: P) => <S {...p}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" /></S>;
export const IconMap = (p: P) => <S {...p}><path d="M9 4L3 6v14l6-2 6 2 6-2V4l-6 2-6-2zM9 4v14M15 6v14" /></S>;
export const IconPlay = (p: P) => <S {...p}><path d="M6 4l14 8-14 8z" /></S>;
export const IconFile = (p: P) => <S {...p}><path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z" /><path d="M14 3v6h6M9 13h6M9 17h6" /></S>;
export const IconServer = (p: P) => <S {...p}><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></S>;
export const IconSearch = (p: P) => <S {...p}><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></S>;
