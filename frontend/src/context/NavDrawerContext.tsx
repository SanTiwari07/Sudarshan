import { createContext, useCallback, useContext, useMemo, useState } from 'react';

type NavDrawerContextValue = {
  open: boolean;
  openDrawer: () => void;
  closeDrawer: () => void;
  toggleDrawer: () => void;
};

const NavDrawerContext = createContext<NavDrawerContextValue | undefined>(undefined);

export function NavDrawerProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);

  const openDrawer = useCallback(() => setOpen(true), []);
  const closeDrawer = useCallback(() => setOpen(false), []);
  const toggleDrawer = useCallback(() => setOpen((v) => !v), []);

  const value = useMemo(
    () => ({ open, openDrawer, closeDrawer, toggleDrawer }),
    [open, openDrawer, closeDrawer, toggleDrawer],
  );

  return <NavDrawerContext.Provider value={value}>{children}</NavDrawerContext.Provider>;
}

export function useNavDrawer() {
  const ctx = useContext(NavDrawerContext);
  if (!ctx) throw new Error('useNavDrawer must be used within NavDrawerProvider');
  return ctx;
}
