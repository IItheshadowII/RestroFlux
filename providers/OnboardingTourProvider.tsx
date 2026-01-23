import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import OnboardingTour from '../components/OnboardingTour';
import stepsData from '../data/onboarding-v1.json';

type TourContextType = {
  start: () => void;
  stop: () => void;
  isRunning: boolean;
};

const TourContext = createContext<TourContextType>({ start: () => {}, stop: () => {}, isRunning: false });

export const OnboardingTourProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [run, setRun] = useState(false);
  const [tourSteps, setTourSteps] = useState<any[]>([]);

  useEffect(() => {
    // Map our JSON steps to Joyride steps
    const mapped = (stepsData || []).map((s: any) => ({
      target: s.selector || 'body',
      placement: s.placement || 'bottom',
      content: (
        <div>
          <strong style={{ display: 'block', marginBottom: 6 }}>{s.title}</strong>
          <div style={{ fontSize: 13 }}>{s.content}</div>
        </div>
      ) as any,
      disableBeacon: true,
      spotlightPadding: s.spotlightPadding || 8
    }));
    setTourSteps(mapped);
  }, []);

  useEffect(() => {
    const handler = () => setRun(true);
    window.addEventListener('startOnboarding', handler as EventListener);
    return () => window.removeEventListener('startOnboarding', handler as EventListener);
  }, []);

  const start = () => setRun(true);
  const stop = () => setRun(false);

  const value = useMemo(() => ({ start, stop, isRunning: run }), [run]);

  return (
    <TourContext.Provider value={value}>
      {children}
      <OnboardingTour steps={tourSteps as any} run={run} callback={(data) => {
        const { status } = data;
        if (status === 'finished' || status === 'skipped') {
          setRun(false);
        }
      }} />
    </TourContext.Provider>
  );
};

export const useOnboardingTour = () => useContext(TourContext);
