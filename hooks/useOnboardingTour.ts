import { useContext } from 'react';
import { useOnboardingTour as useProvider } from '../providers/OnboardingTourProvider';

export const useOnboardingTour = () => {
  return useProvider();
};

export default useOnboardingTour;
