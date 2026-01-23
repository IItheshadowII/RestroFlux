import React from 'react';
import Joyride, { Step, CallBackProps, STATUS } from 'react-joyride';

interface OnboardingTourProps {
  steps: Step[];
  run: boolean;
  continuous?: boolean;
  showSkipButton?: boolean;
  spotlightPadding?: number;
  callback?: (data: CallBackProps) => void;
}

export const OnboardingTour: React.FC<OnboardingTourProps> = ({ steps, run, continuous = true, showSkipButton = true, spotlightPadding = 8, callback }) => {
  return (
    <Joyride
      steps={steps}
      run={run}
      continuous={continuous}
      showSkipButton={showSkipButton}
      spotlightPadding={spotlightPadding}
      styles={{
        options: {
          zIndex: 10050,
        }
      }}
      callback={callback}
      locale={{
        back: 'Atrás',
        close: 'Salir',
        last: 'Finalizar',
        next: 'Continuar',
        skip: 'No mostrar'
      }}
    />
  );
};

export default OnboardingTour;
