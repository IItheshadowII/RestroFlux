import { PlanTier } from '../types';

export const isTrialActive = (tenant: any): boolean => {
  if (!tenant) return false;
  const trialEndsAt = tenant?.trialEndsAt || tenant?.trial_ends_at;
  return String(tenant.subscriptionStatus).toUpperCase() === 'TRIAL' && trialEndsAt && new Date(trialEndsAt).getTime() > Date.now();
};

export const getEffectivePlan = (tenant: any): PlanTier => {
  return isTrialActive(tenant) ? PlanTier.ENTERPRISE : (tenant?.plan || PlanTier.BASIC);
};
