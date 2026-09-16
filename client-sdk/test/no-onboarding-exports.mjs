import assert from 'node:assert/strict';
import * as sdk from '../dist/index.mjs';

const forbidden = [
  'hashOnboarding',
  'hashOnboardingCanonical',
  'onboardingToScVal',
  'onboardingOptionToScVal',
  'OnboardingPayloadInput',
];

for (const name of forbidden) {
  assert.equal(Object.hasOwn(sdk, name), false, `public export ${name} must be removed`);
}

console.log('no-onboarding-exports: ok');
