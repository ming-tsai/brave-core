/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

import { localeStrings as walletCardStrings } from '../../shared/components/wallet_card/stories/locale_strings'
import { localeStrings as onboardingStrings } from '../../shared/components/onboarding/stories/locale_strings'

export const localeStrings = {
  ...walletCardStrings,
  ...onboardingStrings,

  summary: 'Summary',
  tip: 'Tip',
  unverifiedCreator: 'Unverified Creator',
  verifiedCreator: 'Verified Creator',
  refreshStatus: 'Refresh Status',
  pendingTipText: 'Any tip you make will remain pending in your wallet and retry automatically for 90 days. $1Learn more$2',
  pendingTipTitle: 'This creator is not signed up yet.',
  pendingTipTitleRegistered: 'This creator is currently not configured to receive tips from your wallet.',
  platformPublisherTitle: '$1 on $2',
  attention: 'Attention',
  sendTip: 'Send Tip',
  includeInAutoContribute: 'Include in Auto-Contribute',
  monthlyContribution: 'Monthly Contribution',
  ok: 'OK',
  set: 'Set',
  changeAmount: 'Change amount',
  cancel: 'Cancel',

  grantCaptchaTitle: 'Confirm you are a human being',
  grantCaptchaFailedTitle: 'Hmm… Not Quite. Try Again.',
  grantCaptchaHint: 'Drag the BAT icon onto the $1 target.',
  grantCaptchaPassedTitleUGP: 'It’s your lucky day!',
  grantCaptchaPassedTextUGP: 'Your token grant is on its way.',
  grantCaptchaAmountUGP: 'Free Token Grant',
  grantCaptchaPassedTitleAds: 'You\'ve earned an Ads Reward!',
  grantCaptchaPassedTextAds: 'Your Reward is on its way to your Brave Rewards wallet.',
  grantCaptchaAmountAds: 'Your Reward Amount',
  grantCaptchaExpiration: 'Grant Expiration Date',
  grantCaptchaErrorTitle: 'Oops, something is wrong.',
  grantCaptchaErrorText: 'Brave Rewards is having an issue. Please try again later.',

  notificationAddFunds: 'Add Funds',
  notificationReconnect: 'Reconnect',
  notificationClaim: 'Claim',
  notificationAddFundsTitle: 'Insufficient Funds',
  notificationAddFundsText: 'Your Brave Rewards account is waiting for a deposit.',
  notificationAutoContributeCompletedTitle: 'Auto-Contribute',
  notificationAutoContributeCompletedText: 'You\'ve contributed $1.',
  notificationBackupWalletTitle: 'Backup wallet',
  notificationBackupWalletText: 'Please backup your Brave wallet.',
  notificationBackupWalletAction: 'Backup now',
  notificationWalletDisconnectedTitle: 'Your wallet is logged out',
  notificationWalletDisconnectedText: 'This can happen to keep your account secure. Click below to reconnect now.',
  notificationWalletDisconnectedAction: 'Reconnect',
  notificationWalletVerifiedTitle: 'Your wallet is verified!',
  notificationWalletVerifiedText: 'Your $1 wallet was successfully verified and is ready to add and withdraw funds.',
  notificationTokenGrantTitle: 'Token grants',
  notificationTokenGrantText: 'You have a grant waiting for you.',
  notificationAdGrantTitle: 'Ads earnings received',
  notificationAdGrantText: 'Your rewards from Brave Private Ads are here!',
  notificationMonthlyContributionFailedTitle: 'Monthly contribution failed',
  notificationInsufficientFundsText: 'Your scheduled monthly payment for Auto-Contribute and monthly contributions could not be completed due to insufficient funds. We’ll try again in 30 days.',
  notificationMonthlyContributionFailedText: 'There was a problem processing your contribution.',
  notificationMonthlyTipCompletedTitle: 'Contributions and tips',
  notificationMonthlyTipCompletedText: 'Your monthly contributions have been processed.',
  notificationPublisherVerifiedTitle: 'Pending contribution',
  notificationPublisherVerifiedText: 'Creator $1 recently verified.',
  notificationPendingTipFailedTitle: 'Insufficient funds',
  notificationPendingTipFailedText: 'You have pending tips due to insufficient funds'
}
