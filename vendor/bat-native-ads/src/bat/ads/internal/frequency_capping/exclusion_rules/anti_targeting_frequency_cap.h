/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_FREQUENCY_CAPPING_EXCLUSION_RULES_ANTI_TARGETING_FREQUENCY_CAP_H_
#define BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_FREQUENCY_CAPPING_EXCLUSION_RULES_ANTI_TARGETING_FREQUENCY_CAP_H_

#include <string>

#include "bat/ads/internal/bundle/creative_ad_info.h"
#include "bat/ads/internal/frequency_capping/exclusion_rules/exclusion_rule.h"
#include "bat/ads/internal/frequency_capping/frequency_capping_aliases.h"
#include "bat/ads/internal/resources/frequency_capping/anti_targeting_info.h"

namespace ads {

namespace resource {
class AntiTargeting;
}  // namespace resource

class AntiTargetingFrequencyCap final : public ExclusionRule<CreativeAdInfo> {
 public:
  AntiTargetingFrequencyCap(resource::AntiTargeting* anti_targeting_resource,
                            const BrowsingHistoryList& browsing_history);
  ~AntiTargetingFrequencyCap() override;

  AntiTargetingFrequencyCap(const AntiTargetingFrequencyCap&) = delete;
  AntiTargetingFrequencyCap& operator=(const AntiTargetingFrequencyCap&) =
      delete;

  std::string GetUuid(const CreativeAdInfo& creative_ad) const override;

  bool ShouldExclude(const CreativeAdInfo& creative_ad) override;

  std::string GetLastMessage() const override;

 private:
  resource::AntiTargetingInfo anti_targeting_;

  BrowsingHistoryList browsing_history_;

  std::string last_message_;

  bool DoesRespectCap(const CreativeAdInfo& creative_ad) const;
};

}  // namespace ads

#endif  // BRAVE_VENDOR_BAT_NATIVE_ADS_SRC_BAT_ADS_INTERNAL_FREQUENCY_CAPPING_EXCLUSION_RULES_ANTI_TARGETING_FREQUENCY_CAP_H_
