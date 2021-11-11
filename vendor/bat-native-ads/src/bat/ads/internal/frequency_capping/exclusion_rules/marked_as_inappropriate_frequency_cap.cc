/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/frequency_capping/exclusion_rules/marked_as_inappropriate_frequency_cap.h"

#include "base/strings/stringprintf.h"
#include "bat/ads/internal/client/client.h"
#include "bat/ads/internal/client/preferences/flagged_ad_info.h"

namespace ads {

MarkedAsInappropriateFrequencyCap::MarkedAsInappropriateFrequencyCap() =
    default;

MarkedAsInappropriateFrequencyCap::~MarkedAsInappropriateFrequencyCap() =
    default;

std::string MarkedAsInappropriateFrequencyCap::GetUuid(
    const CreativeAdInfo& creative_ad) const {
  return creative_ad.creative_set_id;
}

bool MarkedAsInappropriateFrequencyCap::ShouldExclude(
    const CreativeAdInfo& creative_ad) {
  if (!DoesRespectCap(creative_ad)) {
    last_message_ = base::StringPrintf(
        "creativeSetId %s excluded due to being marked as inappropriate",
        creative_ad.creative_set_id.c_str());

    return true;
  }

  return false;
}

std::string MarkedAsInappropriateFrequencyCap::GetLastMessage() const {
  return last_message_;
}

bool MarkedAsInappropriateFrequencyCap::DoesRespectCap(
    const CreativeAdInfo& creative_ad) {
  const FlaggedAdList flagged_ads = Client::Get()->GetFlaggedAds();
  if (flagged_ads.empty()) {
    return true;
  }

  const auto iter = std::find_if(
      flagged_ads.cbegin(), flagged_ads.cend(),
      [&creative_ad](const FlaggedAdInfo& flagged_ad) {
        return flagged_ad.creative_set_id == creative_ad.creative_set_id;
      });

  if (iter == flagged_ads.end()) {
    return true;
  }

  return false;
}

}  // namespace ads
