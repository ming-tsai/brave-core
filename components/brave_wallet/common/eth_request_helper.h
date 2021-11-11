/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_COMPONENTS_BRAVE_WALLET_COMMON_ETH_REQUEST_HELPER_H_
#define BRAVE_COMPONENTS_BRAVE_WALLET_COMMON_ETH_REQUEST_HELPER_H_

#include <string>

#include "base/values.h"
#include "brave/components/brave_wallet/common/brave_wallet.mojom.h"

namespace brave_wallet {

bool GetEthJsonRequestInfo(const std::string& json,
                           base::Value* id,
                           std::string* method,
                           std::string* params);
mojom::TxDataPtr ParseEthSendTransactionParams(const std::string& json,
                                               std::string* from);
mojom::TxData1559Ptr ParseEthSendTransaction1559Params(const std::string& json,
                                                       std::string* from);
bool NormalizeEthRequest(const std::string& input_json,
                         std::string* output_json);

bool ParseEthSignParams(const std::string& json,
                        std::string* address,
                        std::string* message);
bool ParsePersonalSignParams(const std::string& json,
                             std::string* address,
                             std::string* message);

bool ParseSwitchEthereumChainParams(const std::string& json,
                                    std::string* chain_id);

}  // namespace brave_wallet

#endif  // BRAVE_COMPONENTS_BRAVE_WALLET_COMMON_ETH_REQUEST_HELPER_H_
