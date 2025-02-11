/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/components/brave_wallet/browser/brave_wallet_service.h"

#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "brave/browser/brave_wallet/keyring_controller_factory.h"
#include "brave/components/brave_wallet/browser/brave_wallet_service_delegate.h"
#include "brave/components/brave_wallet/browser/brave_wallet_utils.h"
#include "brave/components/brave_wallet/browser/erc_token_list_parser.h"
#include "brave/components/brave_wallet/browser/erc_token_registry.h"
#include "brave/components/brave_wallet/browser/keyring_controller.h"
#include "brave/components/brave_wallet/browser/pref_names.h"
#include "brave/components/brave_wallet/common/brave_wallet.mojom.h"
#include "brave/components/brave_wallet/common/features.h"
#include "chrome/browser/prefs/browser_prefs.h"
#include "chrome/test/base/testing_browser_process.h"
#include "chrome/test/base/testing_profile.h"
#include "components/grit/brave_components_strings.h"
#include "components/prefs/pref_service.h"
#include "components/prefs/scoped_user_pref_update.h"
#include "components/sync_preferences/testing_pref_service_syncable.h"
#include "content/public/test/browser_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/base/l10n/l10n_util.h"

namespace {

const char token_list_json[] = R"(
  {
   "0x6B175474E89094C44Da98b954EedeAC495271d0F": {
    "name": "USD Coin",
    "logo": "usdc.png",
    "erc20": true,
    "erc721": false,
    "symbol": "USDC",
    "decimals": 6
   },
   "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d": {
     "name": "Crypto Kitties",
     "logo": "CryptoKitties-Kitty-13733.svg",
     "erc20": false,
     "erc721": true,
     "symbol": "CK",
     "decimals": 0
   },
   "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984": {
     "name": "Uniswap",
     "logo": "uni.svg",
     "erc20": true,
     "symbol": "UNI",
     "decimals": 18
   }
  })";

}  // namespace

namespace brave_wallet {

class TestBraveWalletServiceObserver
    : public brave_wallet::mojom::BraveWalletServiceObserver {
 public:
  TestBraveWalletServiceObserver() {}

  void OnDefaultWalletChanged(mojom::DefaultWallet wallet) override {
    default_wallet_ = wallet;
    defaultWalletChangedFired_ = true;
  }
  void OnActiveOriginChanged(const std::string& origin) override {}
  void OnDefaultBaseCurrencyChanged(const std::string& currency) override {
    currency_ = currency;
    defaultBaseCurrencyChangedFired_ = true;
  }
  void OnDefaultBaseCryptocurrencyChanged(
      const std::string& cryptocurrency) override {
    cryptocurrency_ = cryptocurrency;
    defaultBaseCryptocurrencyChangedFired_ = true;
  }

  void OnNetworkListChanged() override { networkListChangedFired_ = true; }

  mojom::DefaultWallet GetDefaultWallet() { return default_wallet_; }
  bool DefaultWalletChangedFired() { return defaultWalletChangedFired_; }
  std::string GetDefaultBaseCurrency() { return currency_; }
  std::string GetDefaultBaseCryptocurrency() { return cryptocurrency_; }
  bool DefaultBaseCurrencyChangedFired() {
    return defaultBaseCurrencyChangedFired_;
  }
  bool DefaultBaseCryptocurrencyChangedFired() {
    return defaultBaseCryptocurrencyChangedFired_;
  }
  bool OnNetworkListChangedFired() { return networkListChangedFired_; }

  mojo::PendingRemote<brave_wallet::mojom::BraveWalletServiceObserver>
  GetReceiver() {
    return observer_receiver_.BindNewPipeAndPassRemote();
  }

  void Reset() {
    defaultWalletChangedFired_ = false;
    defaultBaseCurrencyChangedFired_ = false;
    defaultBaseCryptocurrencyChangedFired_ = false;
    networkListChangedFired_ = false;
  }

 private:
  mojom::DefaultWallet default_wallet_ =
      mojom::DefaultWallet::BraveWalletPreferExtension;
  bool defaultWalletChangedFired_ = false;
  bool defaultBaseCurrencyChangedFired_ = false;
  bool defaultBaseCryptocurrencyChangedFired_ = false;
  bool networkListChangedFired_ = false;
  std::string currency_;
  std::string cryptocurrency_;
  mojo::Receiver<brave_wallet::mojom::BraveWalletServiceObserver>
      observer_receiver_{this};
};

class BraveWalletServiceUnitTest : public testing::Test {
 public:
  BraveWalletServiceUnitTest()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
  ~BraveWalletServiceUnitTest() override = default;

  using ImportInfo = BraveWalletServiceDelegate::ImportInfo;
  using ImportError = BraveWalletServiceDelegate::ImportError;

 protected:
  void SetUp() override {
    scoped_feature_list_.InitAndEnableFeature(
        features::kNativeBraveWalletFeature);

    TestingProfile::Builder builder;
    auto prefs =
        std::make_unique<sync_preferences::TestingPrefServiceSyncable>();
    RegisterUserProfilePrefs(prefs->registry());
    builder.SetPrefService(std::move(prefs));
    profile_ = builder.Build();
    histogram_tester_.reset(new base::HistogramTester);
    keyring_controller_ =
        KeyringControllerFactory::GetControllerForContext(profile_.get());
    service_.reset(new BraveWalletService(
        BraveWalletServiceDelegate::Create(profile_.get()), keyring_controller_,
        GetPrefs()));
    observer_.reset(new TestBraveWalletServiceObserver());
    service_->AddObserver(observer_->GetReceiver());

    auto* registry = ERCTokenRegistry::GetInstance();
    std::vector<mojom::ERCTokenPtr> input_erc_tokens;
    ASSERT_TRUE(ParseTokenList(token_list_json, &input_erc_tokens));
    registry->UpdateTokenList(std::move(input_erc_tokens));

    bool callback_called = false;
    mojom::ERCTokenPtr token1;
    GetRegistry()->GetTokenByContract(
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        base::BindLambdaForTesting([&](mojom::ERCTokenPtr token) {
          token1_ = std::move(token);
          callback_called = true;
        }));
    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(callback_called);
    ASSERT_EQ(token1_->symbol, "USDC");

    callback_called = false;
    mojom::ERCTokenPtr token2;
    GetRegistry()->GetTokenByContract(
        "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
        base::BindLambdaForTesting([&](mojom::ERCTokenPtr token) {
          token2_ = std::move(token);
          callback_called = true;
        }));
    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(callback_called);
    ASSERT_EQ(token2_->symbol, "UNI");

    callback_called = false;
    mojom::ERCTokenPtr erc721_token;
    GetRegistry()->GetTokenByContract(
        "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d",
        base::BindLambdaForTesting([&](mojom::ERCTokenPtr token) {
          erc721_token_ = std::move(token);
          callback_called = true;
        }));
    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(callback_called);
    ASSERT_EQ(erc721_token_->symbol, "CK");

    eth_token_ = mojom::ERCToken::New();
    eth_token_->contract_address = "";
    eth_token_->name = "Ethereum";
    eth_token_->symbol = "ETH";
    eth_token_->is_erc20 = false;
    eth_token_->is_erc721 = false;
    eth_token_->decimals = 18;
    eth_token_->visible = true;

    bat_token_ = mojom::ERCToken::New();
    bat_token_->contract_address = "0x0D8775F648430679A709E98d2b0Cb6250d2887EF";
    bat_token_->name = "Basic Attention Token";
    bat_token_->symbol = "BAT";
    bat_token_->is_erc20 = true;
    bat_token_->is_erc721 = false;
    bat_token_->decimals = 18;
    bat_token_->visible = true;
    bat_token_->logo = "bat.png";
  }

  mojom::ERCTokenPtr GetToken1() { return token1_.Clone(); }
  mojom::ERCTokenPtr GetToken2() { return token2_.Clone(); }
  mojom::ERCTokenPtr GetErc721Token() { return erc721_token_.Clone(); }
  mojom::ERCTokenPtr GetEthToken() { return eth_token_.Clone(); }
  mojom::ERCTokenPtr GetBatToken() { return bat_token_.Clone(); }

  PrefService* GetPrefs() { return profile_->GetPrefs(); }
  ERCTokenRegistry* GetRegistry() { return ERCTokenRegistry::GetInstance(); }

  void GetUserAssets(const std::string& chain_id,
                     bool* callback_called,
                     std::vector<mojom::ERCTokenPtr>* out_tokens) {
    *callback_called = false;
    service_->GetUserAssets(
        chain_id,
        base::BindLambdaForTesting([&](std::vector<mojom::ERCTokenPtr> tokens) {
          *out_tokens = std::move(tokens);
          *callback_called = true;
        }));
    base::RunLoop().RunUntilIdle();
  }

  void AddUserAsset(mojom::ERCTokenPtr token,
                    const std::string& chain_id,
                    bool* callback_called,
                    bool* out_success) {
    *callback_called = false;
    service_->AddUserAsset(std::move(token), chain_id,
                           base::BindLambdaForTesting([&](bool success) {
                             *out_success = success;
                             *callback_called = true;
                           }));
    base::RunLoop().RunUntilIdle();
  }

  void RemoveUserAsset(mojom::ERCTokenPtr token,
                       const std::string& chain_id,
                       bool* callback_called,
                       bool* out_success) {
    *callback_called = false;
    service_->RemoveUserAsset(std::move(token), chain_id,
                              base::BindLambdaForTesting([&](bool success) {
                                *out_success = success;
                                *callback_called = true;
                              }));
    base::RunLoop().RunUntilIdle();
  }

  void SetUserAssetVisible(mojom::ERCTokenPtr token,
                           const std::string& chain_id,
                           bool visible,
                           bool* callback_called,
                           bool* out_success) {
    *callback_called = false;
    service_->SetUserAssetVisible(std::move(token), chain_id, visible,
                                  base::BindLambdaForTesting([&](bool success) {
                                    *out_success = success;
                                    *callback_called = true;
                                  }));
    base::RunLoop().RunUntilIdle();
  }

  void SetDefaultWallet(mojom::DefaultWallet default_wallet) {
    auto old_default_wallet = observer_->GetDefaultWallet();
    EXPECT_FALSE(observer_->DefaultWalletChangedFired());
    service_->SetDefaultWallet(default_wallet);
    base::RunLoop().RunUntilIdle();
    if (old_default_wallet != default_wallet) {
      EXPECT_TRUE(observer_->DefaultWalletChangedFired());
    } else {
      EXPECT_FALSE(observer_->DefaultWalletChangedFired());
    }
    EXPECT_EQ(default_wallet, observer_->GetDefaultWallet());
    observer_->Reset();
  }

  void SetDefaultBaseCurrency(const std::string& currency) {
    auto old_currency = observer_->GetDefaultBaseCurrency();
    EXPECT_FALSE(observer_->DefaultBaseCurrencyChangedFired());
    service_->SetDefaultBaseCurrency(currency);
    base::RunLoop().RunUntilIdle();
    if (old_currency != currency) {
      EXPECT_TRUE(observer_->DefaultBaseCurrencyChangedFired());
    } else {
      EXPECT_FALSE(observer_->DefaultBaseCurrencyChangedFired());
    }
    EXPECT_EQ(currency, observer_->GetDefaultBaseCurrency());
    observer_->Reset();
  }

  void SetDefaultBaseCryptocurrency(const std::string& cryptocurrency) {
    auto old_cryptocurrency = observer_->GetDefaultBaseCryptocurrency();
    EXPECT_FALSE(observer_->DefaultBaseCryptocurrencyChangedFired());
    service_->SetDefaultBaseCryptocurrency(cryptocurrency);
    base::RunLoop().RunUntilIdle();
    if (old_cryptocurrency != cryptocurrency) {
      EXPECT_TRUE(observer_->DefaultBaseCryptocurrencyChangedFired());
    } else {
      EXPECT_FALSE(observer_->DefaultBaseCryptocurrencyChangedFired());
    }
    EXPECT_EQ(cryptocurrency, observer_->GetDefaultBaseCryptocurrency());
    observer_->Reset();
  }

  mojom::DefaultWallet GetDefaultWallet() {
    base::RunLoop run_loop;
    mojom::DefaultWallet default_wallet;
    service_->GetDefaultWallet(
        base::BindLambdaForTesting([&](mojom::DefaultWallet v) {
          default_wallet = v;
          run_loop.Quit();
        }));
    run_loop.Run();
    return default_wallet;
  }

  std::string GetDefaultBaseCurrency() {
    base::RunLoop run_loop;
    std::string default_currency;
    service_->GetDefaultBaseCurrency(
        base::BindLambdaForTesting([&](const std::string& v) {
          default_currency = v;
          run_loop.Quit();
        }));
    run_loop.Run();
    return default_currency;
  }

  std::string GetDefaultBaseCryptocurrency() {
    base::RunLoop run_loop;
    std::string default_cryptocurrency;
    service_->GetDefaultBaseCryptocurrency(
        base::BindLambdaForTesting([&](const std::string& v) {
          default_cryptocurrency = v;
          run_loop.Quit();
        }));
    run_loop.Run();
    return default_cryptocurrency;
  }

  void SimulateOnGetImportInfo(const std::string& new_password,
                               bool result,
                               const ImportInfo& info,
                               ImportError error,
                               bool* success_out,
                               std::string* error_message_out) {
    // People import with a blank default keyring, so clear it out
    keyring_controller_->Reset();
    base::RunLoop run_loop;
    service_->OnGetImportInfo(
        new_password,
        base::BindLambdaForTesting(
            [&](bool success,
                const absl::optional<std::string>& error_message) {
              *success_out = success;
              if (error_message)
                *error_message_out = *error_message;
              run_loop.Quit();
            }),
        result, info, error);
    run_loop.Run();
  }

  std::vector<mojom::SignMessageRequestPtr> GetPendingSignMessageRequests()
      const {
    base::RunLoop run_loop;
    std::vector<mojom::SignMessageRequestPtr> requests_out;
    service_->GetPendingSignMessageRequests(base::BindLambdaForTesting(
        [&](std::vector<mojom::SignMessageRequestPtr> requests) {
          for (const auto& request : requests)
            requests_out.push_back(request.Clone());
          run_loop.Quit();
        }));
    run_loop.Run();
    return requests_out;
  }

  void CheckPasswordAndMnemonic(const std::string& new_password,
                                const std::string& in_mnemonic,
                                bool* valid_password,
                                bool* valid_mnemonic) {
    ASSERT_NE(valid_password, nullptr);
    ASSERT_NE(valid_mnemonic, nullptr);

    keyring_controller_->Lock();
    // Check new password
    base::RunLoop run_loop;
    keyring_controller_->Unlock(new_password,
                                base::BindLambdaForTesting([&](bool success) {
                                  *valid_password = success;
                                  run_loop.Quit();
                                }));
    run_loop.Run();

    base::RunLoop run_loop2;
    keyring_controller_->GetMnemonicForDefaultKeyring(
        base::BindLambdaForTesting([&](const std::string& mnemonic) {
          *valid_mnemonic = (mnemonic == in_mnemonic);
          run_loop2.Quit();
        }));
    run_loop2.Run();
  }

  void CheckAddresses(const std::vector<std::string>& addresses,
                      bool* valid_addresses) {
    ASSERT_NE(valid_addresses, nullptr);

    base::RunLoop run_loop;
    keyring_controller_->GetDefaultKeyringInfo(
        base::BindLambdaForTesting([&](mojom::KeyringInfoPtr keyring_info) {
          *valid_addresses = false;
          if (keyring_info->account_infos.size() == addresses.size()) {
            for (size_t i = 0; i < addresses.size(); ++i) {
              *valid_addresses =
                  (keyring_info->account_infos[i]->address == addresses[i]);
              if (!*valid_addresses)
                break;
            }
          }
          run_loop.Quit();
        }));
    run_loop.Run();
  }

  content::BrowserTaskEnvironment task_environment_;
  std::unique_ptr<TestingProfile> profile_;
  std::unique_ptr<base::HistogramTester> histogram_tester_;
  std::unique_ptr<BraveWalletService> service_;
  KeyringController* keyring_controller_;
  std::unique_ptr<TestBraveWalletServiceObserver> observer_;
  base::test::ScopedFeatureList scoped_feature_list_;

  mojom::ERCTokenPtr token1_;
  mojom::ERCTokenPtr token2_;
  mojom::ERCTokenPtr erc721_token_;
  mojom::ERCTokenPtr eth_token_;
  mojom::ERCTokenPtr bat_token_;
};

TEST_F(BraveWalletServiceUnitTest, GetUserAssets) {
  bool callback_called = false;
  bool success = false;
  std::vector<mojom::ERCTokenPtr> tokens;

  // Empty vector should be returned for invalid chain_id.
  GetUserAssets("", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens, std::vector<mojom::ERCTokenPtr>());

  GetUserAssets("0x123", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens, std::vector<mojom::ERCTokenPtr>());

  // Check mainnet default value.
  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], GetBatToken());

  // ETH should be returned before any token is added.
  GetUserAssets("0x3", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_EQ(tokens[0], GetEthToken());

  // Prepare tokens to add.
  mojom::ERCTokenPtr token1 = GetToken1();
  mojom::ERCTokenPtr token2 = GetToken2();

  // Add tokens and test GetUserAsset.
  AddUserAsset(token1.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  // Adding token with lower case contract address should be converted to
  // checksum address.
  auto unchecked_token = token1.Clone();
  unchecked_token->contract_address =
      base::ToLowerASCII(unchecked_token->contract_address);
  AddUserAsset(std::move(unchecked_token), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  AddUserAsset(token2.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 3u);
  EXPECT_EQ(GetEthToken(), tokens[0]);
  EXPECT_EQ(GetBatToken(), tokens[1]);
  EXPECT_EQ(token1, tokens[2]);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 3u);
  EXPECT_EQ(GetEthToken(), tokens[0]);
  EXPECT_EQ(token1, tokens[1]);
  EXPECT_EQ(token2, tokens[2]);

  // Remove token1 from "0x1" and token2 from "0x4" and test GetUserAssets.
  RemoveUserAsset(token1.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  RemoveUserAsset(token2.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], GetBatToken());

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(GetEthToken(), tokens[0]);
  EXPECT_EQ(token1, tokens[1]);
}

TEST_F(BraveWalletServiceUnitTest, DefaultAssets) {
  std::vector<std::string> ids = {
      mojom::kMainnetChainId, mojom::kRinkebyChainId, mojom::kRopstenChainId,
      mojom::kGoerliChainId,  mojom::kKovanChainId,   mojom::kLocalhostChainId};
  for (const auto& id : ids) {
    bool callback_called = false;
    std::vector<mojom::ERCTokenPtr> tokens;
    GetUserAssets(id, &callback_called, &tokens);
    EXPECT_TRUE(callback_called);
    if (id == mojom::kMainnetChainId) {
      EXPECT_EQ(tokens.size(), 2u);
      EXPECT_EQ(GetEthToken(), tokens[0]);
      EXPECT_EQ(GetBatToken(), tokens[1]);
    } else {
      EXPECT_EQ(tokens.size(), 1u);
      EXPECT_EQ(GetEthToken(), tokens[0]);
    }
  }
}

TEST_F(BraveWalletServiceUnitTest, AddUserAsset) {
  bool callback_called = false;
  bool success = false;
  std::vector<mojom::ERCTokenPtr> tokens;

  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], GetBatToken());

  callback_called = false;
  mojom::ERCTokenPtr token = GetToken1();

  // Add token with empty contract address when there exists native asset
  // already should fail, in this case, it was eth.
  auto token_with_empty_contract_address = token.Clone();
  token_with_empty_contract_address->contract_address = "";
  AddUserAsset(std::move(token_with_empty_contract_address), "0x4",
               &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Invalid chain_id will fail.
  AddUserAsset(token.Clone(), "0x123", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Add token.
  AddUserAsset(token.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  // Check token is added as expected.
  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 3u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], GetBatToken());
  EXPECT_EQ(tokens[2], token);

  // Adding token with same address in the same chain will fail.
  AddUserAsset(token.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Adding token with same address in lower cases in the same chain will fail.
  auto token_with_unchecked_address = token.Clone();
  token_with_unchecked_address->contract_address =
      base::ToLowerASCII(token->contract_address);
  AddUserAsset(token_with_unchecked_address.Clone(), "0x1", &callback_called,
               &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Adding token with same address in a different chain will succeed.
  // And the address will be converted to checksum address.
  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_EQ(tokens[0], GetEthToken());

  AddUserAsset(token_with_unchecked_address.Clone(), "0x4", &callback_called,
               &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], token);
}

TEST_F(BraveWalletServiceUnitTest, RemoveUserAsset) {
  mojom::ERCTokenPtr token1 = GetToken1();
  mojom::ERCTokenPtr token2 = GetToken2();

  bool callback_called = false;
  bool success = false;
  std::vector<mojom::ERCTokenPtr> tokens;

  // Add tokens
  AddUserAsset(token1.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  AddUserAsset(token2.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  AddUserAsset(token2.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 4u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], GetBatToken());
  EXPECT_EQ(tokens[2], token1);
  EXPECT_EQ(tokens[3], token2);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], token2);

  // Remove token with invalid contract_address returns false.
  auto invalid_eth_token = GetEthToken().Clone();
  invalid_eth_token->contract_address = "eth";
  RemoveUserAsset(std::move(invalid_eth_token), "0x1", &callback_called,
                  &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Remove token with invalid network_id returns false.
  RemoveUserAsset(token1.Clone(), "0x123", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Returns false when we cannot find the list with network_id.
  RemoveUserAsset(token1.Clone(), "0x7", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Remove non-exist token returns true.
  RemoveUserAsset(token1.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  // Remove existing token.
  RemoveUserAsset(token2.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  // Lowercase address will be converted to checksum address when removing
  // token.
  auto BAT_lower_case_addr = GetBatToken();
  BAT_lower_case_addr->contract_address =
      base::ToLowerASCII(BAT_lower_case_addr->contract_address);
  RemoveUserAsset(std::move(BAT_lower_case_addr), "0x1", &callback_called,
                  &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], token1);
}

TEST_F(BraveWalletServiceUnitTest, SetUserAssetVisible) {
  mojom::ERCTokenPtr token1 = GetToken1();
  mojom::ERCTokenPtr token2 = GetToken2();

  bool callback_called = false;
  bool success = false;
  std::vector<mojom::ERCTokenPtr> tokens;

  // Add tokens
  AddUserAsset(token1.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  AddUserAsset(token2.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  AddUserAsset(token2.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 4u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], GetBatToken());
  EXPECT_EQ(tokens[2], token1);
  EXPECT_EQ(tokens[3], token2);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(tokens[0], GetEthToken());
  EXPECT_EQ(tokens[1], token2);

  // Invalid contract_address return false.
  auto invalid_eth = GetEthToken();
  invalid_eth->contract_address = "eth";
  SetUserAssetVisible(std::move(invalid_eth), "0x1", false, &callback_called,
                      &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Invalid chain_id return false.
  SetUserAssetVisible(token1.Clone(), "0x123", false, &callback_called,
                      &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // List for this network_id is not existed should return false.
  SetUserAssetVisible(token1.Clone(), "0x3", false, &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // No entry with this contract address exists in the list.
  SetUserAssetVisible(token1.Clone(), "0x4", false, &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Set visible to false for BAT & token1 in "0x1" and token2 in "0x4".
  SetUserAssetVisible(token1.Clone(), "0x1", false, &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  // Lowercase address will be converted to checksum address directly.
  auto BAT_lower_case_addr = GetBatToken();
  BAT_lower_case_addr->contract_address =
      base::ToLowerASCII(BAT_lower_case_addr->contract_address);
  SetUserAssetVisible(std::move(BAT_lower_case_addr), "0x1", false,
                      &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  SetUserAssetVisible(token2.Clone(), "0x4", false, &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x1", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 4u);
  EXPECT_EQ(tokens[0]->contract_address, GetEthToken()->contract_address);
  EXPECT_TRUE(tokens[0]->visible);
  EXPECT_EQ(tokens[1]->contract_address, GetBatToken()->contract_address);
  EXPECT_FALSE(tokens[1]->visible);
  EXPECT_EQ(tokens[2]->contract_address, token1->contract_address);
  EXPECT_FALSE(tokens[2]->visible);
  EXPECT_EQ(tokens[3]->contract_address, token2->contract_address);
  EXPECT_TRUE(tokens[3]->visible);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(tokens[0]->contract_address, GetEthToken()->contract_address);
  EXPECT_TRUE(tokens[0]->visible);
  EXPECT_EQ(tokens[1]->contract_address, token2->contract_address);
  EXPECT_FALSE(tokens[1]->visible);
}

TEST_F(BraveWalletServiceUnitTest, GetChecksumAddress) {
  absl::optional<std::string> addr = service_->GetChecksumAddress(
      "0x06012c8cf97bead5deae237070f9587f8e7a266d", "0x1");
  EXPECT_EQ(addr.value(), "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d");

  addr = service_->GetChecksumAddress(
      "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "0x1");
  EXPECT_EQ(addr.value(), "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d");

  addr = service_->GetChecksumAddress("", "0x1");
  EXPECT_EQ(addr.value(), "");

  addr = service_->GetChecksumAddress("eth", "0x1");
  EXPECT_FALSE(addr.has_value());

  addr = service_->GetChecksumAddress("ETH", "0x1");
  EXPECT_FALSE(addr.has_value());

  addr = service_->GetChecksumAddress("0x123", "0x1");
  EXPECT_FALSE(addr.has_value());

  addr = service_->GetChecksumAddress("123", "0x1");
  EXPECT_FALSE(addr.has_value());

  addr = service_->GetChecksumAddress(
      "06012c8cf97BEaD5deAe237070F9587f8E7A266d", "0x1");
  EXPECT_FALSE(addr.has_value());
}

TEST_F(BraveWalletServiceUnitTest, GetAndSetDefaultWallet) {
  SetDefaultWallet(mojom::DefaultWallet::BraveWallet);
  EXPECT_EQ(GetDefaultWallet(), mojom::DefaultWallet::BraveWallet);

  SetDefaultWallet(mojom::DefaultWallet::CryptoWallets);
  EXPECT_EQ(GetDefaultWallet(), mojom::DefaultWallet::CryptoWallets);

  SetDefaultWallet(mojom::DefaultWallet::None);
  EXPECT_EQ(GetDefaultWallet(), mojom::DefaultWallet::None);

  SetDefaultWallet(mojom::DefaultWallet::BraveWalletPreferExtension);
  EXPECT_EQ(GetDefaultWallet(),
            mojom::DefaultWallet::BraveWalletPreferExtension);

  // Setting the same value twice is ok
  // SetDefaultWallet will check that the observer is not fired.
  SetDefaultWallet(mojom::DefaultWallet::BraveWalletPreferExtension);
  EXPECT_EQ(GetDefaultWallet(),
            mojom::DefaultWallet::BraveWalletPreferExtension);
}

TEST_F(BraveWalletServiceUnitTest, GetAndSetDefaultBaseCurrency) {
  SetDefaultBaseCurrency("CAD");
  EXPECT_EQ(GetDefaultBaseCurrency(), "CAD");

  // Setting the same value twice is ok
  // SetDefaultBaseCurrency will check that the observer is not fired.
  SetDefaultBaseCurrency("CAD");
  EXPECT_EQ(GetDefaultBaseCurrency(), "CAD");
}

TEST_F(BraveWalletServiceUnitTest, GetAndSetDefaultBaseCryptocurrency) {
  SetDefaultBaseCryptocurrency("ETH");
  EXPECT_EQ(GetDefaultBaseCryptocurrency(), "ETH");

  // Setting the same value twice is ok
  // SetDefaultBaseCryptocurrency will check that the observer is not fired.
  SetDefaultBaseCryptocurrency("ETH");
  EXPECT_EQ(GetDefaultBaseCryptocurrency(), "ETH");
}

TEST_F(BraveWalletServiceUnitTest, EthAddRemoveSetUserAssetVisible) {
  bool success = false;
  bool callback_called = false;
  std::vector<mojom::ERCTokenPtr> tokens;

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_EQ(GetEthToken(), tokens[0]);

  // Add ETH again will fail.
  AddUserAsset(GetEthToken(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Test setting visibility of ETH.
  SetUserAssetVisible(GetEthToken(), "0x4", false, &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_FALSE(tokens[0]->visible);

  // Test removing ETH from user asset list.
  RemoveUserAsset(GetEthToken(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(tokens.empty());

  // Add ETH with eth as the contract address will fail.
  auto invalid_eth = GetEthToken();
  invalid_eth->contract_address = "eth";
  AddUserAsset(std::move(invalid_eth), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Add ETH with empty contract address.
  AddUserAsset(GetEthToken(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_EQ(GetEthToken(), tokens[0]);
}

TEST_F(BraveWalletServiceUnitTest, NetworkListChangedEvent) {
  mojom::EthereumChain chain(
      "0x5566", "Test Custom Chain", {"https://url1.com"}, {"https://url1.com"},
      {"https://url1.com"}, "TC", "Test Coin", 11, false);

  AddCustomNetwork(GetPrefs(), chain.Clone());
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(observer_->OnNetworkListChangedFired());

  // Remove network.
  observer_->Reset();
  {
    ListPrefUpdate update(GetPrefs(), kBraveWalletCustomNetworks);
    base::ListValue* list = update.Get();
    list->EraseListValueIf([&](const base::Value& v) {
      auto* chain_id_value = v.FindStringKey("chainId");
      if (!chain_id_value)
        return false;
      return *chain_id_value == "0x5566";
    });
  }
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(observer_->OnNetworkListChangedFired());
}

TEST_F(BraveWalletServiceUnitTest,
       CustomChainNativeAssetAddRemoveSetUserAssetVisible) {
  brave_wallet::mojom::EthereumChain chain(
      "0x5566", "Test Custom Chain", {"https://url1.com"}, {"https://url1.com"},
      {"https://url1.com"}, "TC", "Test Coin", 11, false);
  AddCustomNetwork(GetPrefs(), chain.Clone());

  auto native_asset = mojom::ERCToken::New("", "Test Coin", "https://url1.com",
                                           false, false, "TC", 11, true, "");

  bool success = false;
  bool callback_called = false;
  std::vector<mojom::ERCTokenPtr> tokens;

  GetUserAssets("0x5566", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_EQ(native_asset.Clone(), tokens[0]);

  // Add native asset again will fail.
  AddUserAsset(native_asset.Clone(), "0x5566", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Test setting visibility of ETH.
  SetUserAssetVisible(native_asset.Clone(), "0x5566", false, &callback_called,
                      &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x5566", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_FALSE(tokens[0]->visible);

  // Test removing native asset from user asset list.
  RemoveUserAsset(native_asset.Clone(), "0x5566", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x5566", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(tokens.empty());

  // Add native asset again
  AddUserAsset(native_asset.Clone(), "0x5566", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x5566", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_EQ(native_asset.Clone(), tokens[0]);
}

TEST_F(BraveWalletServiceUnitTest, ERC721TokenAddRemoveSetUserAssetVisible) {
  bool success = false;
  bool callback_called = false;
  std::vector<mojom::ERCTokenPtr> tokens;

  auto erc721_token_with_empty_token_id = GetErc721Token();
  auto erc721_token_1 = erc721_token_with_empty_token_id.Clone();
  erc721_token_1->token_id = "0x1";
  auto erc721_token_2 = erc721_token_with_empty_token_id.Clone();
  erc721_token_2->token_id = "0x2";

  // Add ERC721 token without tokenId will fail.
  AddUserAsset(std::move(erc721_token_with_empty_token_id), "0x4",
               &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Add ERC721 token with token_id = 1 should success.
  AddUserAsset(erc721_token_1.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  // Add the same token_id should fail.
  AddUserAsset(erc721_token_1.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(success);

  // Add to another chain should success
  AddUserAsset(erc721_token_1.Clone(), "0x1", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  // Add ERC721 token with token_id = 2 should success.
  AddUserAsset(erc721_token_2.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 3u);
  EXPECT_EQ(GetEthToken(), tokens[0]);
  EXPECT_EQ(erc721_token_1, tokens[1]);
  EXPECT_EQ(erc721_token_2, tokens[2]);

  SetUserAssetVisible(erc721_token_1.Clone(), "0x4", false, &callback_called,
                      &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  RemoveUserAsset(erc721_token_2.Clone(), "0x4", &callback_called, &success);
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(success);

  auto erc721_token_1_visible_false = erc721_token_1.Clone();
  erc721_token_1_visible_false->visible = false;
  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 2u);
  EXPECT_EQ(GetEthToken(), tokens[0]);
  EXPECT_EQ(erc721_token_1_visible_false, tokens[1]);
}

TEST_F(BraveWalletServiceUnitTest, MigrateUserAssetEthContractAddress) {
  EXPECT_FALSE(
      GetPrefs()->GetBoolean(kBraveWalletUserAssetEthContractAddressMigrated));

  DictionaryPrefUpdate update(GetPrefs(), kBraveWalletUserAssets);
  base::DictionaryValue* user_assets_pref = update.Get();
  base::Value* user_assets_list =
      user_assets_pref->SetKey("rinkeby", base::Value(base::Value::Type::LIST));

  base::Value value(base::Value::Type::DICTIONARY);
  value.SetKey("contract_address", base::Value("eth"));
  value.SetKey("name", base::Value("Ethereum"));
  value.SetKey("symbol", base::Value("ETH"));
  value.SetKey("is_erc20", base::Value(false));
  value.SetKey("is_erc721", base::Value(false));
  value.SetKey("decimals", base::Value(18));
  value.SetKey("visible", base::Value(true));
  user_assets_list->Append(std::move(value));

  bool callback_called = false;
  std::vector<mojom::ERCTokenPtr> tokens;
  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_EQ(tokens[0]->contract_address, "eth");

  BraveWalletService::MigrateUserAssetEthContractAddress(GetPrefs());

  callback_called = false;
  GetUserAssets("0x4", &callback_called, &tokens);
  EXPECT_TRUE(callback_called);
  EXPECT_EQ(tokens.size(), 1u);
  EXPECT_EQ(tokens[0]->contract_address, "");

  EXPECT_TRUE(
      GetPrefs()->GetBoolean(kBraveWalletUserAssetEthContractAddressMigrated));
}

TEST_F(BraveWalletServiceUnitTest, RecordWalletHistogram) {
  service_->RecordWalletUsage(base::Time::Now());
  histogram_tester_->ExpectBucketCount(kBraveWalletDailyHistogramName, true, 1);
  histogram_tester_->ExpectBucketCount(kBraveWalletWeeklyHistogramName, true,
                                       1);
  histogram_tester_->ExpectBucketCount(kBraveWalletMonthlyHistogramName, true,
                                       1);

  service_->RecordWalletUsage(base::Time::Now() +
                              base::TimeDelta::FromDays(31));
  histogram_tester_->ExpectBucketCount(kBraveWalletDailyHistogramName, false,
                                       2);
  histogram_tester_->ExpectBucketCount(kBraveWalletWeeklyHistogramName, false,
                                       2);
  histogram_tester_->ExpectBucketCount(kBraveWalletMonthlyHistogramName, false,
                                       2);
}

TEST_F(BraveWalletServiceUnitTest, OnGetImportInfo) {
  const char* new_password = "brave1234!";
  bool success;
  std::string error_message;
  SimulateOnGetImportInfo(new_password, false, ImportInfo(),
                          ImportError::kJsonError, &success, &error_message);
  EXPECT_FALSE(success);
  EXPECT_EQ(error_message,
            l10n_util::GetStringUTF8(IDS_BRAVE_WALLET_IMPORT_JSON_ERROR));

  SimulateOnGetImportInfo(new_password, false, ImportInfo(),
                          ImportError::kPasswordError, &success,
                          &error_message);
  EXPECT_FALSE(success);
  EXPECT_EQ(error_message,
            l10n_util::GetStringUTF8(IDS_BRAVE_WALLET_IMPORT_PASSWORD_ERROR));

  SimulateOnGetImportInfo(new_password, false, ImportInfo(),
                          ImportError::kInternalError, &success,
                          &error_message);
  EXPECT_FALSE(success);
  EXPECT_EQ(error_message,
            l10n_util::GetStringUTF8(IDS_BRAVE_WALLET_IMPORT_INTERNAL_ERROR));

  error_message.clear();
  const char* valid_mnemonic =
      "drip caution abandon festival order clown oven regular absorb evidence "
      "crew where";
  SimulateOnGetImportInfo(new_password, true,
                          ImportInfo({valid_mnemonic, false, 3}),
                          ImportError::kNone, &success, &error_message);
  EXPECT_TRUE(success);
  EXPECT_TRUE(error_message.empty());
  {
    bool is_valid_password = false;
    bool is_valid_mnemonic = false;
    CheckPasswordAndMnemonic(new_password, valid_mnemonic, &is_valid_password,
                             &is_valid_mnemonic);
    EXPECT_TRUE(is_valid_password);
    EXPECT_TRUE(is_valid_mnemonic);

    bool is_valid_addresses = false;
    const std::vector<std::string> expected_addresses(
        {"0x084DCb94038af1715963F149079cE011C4B22961",
         "0xE60A2209372AF1049C4848B1bF0136258c35f268",
         "0xb41c52De621B42A3a186ae1e608073A546195C9C"});
    CheckAddresses(expected_addresses, &is_valid_addresses);
    EXPECT_TRUE(is_valid_addresses);
  }

  const char* valid_legacy_mnemonic =
      "cushion pitch impact album daring marine much annual budget social "
      "clarify "
      "balance rose almost area busy among bring hidden bind later capable "
      "pulp "
      "laundry";
  SimulateOnGetImportInfo(new_password, true,
                          ImportInfo({valid_legacy_mnemonic, true, 4}),
                          ImportError::kNone, &success, &error_message);
  EXPECT_TRUE(success);
  EXPECT_TRUE(error_message.empty());
  {
    bool is_valid_password = false;
    bool is_valid_mnemonic = false;
    CheckPasswordAndMnemonic(new_password, valid_legacy_mnemonic,
                             &is_valid_password, &is_valid_mnemonic);
    EXPECT_TRUE(is_valid_password);
    EXPECT_TRUE(is_valid_mnemonic);

    bool is_valid_addresses = false;
    const std::vector<std::string> expected_addresses(
        {"0xea3C17c81E3baC3472d163b2c8b12ddDAa027874",
         "0xEc1BB5a4EC94dE9107222c103907CCC720fA3854",
         "0x8cb80Ef1d274ED215A4C08B31b77e5A813eD8Ea1",
         "0x3899D70A5D45368807E38Ef2c1EB5E4f07542e4f"});
    CheckAddresses(expected_addresses, &is_valid_addresses);
    EXPECT_TRUE(is_valid_addresses);
  }

  const char* invalid_mnemonic = "not correct seed word";
  SimulateOnGetImportInfo(new_password, true,
                          ImportInfo({invalid_mnemonic, false, 2}),
                          ImportError::kNone, &success, &error_message);
  EXPECT_FALSE(success);
  EXPECT_EQ(error_message,
            l10n_util::GetStringUTF8(IDS_WALLET_INVALID_MNEMONIC_ERROR));
}

TEST_F(BraveWalletServiceUnitTest, SignMessageHardware) {
  std::string expected_signature = std::string("0xSiGnEd");
  std::string address = "0xbe862ad9abfe6f22bcb087716c7d89a26051f74c";
  std::string message = "0xAB";
  auto request1 = mojom::SignMessageRequest::New(
      1, address, std::string(message.begin(), message.end()));
  bool callback_is_called = false;
  service_->AddSignMessageRequest(
      std::move(request1), base::BindLambdaForTesting(
                               [&](bool approved, const std::string& signature,
                                   const std::string& error) {
                                 ASSERT_TRUE(approved);
                                 EXPECT_EQ(signature, expected_signature);
                                 ASSERT_TRUE(error.empty());
                                 callback_is_called = true;
                               }));
  EXPECT_EQ(GetPendingSignMessageRequests().size(), 1u);
  service_->NotifySignMessageHardwareRequestProcessed(
      true, 1, expected_signature, std::string());
  ASSERT_TRUE(callback_is_called);
  ASSERT_TRUE(GetPendingSignMessageRequests().empty());
  service_->NotifySignMessageHardwareRequestProcessed(
      true, 1, expected_signature, std::string());
  ASSERT_TRUE(GetPendingSignMessageRequests().empty());
  callback_is_called = false;
  std::string expected_error = "error";
  auto request2 = mojom::SignMessageRequest::New(
      2, address, std::string(message.begin(), message.end()));
  service_->AddSignMessageRequest(
      std::move(request2), base::BindLambdaForTesting(
                               [&](bool approved, const std::string& signature,
                                   const std::string& error) {
                                 ASSERT_FALSE(approved);
                                 EXPECT_EQ(signature, expected_signature);
                                 EXPECT_EQ(error, expected_error);
                                 callback_is_called = true;
                               }));
  EXPECT_EQ(GetPendingSignMessageRequests().size(), 1u);
  service_->NotifySignMessageHardwareRequestProcessed(
      false, 2, expected_signature, expected_error);
  ASSERT_TRUE(callback_is_called);
  ASSERT_TRUE(GetPendingSignMessageRequests().empty());
}

TEST_F(BraveWalletServiceUnitTest, SignMessage) {
  std::string expected_signature = std::string("0xSiGnEd");
  std::string address = "0xbe862ad9abfe6f22bcb087716c7d89a26051f74c";
  std::string message = "0xAB";
  auto request1 = mojom::SignMessageRequest::New(
      1, address, std::string(message.begin(), message.end()));
  bool callback_is_called = false;
  service_->AddSignMessageRequest(
      std::move(request1), base::BindLambdaForTesting(
                               [&](bool approved, const std::string& signature,
                                   const std::string& error) {
                                 ASSERT_TRUE(approved);
                                 callback_is_called = true;
                               }));
  EXPECT_EQ(GetPendingSignMessageRequests().size(), 1u);
  service_->NotifySignMessageRequestProcessed(true, 1);
  ASSERT_TRUE(callback_is_called);
  ASSERT_TRUE(GetPendingSignMessageRequests().empty());
  service_->NotifySignMessageRequestProcessed(true, 1);
  ASSERT_TRUE(GetPendingSignMessageRequests().empty());
  callback_is_called = false;
  std::string expected_error = "error";
  auto request2 = mojom::SignMessageRequest::New(
      2, address, std::string(message.begin(), message.end()));
  service_->AddSignMessageRequest(
      std::move(request2), base::BindLambdaForTesting(
                               [&](bool approved, const std::string& signature,
                                   const std::string& error) {
                                 ASSERT_FALSE(approved);
                                 callback_is_called = true;
                               }));
  EXPECT_EQ(GetPendingSignMessageRequests().size(), 1u);
  service_->NotifySignMessageRequestProcessed(false, 2);
  ASSERT_TRUE(callback_is_called);
  ASSERT_TRUE(GetPendingSignMessageRequests().empty());
}

}  // namespace brave_wallet
