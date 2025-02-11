/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_COMPONENTS_BRAVE_WALLET_BROWSER_ETH_JSON_RPC_CONTROLLER_H_
#define BRAVE_COMPONENTS_BRAVE_WALLET_BROWSER_ETH_JSON_RPC_CONTROLLER_H_

#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/callback.h"
#include "base/containers/flat_map.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list_threadsafe.h"
#include "brave/components/api_request_helper/api_request_helper.h"
#include "brave/components/brave_wallet/browser/brave_wallet_constants.h"
#include "brave/components/brave_wallet/browser/brave_wallet_types.h"
#include "brave/components/brave_wallet/common/brave_wallet.mojom.h"
#include "components/keyed_service/core/keyed_service.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/remote_set.h"
#include "url/gurl.h"

namespace network {
class SharedURLLoaderFactory;
class SimpleURLLoader;
}  // namespace network

class PrefService;

namespace brave_wallet {

class EthJsonRpcController : public KeyedService,
                             public mojom::EthJsonRpcController {
 public:
  EthJsonRpcController(
      scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
      PrefService* prefs);
  ~EthJsonRpcController() override;

  struct EthereumChainRequest {
    EthereumChainRequest() {}
    EthereumChainRequest(const GURL& origin, mojom::EthereumChain request)
        : origin(origin), request(std::move(request)) {}
    GURL origin;
    mojom::EthereumChain request;
  };

  mojo::PendingRemote<mojom::EthJsonRpcController> MakeRemote();
  void Bind(mojo::PendingReceiver<mojom::EthJsonRpcController> receiver);

  using StringResultCallback =
      base::OnceCallback<void(bool success, const std::string& result)>;

  using GetBlockNumberCallback =
      base::OnceCallback<void(bool status, uint256_t result)>;
  void GetBlockNumber(GetBlockNumberCallback callback);

  void Request(const std::string& json_payload,
               bool auto_retry_on_network_change,
               RequestCallback callback) override;

  void GetBalance(const std::string& address,
                  GetBalanceCallback callback) override;

  using GetTxCountCallback =
      base::OnceCallback<void(bool status, uint256_t result)>;
  void GetTransactionCount(const std::string& address,
                           GetTxCountCallback callback);

  using GetTxReceiptCallback =
      base::OnceCallback<void(bool status, TransactionReceipt result)>;
  void GetTransactionReceipt(const std::string& tx_hash,
                             GetTxReceiptCallback callback);

  using SendRawTxCallback =
      base::OnceCallback<void(bool status, const std::string& tx_hash)>;
  void SendRawTransaction(const std::string& signed_tx,
                          SendRawTxCallback callback);

  void GetERC20TokenBalance(const std::string& conract_address,
                            const std::string& address,
                            GetERC20TokenBalanceCallback callback) override;
  void GetERC20TokenAllowance(const std::string& contract_address,
                              const std::string& owner_address,
                              const std::string& spender_address,
                              GetERC20TokenAllowanceCallback callback) override;

  using UnstoppableDomainsProxyReaderGetManyCallback =
      base::OnceCallback<void(bool success,
                              const std::vector<std::string>& values)>;
  // Call getMany function of ProxyReader contract from Unstoppable Domains.
  void UnstoppableDomainsProxyReaderGetMany(
      const std::string& chain_id,
      const std::string& domain,
      const std::vector<std::string>& keys,
      UnstoppableDomainsProxyReaderGetManyCallback callback);

  void UnstoppableDomainsGetEthAddr(
      const std::string& domain,
      UnstoppableDomainsGetEthAddrCallback callback) override;

  void EnsResolverGetContentHash(const std::string& chain_id,
                                 const std::string& domain,
                                 StringResultCallback callback);
  void EnsGetEthAddr(const std::string& domain,
                     EnsGetEthAddrCallback callback) override;

  bool SetNetwork(const std::string& chain_id);
  void SetNetwork(const std::string& chain_id,
                  SetNetworkCallback callback) override;
  void GetNetwork(GetNetworkCallback callback) override;
  void AddEthereumChain(mojom::EthereumChainPtr chain,
                        const GURL& origin,
                        AddEthereumChainCallback callback) override;
  void AddEthereumChainRequestCompleted(const std::string& chain_id,
                                        bool approved) override;

  std::string GetChainId() const;
  void GetChainId(
      mojom::EthJsonRpcController::GetChainIdCallback callback) override;
  void GetBlockTrackerUrl(
      mojom::EthJsonRpcController::GetBlockTrackerUrlCallback callback)
      override;
  void GetPendingChainRequests(
      GetPendingChainRequestsCallback callback) override;
  void GetPendingSwitchChainRequests(
      GetPendingSwitchChainRequestsCallback callback) override;
  void NotifySwitchChainRequestProcessed(bool approved,
                                         const GURL& origin) override;
  void GetAllNetworks(GetAllNetworksCallback callback) override;
  std::string GetNetworkUrl() const;
  void GetNetworkUrl(
      mojom::EthJsonRpcController::GetNetworkUrlCallback callback) override;
  void SetCustomNetworkForTesting(const std::string& chain_id,
                                  const GURL& provider_url) override;

  void AddObserver(::mojo::PendingRemote<mojom::EthJsonRpcControllerObserver>
                       observer) override;

  GURL GetBlockTrackerUrlFromNetwork(std::string chain_id);

  using GetEstimateGasCallback =
      base::OnceCallback<void(bool status, const std::string& result)>;
  void GetEstimateGas(const std::string& from_address,
                      const std::string& to_address,
                      const std::string& gas,
                      const std::string& gas_price,
                      const std::string& value,
                      const std::string& data,
                      GetEstimateGasCallback callback);

  using GetGasPriceCallback =
      base::OnceCallback<void(bool status, const std::string& result)>;
  void GetGasPrice(GetGasPriceCallback callback);

  using GetIsEip1559Callback =
      base::OnceCallback<void(bool success, bool is_eip1559)>;
  void GetIsEip1559(GetIsEip1559Callback callback);

  void GetERC721OwnerOf(const std::string& contract,
                        const std::string& token_id,
                        GetERC721OwnerOfCallback callback) override;

  void GetERC721TokenBalance(const std::string& contract_address,
                             const std::string& token_id,
                             const std::string& account_address,
                             GetERC721TokenBalanceCallback callback) override;

  using GetSupportsInterfaceCallback =
      base::OnceCallback<void(bool success, bool is_supported)>;
  void GetSupportsInterface(const std::string& contract_address,
                            const std::string& interface_id,
                            GetSupportsInterfaceCallback callback);

  using SwitchEthereumChainRequestCallback =
      base::OnceCallback<void(int error, const std::string& error_message)>;
  // return false when there is an error before processing request
  bool AddSwitchEthereumChainRequest(
      const std::string& chain_id,
      const GURL& origin,
      SwitchEthereumChainRequestCallback callback);

 private:
  void FireNetworkChanged();
  void FirePendingRequestCompleted(const std::string& chain_id,
                                   const std::string& error);
  bool HasRequestFromOrigin(const GURL& origin) const;
  void RemoveChainIdRequest(const std::string& chain_id);
  void OnGetBlockNumber(
      GetBlockNumberCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);
  void OnGetBalance(GetBalanceCallback callback,
                    const int status,
                    const std::string& body,
                    const base::flat_map<std::string, std::string>& headers);
  void OnGetTransactionCount(
      GetTxCountCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);
  void OnGetTransactionReceipt(
      GetTxReceiptCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);
  void OnSendRawTransaction(
      SendRawTxCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);
  void OnGetERC20TokenBalance(
      GetERC20TokenBalanceCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);
  void OnGetERC20TokenAllowance(
      GetERC20TokenAllowanceCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);

  void OnUnstoppableDomainsProxyReaderGetMany(
      UnstoppableDomainsProxyReaderGetManyCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);

  void OnUnstoppableDomainsGetEthAddr(
      UnstoppableDomainsGetEthAddrCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);

  void EnsRegistryGetResolver(const std::string& chain_id,
                              const std::string& domain,
                              StringResultCallback callback);

  void OnEnsRegistryGetResolver(
      StringResultCallback callback,
      int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);

  void ContinueEnsResolverGetContentHash(const std::string& chain_id,
                                         const std::string& domain,
                                         StringResultCallback callback,
                                         bool success,
                                         const std::string& resolver_address);

  void OnEnsResolverGetContentHash(
      StringResultCallback callback,
      int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);

  void ContinueEnsGetEthAddr(const std::string& domain,
                             StringResultCallback callback,
                             bool success,
                             const std::string& resolver_address);

  void OnEnsGetEthAddr(StringResultCallback callback,
                       int status,
                       const std::string& body,
                       const base::flat_map<std::string, std::string>& headers);

  void OnGetEstimateGas(
      GetEstimateGasCallback callback,
      int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);

  void OnGetGasPrice(GetGasPriceCallback callback,
                     int status,
                     const std::string& body,
                     const base::flat_map<std::string, std::string>& headers);

  void OnGetIsEip1559(GetIsEip1559Callback callback,
                      int status,
                      const std::string& body,
                      const base::flat_map<std::string, std::string>& headers);

  void MaybeUpdateIsEip1559(const std::string& chain_id);
  void UpdateIsEip1559(const std::string& chain_id,
                       bool success,
                       bool is_eip1559);

  void RequestInternal(const std::string& json_payload,
                       bool auto_retry_on_network_change,
                       const GURL& network_url,
                       RequestCallback callback);

  FRIEND_TEST_ALL_PREFIXES(EthJsonRpcControllerUnitTest, IsValidDomain);
  bool IsValidDomain(const std::string& domain);

  void OnGetERC721OwnerOf(
      GetERC721OwnerOfCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);

  void ContinueGetERC721TokenBalance(const std::string& account_address,
                                     GetERC721TokenBalanceCallback callback,
                                     bool success,
                                     const std::string& owner_address);

  void OnGetSupportsInterface(
      GetSupportsInterfaceCallback callback,
      const int status,
      const std::string& body,
      const base::flat_map<std::string, std::string>& headers);

  api_request_helper::APIRequestHelper api_request_helper_;
  GURL network_url_;
  std::string chain_id_;
  // <chain_id, EthereumChainRequest>
  base::flat_map<std::string, EthereumChainRequest> add_chain_pending_requests_;
  // <origin, chain_id>
  base::flat_map<GURL, std::string> switch_chain_requests_;
  base::flat_map<GURL, SwitchEthereumChainRequestCallback>
      switch_chain_callbacks_;
  mojo::RemoteSet<mojom::EthJsonRpcControllerObserver> observers_;

  mojo::ReceiverSet<mojom::EthJsonRpcController> receivers_;
  PrefService* prefs_ = nullptr;
  base::WeakPtrFactory<EthJsonRpcController> weak_ptr_factory_;
};

}  // namespace brave_wallet

#endif  // BRAVE_COMPONENTS_BRAVE_WALLET_BROWSER_ETH_JSON_RPC_CONTROLLER_H_
