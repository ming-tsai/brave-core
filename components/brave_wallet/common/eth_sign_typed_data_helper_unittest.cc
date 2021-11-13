/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/components/brave_wallet/common/eth_sign_typed_data_helper.h"

#include "base/json/json_reader.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace brave_wallet {

TEST(EthSignedTypedDataHelperUnitTest, Types) {
  const std::string types_json(R"({
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person"},
        {"name": "contents", "type": "string"}
    ],
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"}
    ]})");

  auto types_value =
      base::JSONReader::Read(types_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(types_value);

  std::unique_ptr<SignTypedDataHelper> helper = SignTypedDataHelper::Create(
      *types_value, SignTypedDataHelper::Version::kV4);
  ASSERT_TRUE(helper);
  const std::string encoded_types_v4 = helper->EncodeTypes("Mail");
  EXPECT_EQ(encoded_types_v4,
            "Mail(Person from,Person to,string contents)Person(string "
            "name,address wallet)");
  auto typed_hash_v4 = helper->GetTypeHash("Mail");
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(typed_hash_v4)),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2");

  // v3 should be same as v4
  helper->SetVersion(SignTypedDataHelper::Version::kV3);
  const std::string encoded_types_v3 = helper->EncodeTypes("Mail");
  EXPECT_EQ(encoded_types_v4, encoded_types_v3);
  auto typed_hash_v3 = helper->GetTypeHash("Mail");
  EXPECT_EQ(typed_hash_v3, typed_hash_v4);
}

TEST(EthSignedTypedDataHelperUnitTest, EncodedData) {
  const std::string types_json(R"({
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person"},
        {"name": "contents", "type": "string"}
    ],
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"}
    ]})");
  const std::string data_json(R"({
    "from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents":"Hello, Bob!"
    })");
  auto types_value =
      base::JSONReader::Read(types_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(types_value);
  auto data_value =
      base::JSONReader::Read(data_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(data_value);

  std::unique_ptr<SignTypedDataHelper> helper = SignTypedDataHelper::Create(
      *types_value, SignTypedDataHelper::Version::kV4);
  ASSERT_TRUE(helper);
  auto encoded_mail_v4 = helper->EncodeData("Mail", *data_value);
  ASSERT_TRUE(encoded_mail_v4);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*encoded_mail_v4)),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
            "fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd"
            "54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aa"
            "df3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8");
  auto data_mail_hash_v4 = helper->HashStruct("Mail", *data_value);
  ASSERT_TRUE(data_mail_hash_v4);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*data_mail_hash_v4)),
            "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");
  auto encoded_person_v4 =
      helper->EncodeData("Person", *(data_value->FindKey("to")));
  ASSERT_TRUE(encoded_person_v4);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*encoded_person_v4)),
            "b9d8c78acf9b987311de6c7b45bb6a9c8e1bf361fa7fd3467a2163f994c79500"
            "28cac318a86c8a0a6a9156c2dba2c8c2363677ba0514ef616592d81557e679b600"
            "0000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

  // v3 should be same as v4
  helper->SetVersion(SignTypedDataHelper::Version::kV3);
  auto encoded_mail_v3 = helper->EncodeData("Mail", *data_value);
  ASSERT_TRUE(encoded_mail_v3);
  EXPECT_EQ(encoded_mail_v4, encoded_mail_v3);
  auto encoded_person_v3 =
      helper->EncodeData("Person", *(data_value->FindKey("to")));
  EXPECT_EQ(encoded_person_v4, encoded_person_v3);

#if 0
  auto ds_hash = helper->HashStruct("EIP712Domain", *ds_value);
  ASSERT_TRUE(ds_hash);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*ds_hash)),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");

  auto message_to_sign =
      helper->GetTypedDataMessageToSign("Mail", *data_value, *ds_value);
  ASSERT_TRUE(message_to_sign);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*message_to_sign)),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
#endif
}

TEST(EthSignedTypedDataHelperUnitTest, RecursiveCustomTypes) {
  const std::string types_json(R"({
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person"},
        {"name": "contents", "type": "string"},
        {"name": "replyTo", "type": "Mail"}
    ],
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"}
    ]})");
  const std::string data_json(R"({
    "from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents":"Hello, Bob!",
    "replyTo": {
      "from": {"name": "Bob",
               "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
      "to": {"name": "Cow",
             "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
      "contents": "Hello Cow"
     }
    })");
  auto types_value =
      base::JSONReader::Read(types_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(types_value);
  auto data_value =
      base::JSONReader::Read(data_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(data_value);

  std::unique_ptr<SignTypedDataHelper> helper = SignTypedDataHelper::Create(
      *types_value, SignTypedDataHelper::Version::kV4);
  ASSERT_TRUE(helper);
  auto encoded_data_v4 = helper->EncodeData("Mail", *data_value);
  ASSERT_TRUE(encoded_data_v4);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*encoded_data_v4)),
            "66658e9662034bcd21df657297dab8ba47f0ae05dd8aa253cc935d9aacfd9d10fc"
            "71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54"
            "f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf"
            "3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8ed72793e"
            "a6e1bae312dead22c15863b41b67128e0e130ca6d330d302f6d15bc1");

  // v3 and v4 handles resursive types differently
  helper->SetVersion(SignTypedDataHelper::Version::kV3);
  auto encoded_data_v3 = helper->EncodeData("Mail", *data_value);
  ASSERT_TRUE(encoded_data_v3);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*encoded_data_v3)),
            "66658e9662034bcd21df657297dab8ba47f0ae05dd8aa253cc935d9aacfd9d10fc"
            "71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54"
            "f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf"
            "3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8574747e4"
            "62dfdd0a5bbff373d3fcedef5483dba85f0afc5a154f4e4bb5e9ff94");
  EXPECT_NE(encoded_data_v4, encoded_data_v3);
}

TEST(EthSignedTypedDataHelperUnitTest, MissingFieldInData) {
  const std::string types_json(R"({
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person"},
        {"name": "contents", "type": "string"}
    ],
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"}
    ]})");
  const std::string data_json(R"({
    "to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents":"Hello, Bob!"
    })");

  auto types_value =
      base::JSONReader::Read(types_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(types_value);
  auto data_value =
      base::JSONReader::Read(data_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(data_value);

  std::unique_ptr<SignTypedDataHelper> helper = SignTypedDataHelper::Create(
      *types_value, SignTypedDataHelper::Version::kV4);
  ASSERT_TRUE(helper);
  auto encoded_data_v4 = helper->EncodeData("Mail", *data_value);
  ASSERT_TRUE(encoded_data_v4);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*encoded_data_v4)),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac200"
            "00000000000000000000000000000000000000000000000000000000000000cd54"
            "f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf"
            "3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8");

  // v3 and v4 handles resursive types differently
  helper->SetVersion(SignTypedDataHelper::Version::kV3);
  auto encoded_data_v3 = helper->EncodeData("Mail", *data_value);
  ASSERT_TRUE(encoded_data_v3);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*encoded_data_v3)),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2cd"
            "54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aa"
            "df3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8");
  EXPECT_NE(encoded_data_v4, encoded_data_v3);
}

TEST(EthSignedTypedDataHelperUnitTest, ArrayTypes) {
  const std::string types_json(R"({
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person[]"},
        {"name": "contents", "type": "string"}
    ],
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"}
    ]})");
  const std::string data_json(R"({
    "from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to":[
      {"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
      {"name":"Alice","wallet":"0xaAaAAAAaaAAAaaaAaaAaaaaAAaAaaaaAaAaaAAaA"},
    ],
    "contents":"Hello, Alice & Bob!"
    })");

  auto types_value =
      base::JSONReader::Read(types_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(types_value);
  auto data_value =
      base::JSONReader::Read(data_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(data_value);

  std::unique_ptr<SignTypedDataHelper> helper = SignTypedDataHelper::Create(
      *types_value, SignTypedDataHelper::Version::kV4);
  ASSERT_TRUE(helper);
  auto encoded_data = helper->EncodeData("Mail", *data_value);
  ASSERT_TRUE(encoded_data);
  EXPECT_EQ(base::ToLowerASCII(base::HexEncode(*encoded_data)),
            "dd57d9596af52b430ced3d5b52d4e3d5dccfdf3e0572db1dcf526baad311fbd1fc"
            "71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c86447"
            "52e282fcf7fda2a1198d94a0fdc47c09b694e927a40403469fa89f10bbda2b6bac"
            "81575e5745e20d779659dad4d4b9f0967f8d346228028a8675ee5377df");

  // v3 doesn't support array
  helper->SetVersion(SignTypedDataHelper::Version::kV3);
  EXPECT_FALSE(helper->EncodeData("Mail", *data_value));
}

TEST(EthSignedTypedDataHelperUnitTest, EncodeField) {
  // types won't matter here
  std::unique_ptr<SignTypedDataHelper> helper = SignTypedDataHelper::Create(
      base::DictionaryValue(), SignTypedDataHelper::Version::kV3);
  ASSERT_TRUE(helper);

  base::ListValue list;
  list.Append("hello");
  list.Append("world");

  // v3 doesn't support array
  EXPECT_FALSE(helper->EncodeField("string[]", list));
  helper->SetVersion(SignTypedDataHelper::Version::kV4);

  // invalid arrary type
  EXPECT_FALSE(helper->EncodeField("string[[]]", list));
  // non exist custom array type
  EXPECT_FALSE(helper->EncodeField("Sting[[]]", list));
  EXPECT_FALSE(helper->EncodeField("string[]", base::Value("not list")));
}

}  // namespace brave_wallet
