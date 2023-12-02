/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_OBJECT_ASSET_VALUE_H
#define OHOS_OBJECT_ASSET_VALUE_H

#include <string>
#include "common_values_bucket.h"

namespace OHOS {
namespace ObjectStore {
struct AssetBindInfo {
    std::string storeName;
    std::string tableName;
    CommonType::ValuesBucket primaryKey;
    std::string field;
    std::string assetName;
};

using Asset = CommonType::AssetValue;
using ValuesBucket = CommonType::ValuesBucket;
using ValueObject = CommonType::ValueObject;
using Assets = std::vector<Asset>;
} // namespace ObjectStore
} // namespace OHOS
#endif // OHOS_OBJECT_ASSET_VALUE_H