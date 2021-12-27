/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef FLAT_OBJECT_STORAGE_ENGINE_H
#define FLAT_OBJECT_STORAGE_ENGINE_H

#include <cstdint>
#include <map>
#include <shared_mutex>
#include <vector>

#include "kv_store_delegate_manager.h"
#include "object_storage_engine.h"

namespace OHOS::ObjectStore {
class FlatObjectStorageEngine : public ObjectStorageEngine {
public:
    FlatObjectStorageEngine() = default;
    ~FlatObjectStorageEngine() override;
    bool opened_ = false;
    uint32_t Open() override;
    uint32_t Close() override;
    //delete local table
    uint32_t DeleteTable(const std::string &key) override;
    uint32_t CreateTable(const std::string &key) override;
    uint32_t GetTable(const std::string &key, std::map<Field, Value> &result) override;
    uint32_t UpdateItems(const std::string &key, std::map<Field, Value> &data) override;
    uint32_t GetItem(const std::string &key, const Field &itemKey, const Field &value) override;
    uint32_t RegisterObserver(const std::string &key, std::shared_ptr<TableWatcher> watcher) override;
    uint32_t UnRegisterObserver(const std::string &key) override;
    //刷新delegates中的key为新的key
    uint32_t ChangeKey(const std::string &oldKey, const std::string &newKey) override;
    //刷新delegates中的key为 call SetEqualIdentifier
    uint32_t ChangeSession(const std::string &objectId, const std::string &sessionId) override;

private:
    std::shared_mutex operationMutex_{};
    std::shared_ptr<KvStoreDelegateManager> storeManager_;
    std::map<std::string, KvStoreNbDelegate *> delegates;
    std::map<std::string, TableWatcher *> observerMap_;
};
} // namespace OHOS::ObjectStore
#endif
