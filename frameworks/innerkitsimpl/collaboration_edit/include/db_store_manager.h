/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COLLABORATION_EDIT_DB_STORE_MANAGER_H
#define COLLABORATION_EDIT_DB_STORE_MANAGER_H

#include <map>
#include <mutex>

#include "db_error.h"
#include "db_store.h"
#include "db_store_config.h"

namespace OHOS::CollaborationEdit {
class DBStoreManager {
public:
    static DBStoreManager &GetInstance();
    DBStoreManager();
    ~DBStoreManager();
    std::shared_ptr<DBStore> GetDBStore(const DBStoreConfig &config);
    int DeleteDBStore(const DBStoreConfig &config);

private:
    std::shared_ptr<DBStore> OpenDBStore(const DBStoreConfig &config);
    int RemoveDir(const char *dir);
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<DBStore>> storeCache_;
};
} // namespace OHOS::CollaborationEdit
#endif // COLLABORATION_EDIT_DB_STORE_MANAGER_H