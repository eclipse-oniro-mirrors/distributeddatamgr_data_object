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

#define LOG_TAG "DBStoreConfig"

#include "db_store_config.h"

namespace OHOS::CollaborationEdit {
DBStoreConfig::DBStoreConfig(std::string path, std::string name) : path_(path), name_(name)
{}

DBStoreConfig::~DBStoreConfig()
{}

std::string DBStoreConfig::GetName() const
{
    return name_;
}

std::string DBStoreConfig::GetPath() const
{
    return path_;
}
} // namespace OHOS::CollaborationEdit
