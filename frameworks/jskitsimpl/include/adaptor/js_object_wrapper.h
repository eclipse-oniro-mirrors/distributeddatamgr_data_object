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

#ifndef JS_OBJECT_WRAPPER_H
#define JS_OBJECT_WRAPPER_H

#include "js_watcher.h"

namespace OHOS::ObjectStore {
class JSObjectWrapper {
public:
    JSObjectWrapper(DistributedObjectStore *objectStore, DistributedObject *object);
    virtual ~JSObjectWrapper();
    DistributedObject *GetObject();
    bool AddWatch(napi_env env, const char *type, napi_value handler);
    void DeleteWatch(napi_env env, const char *type, napi_value handler = nullptr);
    bool IsUndefined(const char *value);
    void AddUndefined(const char *value);
    void DeleteUndefined(const char *value);
    void DestroyObject();
    void SetObjectId(const std::string &objectId);
    std::string GetObjectId();

private:
    DistributedObjectStore *objectStore_ = nullptr;
    DistributedObject *object_ = nullptr;
    std::shared_ptr<JSWatcher> watcher_ = nullptr;
    std::shared_mutex watchMutex_{};
    std::mutex mutex_;
    std::vector<std::string> undefinedProperties_;
    std::string objectId_;
};
} // namespace OHOS::ObjectStore

#endif
