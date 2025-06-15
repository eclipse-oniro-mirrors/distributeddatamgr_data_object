/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PROGRESS_NOTIFIER_IMPL_H
#define PROGRESS_NOTIFIER_IMPL_H

#include "js_watcher.h"
#include <mutex>

namespace OHOS::ObjectStore {
class ProgressNotifierImpl : public ProgressNotifier {
public:
    static std::shared_ptr<ProgressNotifierImpl> GetInstance();
    virtual ~ProgressNotifierImpl();
    
    void AddWatcher(const std::string &sessionId, std::weak_ptr<JSWatcher> watcher);
    void DelWatcher(const std::string &sessionId);
    void OnChanged(const std::string &sessionId, int32_t progress) override;

private:
    std::mutex mutex_;
    std::map<std::string, std::weak_ptr<JSWatcher>> watchers_;
};
} // namespace OHOS::ObjectStore

#endif // PROGRESS_NOTIFIER_IMPL_H