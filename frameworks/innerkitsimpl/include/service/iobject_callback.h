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

#ifndef I_OBJECT_CALLBACK_H
#define I_OBJECT_CALLBACK_H

#include <map>
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
namespace DistributedObject {
class IObjectSaveCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedObject.IObjectSaveCallback");
    virtual void Completed(const std::map<std::string, int32_t> &results) = 0;
};

class IObjectRevokeSaveCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedObject.IObjectRevokeSaveCallback");
    virtual void Completed(int32_t status) = 0;
};

class IObjectRetrieveCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedObject.IObjectRetrieveCallback");
    virtual void Completed(const std::map<std::string, std::vector<uint8_t>> &results) = 0;
};

class IObjectChangeCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedObject.IObjectChangeCallback");
    virtual void Completed(const std::map<std::string, std::vector<uint8_t>> &results) = 0;
};
} // namespace DistributedObject
} // namespace OHOS

#endif // I_KVSTORE_SYNC_CALLBACK_H
