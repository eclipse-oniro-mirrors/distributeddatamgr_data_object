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
#include "dev_manager.h"

#include <logger.h>

#include "anonymous.h"
#include "device_manager.h"
#include "softbus_adapter.h"

namespace OHOS {
namespace ObjectStore {
using namespace OHOS::DistributedHardware;
using DevInfo = OHOS::DistributedHardware::DmDeviceInfo;
constexpr int32_t DM_OK = 0;
constexpr int32_t DM_ERROR = -1;
constexpr const char *PKG_NAME = "ohos.objectstore";
class DMStateCallback : public DeviceStateCallback {
public:
    explicit DMStateCallback(std::shared_ptr<SoftBusAdapter> softBusAdapter) : softBusAdapter_(softBusAdapter){};
    void OnDeviceOnline(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const DmDeviceInfo &deviceInfo) override;

private:
    std::shared_ptr<SoftBusAdapter> softBusAdapter_;
    void NotifyAll(const DmDeviceInfo &deviceInfo, DeviceChangeType type);
};

void DMStateCallback::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    std::string uuid = DevManager::GetInstance()->GetUuidByNodeId(std::string(deviceInfo.networkId));
    LOG_INFO("[Online] id:%{public}s, name:%{public}s, typeId:%{public}d", Anonymous::Change(uuid).c_str(),
        deviceInfo.deviceName, deviceInfo.deviceTypeId);
    NotifyAll(deviceInfo, DeviceChangeType::DEVICE_ONLINE);
}

void DMStateCallback::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    std::string uuid = DevManager::GetInstance()->GetUuidByNodeId(std::string(deviceInfo.networkId));
    LOG_INFO("[Offline] id:%{public}s, name:%{public}s, typeId:%{public}d", Anonymous::Change(uuid).c_str(),
        deviceInfo.deviceName, deviceInfo.deviceTypeId);
    NotifyAll(deviceInfo, DeviceChangeType::DEVICE_OFFLINE);
}

void DMStateCallback::OnDeviceChanged(const DmDeviceInfo &deviceInfo)
{
    std::string uuid = DevManager::GetInstance()->GetUuidByNodeId(std::string(deviceInfo.networkId));
    LOG_INFO("[InfoChange] id:%{public}s, name:%{public}s", Anonymous::Change(uuid).c_str(), deviceInfo.deviceName);
}

void DMStateCallback::OnDeviceReady(const DmDeviceInfo &deviceInfo)
{
}

class DmDeathCallback : public DmInitCallback {
public:
    explicit DmDeathCallback(DevManager &devManager) : devManager_(devManager){};
    void OnRemoteDied() override;

private:
    DevManager &devManager_;
};

void DmDeathCallback::OnRemoteDied()
{
    LOG_INFO("dm device manager died, init it again");
    devManager_.RegisterDevCallback();
}

void DMStateCallback::NotifyAll(const DmDeviceInfo &deviceInfo, DeviceChangeType type)
{
    DeviceInfo di = { std::string(deviceInfo.networkId), std::string(deviceInfo.deviceName),
        std::to_string(deviceInfo.deviceTypeId) };
    softBusAdapter_->NotifyAll(di, type);
}

DevManager::DevManager()
{
}

DevManager::~DevManager()
{
}

int32_t DevManager::Init()
{
    auto &deviceManager = DeviceManager::GetInstance();
    auto deviceInitCallback = std::make_shared<DmDeathCallback>(*this);
    auto deviceStateCallback = std::make_shared<DMStateCallback>(SoftBusAdapter::GetInstance());
    int32_t status = deviceManager.InitDeviceManager(PKG_NAME, deviceInitCallback);
    if (status != DM_OK) {
        return status;
    }
    status = deviceManager.RegisterDevStateCallback(PKG_NAME, "", deviceStateCallback);
    return status;
}

void DevManager::RegisterDevCallback()
{
    int32_t status = Init();
    if (status == DM_OK) {
        return;
    }
    LOG_INFO("register device callback failed, status: %{public}d, try again.", status);
    std::thread th = std::thread([this]() {
        pthread_setname_np(pthread_self(), "Data_Object_InitDevManager");
        constexpr int RETRY_TIMES = 300;
        int i = 0;
        int32_t status = DM_ERROR;
        while (i++ < RETRY_TIMES) {
            status = Init();
            if (status == DM_OK) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        LOG_INFO("register device callback exit now: %{public}d times, status: %{public}d", i, status);
    });
    th.detach();
}

std::string DevManager::GetUuidByNodeId(const std::string &nodeId) const
{
    std::string uuid = "";
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetEncryptedUuidByNetworkId(
        "ohos.objectstore", nodeId.c_str(), uuid);
    if (ret != DM_OK) {
        LOG_WARN("GetEncryptedUuidByNetworkId error, nodeId:%{public}s", Anonymous::Change(nodeId).c_str());
        return "";
    }
    return uuid;
}

const DevManager::DetailInfo &DevManager::GetLocalDevice()
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    if (!localInfo_.uuid.empty()) {
        return localInfo_;
    }
    DevInfo info;
    auto ret = DeviceManager::GetInstance().GetLocalDeviceInfo(PKG_NAME, info);
    if (ret != DM_OK) {
        LOG_ERROR("get local device info fail");
        return invalidDetail_;
    }
    auto networkId = std::string(info.networkId);
    std::string uuid;
    DeviceManager::GetInstance().GetEncryptedUuidByNetworkId(PKG_NAME, networkId, uuid);
    if (uuid.empty() || networkId.empty()) {
        return invalidDetail_;
    }
    localInfo_.networkId = std::move(networkId);
    localInfo_.uuid = std::move(uuid);
    return localInfo_;
}
} // namespace ObjectStore
} // namespace OHOS