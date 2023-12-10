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

#include "flat_object_store.h"

#include "client_adaptor.h"
#include "distributed_objectstore_impl.h"
#include "logger.h"
#include "object_callback_impl.h"
#include "object_service_proxy.h"
#include "objectstore_errors.h"
#include "softbus_adapter.h"
#include "string_utils.h"
#include "bytes_utils.h"

namespace OHOS::ObjectStore {
FlatObjectStore::FlatObjectStore(const std::string &bundleName)
{
    bundleName_ = bundleName;
    storageEngine_ = std::make_shared<FlatObjectStorageEngine>();
    uint32_t status = storageEngine_->Open(bundleName);
    if (status != SUCCESS) {
        LOG_ERROR("FlatObjectStore: Failed to open, error: open storage engine failure %{public}d", status);
    }
    cacheManager_ = new CacheManager();
}

FlatObjectStore::~FlatObjectStore()
{
    if (storageEngine_ != nullptr) {
        storageEngine_->Close();
        storageEngine_ = nullptr;
    }
    delete cacheManager_;
    cacheManager_ = nullptr;
}

uint32_t FlatObjectStore::CreateObject(const std::string &sessionId)
{
    if (!storageEngine_->isOpened_ && storageEngine_->Open(bundleName_) != SUCCESS) {
        LOG_ERROR("FlatObjectStore::DB has not inited");
        return ERR_DB_NOT_INIT;
    }
    uint32_t status = storageEngine_->CreateTable(sessionId);
    if (status != SUCCESS) {
        LOG_ERROR("FlatObjectStore::CreateObject createTable err %{public}d", status);
        return status;
    }
    std::function<void(const std::map<std::string, std::vector<uint8_t>> &data)> callback =
        [sessionId, this](
            const std::map<std::string, std::vector<uint8_t>> &data) {
            if (data.size() > 0) {
                LOG_INFO("objectstore, retrieve success");
                {
                    std::lock_guard<std::mutex> lck(mutex_);
                    if (find(retrievedCache_.begin(), retrievedCache_.end(), sessionId) == retrievedCache_.end()) {
                        retrievedCache_.push_back(sessionId);
                    }
                }
                auto result = storageEngine_->UpdateItems(sessionId, data);
                if (result != SUCCESS) {
                    LOG_ERROR("UpdateItems failed, status = %{public}d", result);
                }
            } else {
                LOG_INFO("objectstore, retrieve empty");
            }
        };
    std::function<void(const std::map<std::string, std::vector<uint8_t>> &data)> remoteResumeCallback =
            [sessionId, this](
                    const std::map<std::string, std::vector<uint8_t>> &data) {
                LOG_INFO("SubscribeDataChange callback success.");
                std::map<std::string, std::vector<uint8_t>> filteredData = data;
                FilterData(sessionId, filteredData);
                if (!filteredData.empty()) {
                    auto status = storageEngine_->UpdateItems(sessionId, filteredData);
                    if (status != SUCCESS) {
                        LOG_ERROR("UpdateItems failed, status = %{public}d", status);
                    }
                    storageEngine_->NotifyChange(sessionId, filteredData);
                }
                storageEngine_->NotifyStatus(sessionId, "local", "restored");
            };
    cacheManager_->ResumeObject(bundleName_, sessionId, callback);
    cacheManager_->SubscribeDataChange(bundleName_, sessionId, remoteResumeCallback);
    return SUCCESS;
}

uint32_t FlatObjectStore::Delete(const std::string &sessionId)
{
    if (!storageEngine_->isOpened_ && storageEngine_->Open(bundleName_) != SUCCESS) {
        LOG_ERROR("FlatObjectStore::DB has not inited");
        return ERR_DB_NOT_INIT;
    }
    uint32_t status = storageEngine_->DeleteTable(sessionId);
    if (status != SUCCESS) {
        LOG_ERROR("FlatObjectStore: Failed to delete object %{public}d", status);
        return status;
    }
    cacheManager_->UnregisterDataChange(bundleName_, sessionId);
    cacheManager_->DeleteSnapshot(bundleName_, sessionId);
    return SUCCESS;
}

uint32_t FlatObjectStore::Watch(const std::string &sessionId, std::shared_ptr<FlatObjectWatcher> watcher)
{
    if (!storageEngine_->isOpened_ && storageEngine_->Open(bundleName_) != SUCCESS) {
        LOG_ERROR("FlatObjectStore::DB has not inited");
        return ERR_DB_NOT_INIT;
    }
    uint32_t status = storageEngine_->RegisterObserver(sessionId, watcher);
    if (status != SUCCESS) {
        LOG_ERROR("FlatObjectStore::Watch failed %{public}d", status);
    }
    return status;
}

uint32_t FlatObjectStore::UnWatch(const std::string &sessionId)
{
    if (!storageEngine_->isOpened_ && storageEngine_->Open(bundleName_) != SUCCESS) {
        LOG_ERROR("FlatObjectStore::DB has not inited");
        return ERR_DB_NOT_INIT;
    }
    uint32_t status = storageEngine_->UnRegisterObserver(sessionId);
    if (status != SUCCESS) {
        LOG_ERROR("FlatObjectStore::Watch failed %{public}d", status);
    }
    return status;
}

uint32_t FlatObjectStore::Put(const std::string &sessionId, const std::string &key, std::vector<uint8_t> value)
{
    if (!storageEngine_->isOpened_ && storageEngine_->Open(bundleName_) != SUCCESS) {
        LOG_ERROR("FlatObjectStore::DB has not inited");
        return ERR_DB_NOT_INIT;
    }
    return storageEngine_->UpdateItem(sessionId, key, value);
}

uint32_t FlatObjectStore::Get(const std::string &sessionId, const std::string &key, Bytes &value)
{
    if (!storageEngine_->isOpened_ && storageEngine_->Open(bundleName_) != SUCCESS) {
        LOG_ERROR("FlatObjectStore::DB has not inited");
        return ERR_DB_NOT_INIT;
    }
    return storageEngine_->GetItem(sessionId, key, value);
}

uint32_t FlatObjectStore::SetStatusNotifier(std::shared_ptr<StatusWatcher> notifier)
{
    if (!storageEngine_->isOpened_ && storageEngine_->Open(bundleName_) != SUCCESS) {
        LOG_ERROR("FlatObjectStore::DB has not inited");
        return ERR_DB_NOT_INIT;
    }
    return storageEngine_->SetStatusNotifier(notifier);
}

uint32_t FlatObjectStore::SyncAllData(const std::string &sessionId,
    const std::function<void(const std::map<std::string, DistributedDB::DBStatus> &)> &onComplete)
{
    if (!storageEngine_->isOpened_ && storageEngine_->Open(bundleName_) != SUCCESS) {
        LOG_ERROR("FlatObjectStore::DB has not inited");
        return ERR_DB_NOT_INIT;
    }
    std::vector<DeviceInfo> devices = SoftBusAdapter::GetInstance()->GetDeviceList();
    std::vector<std::string> deviceIds;
    for (auto item : devices) {
        deviceIds.push_back(item.deviceId);
    }
    return storageEngine_->SyncAllData(sessionId, deviceIds, onComplete);
}

uint32_t FlatObjectStore::Save(const std::string &sessionId, const std::string &deviceId)
{
    if (cacheManager_ == nullptr) {
        LOG_ERROR("FlatObjectStore::cacheManager_ is null");
        return ERR_NULL_PTR;
    }
    std::map<std::string, std::vector<uint8_t>> objectData;
    uint32_t status = storageEngine_->GetItems(sessionId, objectData);
    if (status != SUCCESS) {
        LOG_ERROR("FlatObjectStore::GetItems fail");
        return status;
    }
    return cacheManager_->Save(bundleName_, sessionId, deviceId, objectData);
}

uint32_t FlatObjectStore::RevokeSave(const std::string &sessionId)
{
    if (cacheManager_ == nullptr) {
        LOG_ERROR("FlatObjectStore::cacheManager_ is null");
        return ERR_NULL_PTR;
    }
    return cacheManager_->RevokeSave(bundleName_, sessionId);
}

uint32_t FlatObjectStore::BindAssetStore(const std::string &sessionId, AssetBindInfo &bindInfo, Asset &assetValue)
{
    std::unique_lock<std::mutex> lck(mutex_);
    sptr<OHOS::DistributedObject::IObjectService> proxy = ClientAdaptor::GetObjectService();
    if (proxy == nullptr) {
        LOG_ERROR("proxy is nullptr.");
        return ERR_PROCESSING;
    }
    int32_t status = proxy->BindAssetStore(bundleName_, sessionId, assetValue, bindInfo);
    if (status != SUCCESS) {
        LOG_ERROR("object bind asset failed code=%{public}d.", static_cast<int>(status));
    }
    LOG_DEBUG("object bind asset successful sessionId: %{public}s and assetName %{public}s", sessionId.c_str(),
        assetValue.name.c_str());
    return status;
}

void FlatObjectStore::CheckRetrieveCache(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lck(mutex_);
    auto iter = find(retrievedCache_.begin(), retrievedCache_.end(), sessionId);
    if (iter != retrievedCache_.end()) {
        storageEngine_->NotifyStatus(*iter, "local", "restored");
        retrievedCache_.erase(iter);
    }
}

void FlatObjectStore::FilterData(const std::string &sessionId,
                                 std::map<std::string, std::vector<uint8_t>> &data)
{
    std::map<std::string, std::vector<uint8_t>> allData {};
    storageEngine_->GetItems(sessionId, allData);
    for (const auto &item : allData) {
        data.erase(item.first);
    }
}

uint32_t FlatObjectStore::PutDouble(const std::string &sessionId, const std::string &key, double value)
{
    Bytes data;
    Type type = Type::TYPE_DOUBLE;
    BytesUtils::PutNum(&type, 0, sizeof(type), data);
    BytesUtils::PutNum(&value, sizeof(type), sizeof(value), data);
    return Put(sessionId, FIELDS_PREFIX + key, data);
}

uint32_t FlatObjectStore::PutBoolean(const std::string &sessionId, const std::string &key, bool value)
{
    Bytes data;
    Type type = Type::TYPE_BOOLEAN;
    BytesUtils::PutNum(&type, 0, sizeof(type), data);
    BytesUtils::PutNum(&value, sizeof(type), sizeof(value), data);
    return Put(sessionId, FIELDS_PREFIX + key, data);
}

uint32_t FlatObjectStore::PutString(const std::string &sessionId, const std::string &key, const std::string &value)
{
    Bytes data;
    Type type = Type::TYPE_STRING;
    BytesUtils::PutNum(&type, 0, sizeof(type), data);
    Bytes dst = StringUtils::StrToBytes(value);
    data.insert(data.end(), dst.begin(), dst.end());
    return Put(sessionId, FIELDS_PREFIX + key, data);
}

uint32_t FlatObjectStore::GetDouble(const std::string &sessionId, const std::string &key, double &value)
{
    Bytes data;
    Bytes keyBytes = StringUtils::StrToBytes(key);
    uint32_t status = Get(sessionId, FIELDS_PREFIX + key, data);
    if (status != SUCCESS) {
        LOG_ERROR("GetDouble field not exist. %{public}d %{public}s", status, key.c_str());
        return status;
    }
    status = BytesUtils::GetNum(data, sizeof(Type), &value, sizeof(value));
    if (status != SUCCESS) {
        LOG_ERROR("GetDouble getNum err. %{public}d", status);
    }
    return status;
}

uint32_t FlatObjectStore::GetBoolean(const std::string &sessionId, const std::string &key, bool &value)
{
    Bytes data;
    Bytes keyBytes = StringUtils::StrToBytes(key);
    uint32_t status = Get(sessionId, FIELDS_PREFIX + key, data);
    if (status != SUCCESS) {
        LOG_ERROR("GetBoolean field not exist. %{public}d %{public}s", status, key.c_str());
        return status;
    }
    status = BytesUtils::GetNum(data, sizeof(Type), &value, sizeof(value));
    if (status != SUCCESS) {
        LOG_ERROR("GetBoolean getNum err. %{public}d", status);
        return status;
    }
    return SUCCESS;
}

uint32_t FlatObjectStore::GetString(const std::string &sessionId, const std::string &key, std::string &value)
{
    Bytes data;
    uint32_t status = Get(sessionId, FIELDS_PREFIX + key, data);
    if (status != SUCCESS) {
        LOG_ERROR("GetString field not exist. %{public}d %{public}s", status, key.c_str());
        return status;
    }
    status = StringUtils::BytesToStrWithType(data, value);
    if (status != SUCCESS) {
        LOG_ERROR("GetString dataToVal err. %{public}d", status);
    }
    return status;
}

uint32_t FlatObjectStore::PutComplex(const std::string &sessionId, const std::string &key,
    const std::vector<uint8_t> &value)
{
    Bytes data;
    Type type = Type::TYPE_COMPLEX;
    BytesUtils::PutNum(&type, 0, sizeof(type), data);
    data.insert(data.end(), value.begin(), value.end());
    uint32_t status = Put(sessionId, FIELDS_PREFIX + key, data);
    if (status != SUCCESS) {
        LOG_ERROR("PutBoolean setField err %{public}d", status);
    }
    return status;
}

uint32_t FlatObjectStore::GetComplex(const std::string &sessionId, const std::string &key,
    std::vector<uint8_t> &value)
{
    uint32_t status = Get(sessionId, FIELDS_PREFIX + key, value);
    if (status != SUCCESS) {
        LOG_ERROR("GetString field not exist. %{public}d %{public}s", status, key.c_str());
        return status;
    }
    value.erase(value.begin(), value.begin() + sizeof(Type));
    return status;
}

uint32_t FlatObjectStore::GetType(const std::string &sessionId, const std::string &key, Type &type)
{
    Bytes data;
    uint32_t status = Get(sessionId, FIELDS_PREFIX + key, data);
    if (status != SUCCESS) {
        LOG_ERROR("GetString field not exist. %{public}d %{public}s", status, key.c_str());
        return status;
    }
    status = BytesUtils::GetNum(data, 0, &type, sizeof(type));
    if (status != SUCCESS) {
        LOG_ERROR("GetBoolean getNum err. %{public}d", status);
        return status;
    }
    return SUCCESS;
}

std::string FlatObjectStore::GetBundleName()
{
    return bundleName_;
}

CacheManager::CacheManager()
{
}

uint32_t CacheManager::Save(const std::string &bundleName, const std::string &sessionId, const std::string &deviceId,
    const std::map<std::string, std::vector<uint8_t>> &objectData)
{
    std::unique_lock<std::mutex> lck(mutex_);
    ConditionLock<int32_t> conditionLock;
    int32_t status = SaveObject(bundleName, sessionId, deviceId, objectData,
        [this, &deviceId, &conditionLock](const std::map<std::string, int32_t> &results) {
            LOG_INFO("CacheManager::task callback");
            if (results.count(deviceId) != 0) {
                conditionLock.Notify(results.at(deviceId));
            } else {
                conditionLock.Notify(ERR_DB_GET_FAIL);
            }
        });
    if (status != SUCCESS) {
        LOG_ERROR("SaveObject failed");
        return status;
    }
    LOG_INFO("CacheManager::start wait");
    status = conditionLock.Wait();
    LOG_INFO("CacheManager::end wait, %{public}d", status);
    return status == SUCCESS ? status : ERR_DB_GET_FAIL;
}

uint32_t CacheManager::RevokeSave(const std::string &bundleName, const std::string &sessionId)
{
    std::unique_lock<std::mutex> lck(mutex_);
    ConditionLock<int32_t> conditionLock;
    std::function<void(int32_t)> callback = [this, &conditionLock](int32_t result) {
        LOG_INFO("CacheManager::task callback");
        conditionLock.Notify(result);
    };
    int32_t status = RevokeSaveObject(bundleName, sessionId, callback);
    if (status != SUCCESS) {
        LOG_ERROR("RevokeSaveObject failed");
        return status;
    }
    LOG_INFO("CacheManager::start wait");
    status = conditionLock.Wait();
    LOG_INFO("CacheManager::end wait, %{public}d", status);
    return status == SUCCESS ? status : ERR_DB_GET_FAIL;
}

int32_t CacheManager::SaveObject(const std::string &bundleName, const std::string &sessionId,
    const std::string &deviceId, const std::map<std::string, std::vector<uint8_t>> &objectData,
    const std::function<void(const std::map<std::string, int32_t> &)> &callback)
{
    sptr<OHOS::DistributedObject::IObjectService> proxy = ClientAdaptor::GetObjectService();
    if (proxy == nullptr) {
        LOG_ERROR("proxy is nullptr.");
        return ERR_PROCESSING;
    }
    sptr<ObjectSaveCallbackBroker> objectSaveCallback = new (std::nothrow) ObjectSaveCallback(callback);
    if (objectSaveCallback == nullptr) {
        LOG_ERROR("CacheManager::SaveObject no memory for ObjectSaveCallback malloc!");
        return ERR_NULL_PTR;
    }
    int32_t status = proxy->ObjectStoreSave(
        bundleName, sessionId, deviceId, objectData, objectSaveCallback->AsObject().GetRefPtr());
    if (status != SUCCESS) {
        LOG_ERROR("object save failed code=%d.", static_cast<int>(status));
    }
    LOG_INFO("object save successful");
    return status;
}

int32_t CacheManager::RevokeSaveObject(
    const std::string &bundleName, const std::string &sessionId, std::function<void(int32_t)> &callback)
{
    sptr<OHOS::DistributedObject::IObjectService> proxy = ClientAdaptor::GetObjectService();
    if (proxy == nullptr) {
        LOG_ERROR("proxy is nullptr.");
        return ERR_PROCESSING;
    }
    sptr<ObjectRevokeSaveCallbackBroker> objectRevokeSaveCallback = new (std::nothrow)
        ObjectRevokeSaveCallback(callback);
    if (objectRevokeSaveCallback == nullptr) {
        LOG_ERROR("CacheManager::RevokeSaveObject no memory for ObjectRevokeSaveCallback malloc!");
        return ERR_NULL_PTR;
    }
    int32_t status = proxy->ObjectStoreRevokeSave(
        bundleName, sessionId, objectRevokeSaveCallback->AsObject().GetRefPtr());
    if (status != SUCCESS) {
        LOG_ERROR("object revoke save failed code=%d.", static_cast<int>(status));
    }
    LOG_INFO("object revoke save successful");
    return status;
}

int32_t CacheManager::ResumeObject(const std::string &bundleName, const std::string &sessionId,
    std::function<void(const std::map<std::string, std::vector<uint8_t>> &data)> &callback)
{
    sptr<OHOS::DistributedObject::IObjectService> proxy = ClientAdaptor::GetObjectService();
    if (proxy == nullptr) {
        LOG_ERROR("proxy is nullptr.");
        return ERR_NULL_PTR;
    }
    sptr<ObjectRetrieveCallbackBroker> objectRetrieveCallback = new (std::nothrow) ObjectRetrieveCallback(callback);
    if (objectRetrieveCallback == nullptr) {
        LOG_ERROR("CacheManager::ResumeObject no memory for ObjectRetrieveCallback malloc!");
        return ERR_NULL_PTR;
    }
    int32_t status = proxy->ObjectStoreRetrieve(
        bundleName, sessionId, objectRetrieveCallback->AsObject().GetRefPtr());
    if (status != SUCCESS) {
        LOG_ERROR("object resume failed code=%d.", static_cast<int>(status));
    }
    LOG_INFO("object resume successful");
    return status;
}

int32_t CacheManager::SubscribeDataChange(const std::string &bundleName, const std::string &sessionId,
    std::function<void(const std::map<std::string, std::vector<uint8_t>> &data)> &callback)
{
    sptr<OHOS::DistributedObject::IObjectService> proxy = ClientAdaptor::GetObjectService();
    if (proxy == nullptr) {
        LOG_ERROR("proxy is nullptr.");
        return ERR_NULL_PTR;
    }
    sptr<ObjectChangeCallbackBroker> objectRemoteResumeCallback = new (std::nothrow) ObjectChangeCallback(callback);
    if (objectRemoteResumeCallback == nullptr) {
        LOG_ERROR("CacheManager::SubscribeDataChange no memory for ObjectChangeCallback malloc!");
        return ERR_NULL_PTR;
    }
    ClientAdaptor::RegisterClientDeathListener(bundleName, objectRemoteResumeCallback->AsObject());
    int32_t status = proxy->RegisterDataObserver(
        bundleName, sessionId, objectRemoteResumeCallback->AsObject().GetRefPtr());
    if (status != SUCCESS) {
        LOG_ERROR("object remote resume failed code=%d.", static_cast<int>(status));
    }
    LOG_INFO("object remote resume successful");
    return status;
}

int32_t CacheManager::UnregisterDataChange(const std::string &bundleName, const std::string &sessionId)
{
    sptr<OHOS::DistributedObject::IObjectService> proxy = ClientAdaptor::GetObjectService();
    if (proxy == nullptr) {
        LOG_ERROR("proxy is nullptr.");
        return ERR_NULL_PTR;
    }
    int32_t status = proxy->UnregisterDataChangeObserver(bundleName, sessionId);
    if (status != SUCCESS) {
        LOG_ERROR("object remote resume failed code=%d.", static_cast<int>(status));
    }
    LOG_INFO("object unregister data change observer successful");
    return status;
}

int32_t CacheManager::DeleteSnapshot(const std::string &bundleName, const std::string &sessionId)
{
    sptr<OHOS::DistributedObject::IObjectService> proxy = ClientAdaptor::GetObjectService();
    if (proxy == nullptr) {
        LOG_ERROR("proxy is nullptr.");
        return ERR_NULL_PTR;
    }
    int32_t status = proxy->DeleteSnapshot(bundleName, sessionId);
    if (status != SUCCESS) {
        LOG_ERROR("object delete snapshot failed code=%d.", static_cast<int>(status));
    }
    LOG_INFO("object delete snapshot successful");
    return status;
}
} // namespace OHOS::ObjectStore
