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
#include "flat_object_storage_engine.h"

#include "anonymous.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "objectstore_errors.h"
#include "process_communicator_impl.h"
#include "softbus_adapter.h"
#include "string_utils.h"
#include "object_radar_reporter.h"

namespace OHOS::ObjectStore {
constexpr static const char *DISTRIBUTED_DATASYNC = "ohos.permission.DISTRIBUTED_DATASYNC";

FlatObjectStorageEngine::~FlatObjectStorageEngine()
{
    if (!isOpened_) {
        return;
    }
    storeManager_ = nullptr;
    LOG_INFO("FlatObjectStorageEngine::~FlatObjectStorageEngine Crash! end");
}

uint32_t FlatObjectStorageEngine::Open(const std::string &bundleName)
{
    if (isOpened_) {
        LOG_INFO("FlatObjectDatabase: No need to reopen it");
        return SUCCESS;
    }
    auto tokenId = IPCSkeleton::GetSelfTokenID();
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, DISTRIBUTED_DATASYNC);
    LOG_INFO("bundleName:%{public}s, permission :%{public}d", bundleName.c_str(), ret);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        auto status = DistributedDB::KvStoreDelegateManager::SetProcessLabel("objectstoreDB", bundleName);
        if (status != DistributedDB::DBStatus::OK) {
            LOG_ERROR("delegate SetProcessLabel failed: %{public}d.", static_cast<int>(status));
        }
        status = DistributedDB::KvStoreDelegateManager::SetProcessCommunicator(
            std::make_shared<ProcessCommunicatorImpl>());
        if (status != DistributedDB::DBStatus::OK) {
            LOG_ERROR("set distributed db communicator failed: %{public}d.", static_cast<int>(status));
        }
    }
    storeManager_ = std::make_shared<DistributedDB::KvStoreDelegateManager>(bundleName, "default");
    DistributedDB::KvStoreConfig config;
    config.dataDir = "/data/log";
    storeManager_->SetKvStoreConfig(config);
    isOpened_ = true;
    LOG_INFO("FlatObjectDatabase::Open Succeed");
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::Close()
{
    if (!isOpened_) {
        LOG_INFO("FlatObjectStorageEngine::Close has been closed!");
        return SUCCESS;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    storeManager_ = nullptr;
    isOpened_ = false;
    return SUCCESS;
}

void FlatObjectStorageEngine::OnComplete(const std::string &key,
    const std::map<std::string, DistributedDB::DBStatus> &devices, std::shared_ptr<StatusWatcher> statusWatcher)
{
    std::lock_guard<std::mutex> lock(watcherMutex_);
    LOG_INFO("complete");
    if (statusWatcher != nullptr) {
        for (auto item : devices) {
            statusWatcher->OnChanged(key, SoftBusAdapter::GetInstance()->ToNodeID(item.first),
                item.second == DistributedDB::OK ? "online" : "offline");
        }
    }
}

uint32_t FlatObjectStorageEngine::CreateTable(const std::string &key)
{
    RadarReporter::ReportStage(std::string(__FUNCTION__), CREATE, CREATE_TABLE, IDLE);
    if (!isOpened_) {
        RadarReporter::ReportStateError(std::string(__FUNCTION__), CREATE, CREATE_TABLE,
            RADAR_FAILED, DB_NOT_INIT, FINISHED);
        return ERR_DB_NOT_INIT;
    }
    {
        std::lock_guard<std::mutex> lock(operationMutex_);
        if (delegates_.count(key) != 0) {
            LOG_ERROR("table: %{public}s already created", Anonymous::Change(key).c_str());
            RadarReporter::ReportStateError(std::string(__FUNCTION__), CREATE, CREATE_TABLE, RADAR_FAILED,
                DUPLICATE_CREATE, FINISHED);
            return ERR_EXIST;
        }
    }
    DistributedDB::KvStoreNbDelegate *kvStore = nullptr;
    DistributedDB::DBStatus status;
    DistributedDB::KvStoreNbDelegate::Option option = { true, true, false };
    LOG_INFO("start create table");
    storeManager_->GetKvStore(key, option,
        [&status, &kvStore](DistributedDB::DBStatus dbStatus, DistributedDB::KvStoreNbDelegate *kvStoreNbDelegate) {
            status = dbStatus;
            kvStore = kvStoreNbDelegate;
            LOG_INFO("create table result %{public}d", status);
        });
    if (status != DistributedDB::DBStatus::OK || kvStore == nullptr) {
        LOG_ERROR("GetKvStore fail[%{public}d], store:%{public}s", status, Anonymous::Change(key).c_str());
        RadarReporter::ReportStateError(std::string(__FUNCTION__), CREATE, CREATE_TABLE,
            RADAR_FAILED, status, FINISHED);
        return ERR_DB_GETKV_FAIL;
    }
    bool autoSync = true;
    DistributedDB::PragmaData data = static_cast<DistributedDB::PragmaData>(&autoSync);
    LOG_INFO("start Pragma");
    status = kvStore->Pragma(DistributedDB::AUTO_SYNC, data);
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR("Set Pragma fail[%{public}d], store:%{public}s", status, Anonymous::Change(key).c_str());
        RadarReporter::ReportStateError(std::string(__FUNCTION__), CREATE, CREATE_TABLE,
            RADAR_FAILED, status, FINISHED);
        return ERR_DB_GETKV_FAIL;
    }
    LOG_INFO("create table %{public}s success", Anonymous::Change(key).c_str());
    {
        std::lock_guard<std::mutex> lock(operationMutex_);
        delegates_.insert_or_assign(key, kvStore);
    }
    auto onComplete = [key, this](const std::map<std::string, DistributedDB::DBStatus> &devices) {
        OnComplete(key, devices, statusWatcher_);
    };
    std::vector<DeviceInfo> devices = SoftBusAdapter::GetInstance()->GetDeviceList();
    std::vector<std::string> deviceIds;
    for (auto item : devices) {
        deviceIds.push_back(item.deviceId);
    }
    SyncAllData(key, deviceIds, onComplete);
    RadarReporter::ReportStateFinished(std::string(__FUNCTION__), CREATE, CREATE_TABLE, RADAR_SUCCESS, FINISHED);
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::GetTable(const std::string &key, std::map<std::string, Value> &result)
{
    if (!isOpened_) {
        LOG_ERROR("not opened %{public}s", key.c_str());
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(key) == 0) {
        LOG_INFO("FlatObjectStorageEngine::GetTable %{public}s not exist", key.c_str());
        return ERR_DB_NOT_EXIST;
    }
    result.clear();
    DistributedDB::KvStoreResultSet *resultSet = nullptr;
    Key emptyKey;
    LOG_DEBUG("start GetEntries");
    auto delegate = delegates_.at(key);
    DistributedDB::DBStatus status = delegate->GetEntries(emptyKey, resultSet);
    if (status != DistributedDB::DBStatus::OK || resultSet == nullptr) {
        LOG_INFO("FlatObjectStorageEngine::GetTable %{public}s GetEntries fail", key.c_str());
        return ERR_DB_GET_FAIL;
    }
    LOG_DEBUG("end GetEntries");
    while (resultSet->IsAfterLast()) {
        DistributedDB::Entry entry;
        status = resultSet->GetEntry(entry);
        if (status != DistributedDB::DBStatus::OK) {
            LOG_INFO("FlatObjectStorageEngine::GetTable GetEntry fail, errcode = %{public}d", status);
            status = delegate->CloseResultSet(resultSet);
            if (status != DistributedDB::DBStatus::OK) {
                LOG_INFO("KvStoreNbDelegate::CloseResultSet fail, errcode = %{public}d", status);
                return ERR_RESULTSET;
            }
            return ERR_DB_ENTRY_FAIL;
        }
        result.insert_or_assign(StringUtils::BytesToStr(entry.key), entry.value);
        resultSet->MoveToNext();
    }
    status = delegate->CloseResultSet(resultSet);
    if (status != DistributedDB::DBStatus::OK) {
        LOG_INFO("KvStoreNbDelegate::CloseResultSet fail, errcode = %{public}d", status);
        return ERR_RESULTSET;
    }
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::UpdateItem(const std::string &key, const std::string &itemKey, Value &value)
{
    if (!isOpened_) {
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(key) == 0) {
        LOG_INFO("FlatObjectStorageEngine::GetTable %{public}s not exist", key.c_str());
        return ERR_DB_NOT_EXIST;
    }
    auto delegate = delegates_.at(key);
    LOG_DEBUG("start Put");
    auto status = delegate->Put(StringUtils::StrToBytes(itemKey), value);
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR("%{public}s Put fail[%{public}d]", key.c_str(), status);
        return ERR_CLOSE_STORAGE;
    }
    LOG_DEBUG("put success");
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::UpdateItems(
    const std::string &key, const std::map<std::string, std::vector<uint8_t>> &data)
{
    if (!isOpened_ || data.size() == 0) {
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(key) == 0) {
        LOG_INFO("FlatObjectStorageEngine::UpdateItems %{public}s not exist", key.c_str());
        return ERR_DB_NOT_EXIST;
    }

    std::vector<DistributedDB::Entry> entries;
    for (auto &item : data) {
        DistributedDB::Entry entry = { .key = StringUtils::StrToBytes(item.first), .value = item.second };
        entries.emplace_back(entry);
    }
    auto delegate = delegates_.at(key);
    LOG_DEBUG("start PutBatch");
    auto status = delegate->PutBatch(entries);
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR("%{public}s PutBatch fail[%{public}d]", key.c_str(), status);
        return ERR_CLOSE_STORAGE;
    }
    LOG_DEBUG("put success");
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::DeleteTable(const std::string &key)
{
    if (!isOpened_) {
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(key) == 0) {
        LOG_INFO("FlatObjectStorageEngine::GetTable %{public}s not exist", key.c_str());
        return ERR_DB_NOT_EXIST;
    }
    LOG_DEBUG("start DeleteTable %{public}s", key.c_str());
    auto status = storeManager_->CloseKvStore(delegates_.at(key));
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR(
            "FlatObjectStorageEngine::CloseKvStore %{public}s CloseKvStore fail[%{public}d]", key.c_str(), status);
        return ERR_CLOSE_STORAGE;
    }
    LOG_DEBUG("DeleteTable success");
    delegates_.erase(key);
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::GetItem(const std::string &key, const std::string &itemKey, Value &value)
{
    if (!isOpened_) {
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(key) == 0) {
        LOG_ERROR("FlatObjectStorageEngine::GetItem %{public}s not exist", key.c_str());
        return ERR_DB_NOT_EXIST;
    }
    LOG_DEBUG("start Get %{public}s", key.c_str());
    DistributedDB::DBStatus status = delegates_.at(key)->Get(StringUtils::StrToBytes(itemKey), value);
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR("FlatObjectStorageEngine::GetItem %{public}s item fail %{public}d", itemKey.c_str(), status);
        return status;
    }
    LOG_DEBUG("end Get %{public}s", key.c_str());
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::RegisterObserver(const std::string &key, std::shared_ptr<TableWatcher> watcher)
{
    if (!isOpened_) {
        LOG_ERROR("FlatObjectStorageEngine::RegisterObserver kvStore has not init");
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(key) == 0) {
        LOG_INFO("FlatObjectStorageEngine::RegisterObserver %{public}s not exist", key.c_str());
        return ERR_DB_NOT_EXIST;
    }
    if (observerMap_.count(key) != 0) {
        LOG_INFO("FlatObjectStorageEngine::RegisterObserver observer already exist.");
        return SUCCESS;
    }
    auto delegate = delegates_.at(key);
    std::vector<uint8_t> tmpKey;
    LOG_DEBUG("start RegisterObserver %{public}s", key.c_str());
    DistributedDB::DBStatus status =
        delegate->RegisterObserver(tmpKey, DistributedDB::ObserverMode::OBSERVER_CHANGES_FOREIGN, watcher.get());
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR("FlatObjectStorageEngine::RegisterObserver watch err %{public}d", status);
        return ERR_REGISTER;
    }
    LOG_DEBUG("end RegisterObserver %{public}s", key.c_str());
    observerMap_.insert_or_assign(key, watcher);
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::UnRegisterObserver(const std::string &key)
{
    if (!isOpened_) {
        LOG_ERROR("FlatObjectStorageEngine::RegisterObserver kvStore has not init");
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(key) == 0) {
        LOG_INFO("FlatObjectStorageEngine::RegisterObserver %{public}s not exist", key.c_str());
        return ERR_DB_NOT_EXIST;
    }
    auto iter = observerMap_.find(key);
    if (iter == observerMap_.end()) {
        LOG_ERROR("FlatObjectStorageEngine::UnRegisterObserver observer not exist.");
        return ERR_NO_OBSERVER;
    }
    auto delegate = delegates_.at(key);
    std::shared_ptr<TableWatcher> watcher = iter->second;
    LOG_DEBUG("start UnRegisterObserver %{public}s", key.c_str());
    DistributedDB::DBStatus status = delegate->UnRegisterObserver(watcher.get());
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR("FlatObjectStorageEngine::UnRegisterObserver unRegister err %{public}d", status);
        return ERR_UNRIGSTER;
    }
    LOG_DEBUG("end UnRegisterObserver %{public}s", key.c_str());
    observerMap_.erase(key);
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::SetStatusNotifier(std::shared_ptr<StatusWatcher> watcher)
{
    if (!isOpened_) {
        LOG_ERROR("FlatObjectStorageEngine::SetStatusNotifier kvStore has not init");
        return ERR_DB_NOT_INIT;
    }
    auto databaseStatusNotifyCallback = [this](std::string userId, std::string appId, std::string storeId,
                                            const std::string deviceId, bool onlineStatus) -> void {
        std::lock_guard<std::mutex> lock(watcherMutex_);
        LOG_INFO("complete");
        if (statusWatcher_ == nullptr) {
            LOG_INFO("FlatObjectStorageEngine::statusWatcher_ null");
            return;
        }
        if (onlineStatus) {
            auto onComplete = [this, storeId](const std::map<std::string, DistributedDB::DBStatus> &devices) {
                for (auto item : devices) {
                    LOG_INFO("%{public}s pull data result %{public}d in device %{public}s",
                        Anonymous::Change(storeId).c_str(), item.second,
                        Anonymous::Change(SoftBusAdapter::GetInstance()->ToNodeID(item.first)).c_str());
                }
                if (statusWatcher_ != nullptr) {
                    for (auto item : devices) {
                        statusWatcher_->OnChanged(storeId, SoftBusAdapter::GetInstance()->ToNodeID(item.first),
                            item.second == DistributedDB::OK ? "online" : "offline");
                    }
                }
            };
            SyncAllData(storeId, std::vector<std::string>({ deviceId }), onComplete);
        } else {
            statusWatcher_->OnChanged(storeId, SoftBusAdapter::GetInstance()->ToNodeID(deviceId), "offline");
        }
    };
    storeManager_->SetStoreStatusNotifier(databaseStatusNotifyCallback);
    LOG_INFO("FlatObjectStorageEngine::SetStatusNotifier success");
    std::lock_guard<std::mutex> lock(watcherMutex_);
    statusWatcher_ = watcher;
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::SetProgressNotifier(std::shared_ptr<ProgressWatcher> watcher)
{
    if (!isOpened_) {
        LOG_ERROR("FlatObjectStorageEngine::SetProgressNotifier has not init");
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(progressMutex_);
    progressWatcher_ = watcher;
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::SyncAllData(const std::string &sessionId, const std::vector<std::string> &deviceIds,
    const std::function<void(const std::map<std::string, DistributedDB::DBStatus> &)> &onComplete)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(sessionId) == 0) {
        LOG_ERROR("%{public}s already deleted", Anonymous::Change(sessionId).c_str());
        return ERR_DB_NOT_EXIST;
    }
    DistributedDB::KvStoreNbDelegate *kvstore = delegates_.at(sessionId);
    if (deviceIds.empty()) {
        LOG_INFO("single device,no need sync");
        return ERR_SINGLE_DEVICE;
    }
    LOG_INFO("start sync %{public}s", Anonymous::Change(sessionId).c_str());
    DistributedDB::DBStatus status = kvstore->Sync(deviceIds, DistributedDB::SyncMode::SYNC_MODE_PULL_ONLY, onComplete);
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR("FlatObjectStorageEngine::UnRegisterObserver unRegister err %{public}d", status);
        return ERR_UNRIGSTER;
    }
    LOG_INFO("end sync %{public}s", Anonymous::Change(sessionId).c_str());
    return SUCCESS;
}

uint32_t FlatObjectStorageEngine::GetItems(const std::string &key, std::map<std::string, std::vector<uint8_t>> &data)
{
    if (!isOpened_) {
        LOG_ERROR("GetItems %{public}s not init", Anonymous::Change(key).c_str());
        return ERR_DB_NOT_INIT;
    }
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (delegates_.count(key) == 0) {
        LOG_ERROR("GetItems %{public}s not exist", Anonymous::Change(key).c_str());
        return ERR_DB_NOT_EXIST;
    }
    LOG_INFO("start Get %{public}s", Anonymous::Change(key).c_str());
    std::vector<DistributedDB::Entry> entries;
    DistributedDB::DBStatus status = delegates_.at(key)->GetEntries(StringUtils::StrToBytes(""), entries);
    if (status != DistributedDB::DBStatus::OK) {
        LOG_ERROR("FlatObjectStorageEngine::GetItems item fail status = %{public}d", status);
        return status;
    }
    for (auto &item : entries) {
        data[StringUtils::BytesToStr(item.key)] = item.value;
    }
    LOG_INFO("end Get %{public}s", Anonymous::Change(key).c_str());
    return SUCCESS;
}

void FlatObjectStorageEngine::NotifyStatus(const std::string &sessionId, const std::string &deviceId,
                                           const std::string &status)
{
    std::lock_guard<std::mutex> lock(watcherMutex_);
    if (statusWatcher_ == nullptr) {
        return;
    }
    statusWatcher_->OnChanged(sessionId, deviceId, status);
}

bool FlatObjectStorageEngine::NotifyProgress(const std::string &sessionId, int32_t progress)
{
    std::lock_guard<std::mutex> lock(progressMutex_);
    if (progressWatcher_ == nullptr) {
        return false;
    }
    progressWatcher_->OnChanged(sessionId, progress);
    return true;
}

void FlatObjectStorageEngine::NotifyChange(
    const std::string &sessionId, const std::map<std::string, std::vector<uint8_t>> &changedData)
{
    std::lock_guard<std::mutex> lock(operationMutex_);
    if (observerMap_.count(sessionId) == 0) {
        return;
    }
    std::vector<std::string> data {};
    for (const auto &item : changedData) {
        std::string key = item.first;
        if (key.compare(0, FIELDS_PREFIX_LEN, FIELDS_PREFIX) == 0) {
            key = key.substr(FIELDS_PREFIX_LEN);
        }
        data.push_back(key);
    }
    observerMap_[sessionId]->OnChanged(sessionId, data, false);
}

void Watcher::OnChange(const DistributedDB::KvStoreChangedData &data)
{
    std::vector<std::string> changedData;
    std::string tmp;
    for (DistributedDB::Entry item : data.GetEntriesInserted()) {
        tmp = StringUtils::BytesToStr(item.key);
        LOG_INFO("inserted %{public}s", tmp.c_str());
        // property key start with p_, 2 is p_ size
        if (tmp.compare(0, FIELDS_PREFIX_LEN, FIELDS_PREFIX) == 0) {
            changedData.push_back(tmp.substr(FIELDS_PREFIX_LEN));
        }
    }
    for (DistributedDB::Entry item : data.GetEntriesUpdated()) {
        tmp = StringUtils::BytesToStr(item.key);
        LOG_INFO("updated %{public}s", tmp.c_str());
        // property key start with p_, 2 is p_ size
        if (tmp.compare(0, FIELDS_PREFIX_LEN, FIELDS_PREFIX) == 0) {
            changedData.push_back(tmp.substr(FIELDS_PREFIX_LEN));
        }
    }
    this->OnChanged(sessionId_, changedData, true);
}

Watcher::Watcher(const std::string &sessionId) : sessionId_(sessionId)
{
}
} // namespace OHOS::ObjectStore
