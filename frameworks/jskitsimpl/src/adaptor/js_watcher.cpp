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

#include "anonymous.h"
#include "js_common.h"
#include "js_util.h"
#include "logger.h"
#include "notifier_impl.h"
#include "objectstore_errors.h"
#include "progress_notifier_impl.h"

namespace OHOS::ObjectStore {
JSWatcher::JSWatcher(const napi_env env, DistributedObjectStore *objectStore, DistributedObject *object)
    : UvQueue(env), env_(env), changeEventListener_(nullptr), statusEventListener_(nullptr),
      progressEventListener_(nullptr)
{
}

JSWatcher::~JSWatcher()
{
    delete changeEventListener_;
    delete statusEventListener_;
    delete progressEventListener_;
    changeEventListener_ = nullptr;
    statusEventListener_ = nullptr;
    progressEventListener_ = nullptr;
}

bool JSWatcher::On(const char *type, napi_value handler)
{
    EventListener *listener = Find(type);
    if (listener == nullptr) {
        LOG_ERROR("error type %{public}s", type);
        return false;
    }
    return listener->Add(env_, handler);
}

void JSWatcher::Off(const char *type, napi_value handler)
{
    EventListener *listener = Find(type);
    if (listener == nullptr) {
        LOG_ERROR("error type %{public}s", type);
        return;
    }
    if (handler == nullptr) {
        listener->Clear(env_);
    } else {
        listener->Del(env_, handler);
    }
}
void JSWatcher::ProcessChange(napi_env env, std::list<void *> &args)
{
    constexpr static int8_t ARGV_SIZE = 2;
    napi_value callback = nullptr;
    napi_value global = nullptr;
    napi_value param[ARGV_SIZE];
    napi_value result;
    napi_status status = napi_get_global(env, &global);
    NOT_MATCH_GOTO_ERROR(status == napi_ok);
    for (auto item : args) {
        ChangeArgs *changeArgs = static_cast<ChangeArgs *>(item);
        status = napi_get_reference_value(env, changeArgs->callback_, &callback);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        status = JSUtil::SetValue(env, changeArgs->sessionId_, param[0]);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        JSUtil::SetValue(env, changeArgs->changeData_, param[1]);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        LOG_INFO("start %{public}s, %{public}zu", Anonymous::Change(changeArgs->sessionId_).c_str(),
            changeArgs->changeData_.size());
        status = napi_call_function(env, global, callback, ARGV_SIZE, param, &result);
        LOG_INFO("end %{public}3s, %{public}zu", Anonymous::Change(changeArgs->sessionId_).c_str(),
            changeArgs->changeData_.size());
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
    }
ERROR:
    for (auto item : args) {
        ChangeArgs *changeArgs = static_cast<ChangeArgs *>(item);
        delete changeArgs;
    }
    args.clear();
}
void JSWatcher::Emit(const char *type, const std::string &sessionId, const std::vector<std::string> &changeData)
{
    if (changeData.empty()) {
        LOG_ERROR("empty change");
        return;
    }
    LOG_INFO("start %{public}3s, %{public}s", Anonymous::Change(sessionId).c_str(), changeData.at(0).c_str());
    EventListener *listener = Find(type);
    if (listener == nullptr) {
        LOG_ERROR("error type %{public}s", type);
        return;
    }

    for (EventHandler *handler = listener->handlers_; handler != nullptr; handler = handler->next) {
        ChangeArgs *changeArgs = new (std::nothrow) ChangeArgs(handler->callbackRef, sessionId, changeData);
        if (changeArgs == nullptr) {
            LOG_ERROR("JSWatcher::Emit no memory for changeArgs malloc!");
            return;
        }
        CallFunction(ProcessChange, changeArgs);
    }
}

EventListener *JSWatcher::Find(const char *type)
{
    if (!strcmp(Constants::CHANGE, type)) {
        return changeEventListener_;
    }
    if (!strcmp(Constants::STATUS, type)) {
        return statusEventListener_;
    }
    if (!strcmp(Constants::PROGRESS, type)) {
        return progressEventListener_;
    }
    return nullptr;
}

void JSWatcher::ProcessStatus(napi_env env, std::list<void *> &args)
{
    constexpr static int8_t ARGV_SIZE = 3;
    napi_value callback = nullptr;
    napi_value global = nullptr;
    napi_value param[ARGV_SIZE];
    napi_value result;
    napi_status status = napi_get_global(env, &global);
    NOT_MATCH_GOTO_ERROR(status == napi_ok);
    for (auto item : args) {
        StatusArgs *statusArgs = static_cast<StatusArgs *>(item);
        status = napi_get_reference_value(env, statusArgs->callback_, &callback);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        status = JSUtil::SetValue(env, statusArgs->sessionId_, param[0]);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        status = JSUtil::SetValue(env, statusArgs->networkId_, param[1]);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        status = JSUtil::SetValue(env, statusArgs->status_, param[2]);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        LOG_INFO("start %{public}s, %{public}s, %{public}s", Anonymous::Change(statusArgs->sessionId_).c_str(),
            Anonymous::Change(statusArgs->networkId_).c_str(), statusArgs->status_.c_str());
        status = napi_call_function(env, global, callback, ARGV_SIZE, param, &result);
        LOG_INFO("end %{public}s, %{public}s, %{public}s", Anonymous::Change(statusArgs->sessionId_).c_str(),
            Anonymous::Change(statusArgs->networkId_).c_str(), statusArgs->status_.c_str());
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
    }
ERROR:
    LOG_DEBUG("do clear");
    for (auto item : args) {
        StatusArgs *statusArgs = static_cast<StatusArgs *>(item);
        delete statusArgs;
    }
    args.clear();
}

void JSWatcher::Emit(
    const char *type, const std::string &sessionId, const std::string &networkId, const std::string &status)
{
    if (sessionId.empty() || networkId.empty()) {
        LOG_ERROR("empty %{public}s  %{public}s", Anonymous::Change(sessionId).c_str(),
            Anonymous::Change(networkId).c_str());
        return;
    }
    LOG_INFO("status change %{public}s  %{public}s", Anonymous::Change(sessionId).c_str(),
        Anonymous::Change(networkId).c_str());
    EventListener *listener = Find(type);
    if (listener == nullptr) {
        LOG_ERROR("error type %{public}s", type);
        return;
    }

    for (EventHandler *handler = listener->handlers_; handler != nullptr; handler = handler->next) {
        StatusArgs *changeArgs = new (std::nothrow) StatusArgs(handler->callbackRef, sessionId, networkId, status);
        if (changeArgs == nullptr) {
            LOG_ERROR("JSWatcher::Emit no memory for StatusArgs malloc!");
            return;
        }
        CallFunction(ProcessStatus, changeArgs);
    }
    return;
}

void JSWatcher::ProcessProgress(napi_env env, std::list<void *> &args)
{
    constexpr static int8_t ARGV_SIZE = 2;
    napi_value callback = nullptr;
    napi_value global = nullptr;
    napi_value param[ARGV_SIZE];
    napi_value result;
    napi_status status = napi_get_global(env, &global);
    NOT_MATCH_GOTO_ERROR(status == napi_ok);
    for (auto item : args) {
        ProgressArgs *progressArgs = static_cast<ProgressArgs *>(item);
        status = napi_get_reference_value(env, progressArgs->callback_, &callback);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        status = JSUtil::SetValue(env, progressArgs->sessionId_, param[0]);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        status = JSUtil::SetValue(env, static_cast<uint32_t>(progressArgs->progress_), param[1]);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
        LOG_INFO("start %{public}s, %{public}d", Anonymous::Change(progressArgs->sessionId_).c_str(),
            progressArgs->progress_);
        status = napi_call_function(env, global, callback, ARGV_SIZE, param, &result);
        LOG_INFO("end %{public}s, %{public}d", Anonymous::Change(progressArgs->sessionId_).c_str(),
            progressArgs->progress_);
        NOT_MATCH_GOTO_ERROR(status == napi_ok);
    }
ERROR:
    LOG_DEBUG("do clear");
    for (auto item : args) {
        ProgressArgs *progressArgs = static_cast<ProgressArgs *>(item);
        delete progressArgs;
    }
    args.clear();
}

void JSWatcher::Emit(const char *type, const std::string &sessionId, int32_t progress)
{
    if (sessionId.empty()) {
        LOG_ERROR("empty sessionId %{public}s", Anonymous::Change(sessionId).c_str());
        return;
    }
    LOG_INFO("progress change %{public}s %{public}d", Anonymous::Change(sessionId).c_str(), progress);
    EventListener *listener = Find(type);
    if (listener == nullptr) {
        LOG_ERROR("error type %{public}s", type);
        return;
    }

    for (EventHandler *handler = listener->handlers_; handler != nullptr; handler = handler->next) {
        ProgressArgs *progressArgs = new (std::nothrow) ProgressArgs(handler->callbackRef, sessionId, progress);
        if (progressArgs == nullptr) {
            LOG_ERROR("JSWatcher::Emit no memory for ProgressArgs malloc!");
            return;
        }
        CallFunction(ProcessProgress, progressArgs);
    }
    return;
}

bool JSWatcher::IsEmpty()
{
    if (changeEventListener_->IsEmpty() && statusEventListener_->IsEmpty() && progressEventListener_->IsEmpty()) {
        return true;
    }
    return false;
}

void JSWatcher::SetListener(ChangeEventListener *changeEventListener, StatusEventListener *statusEventListener,
    ProgressEventListener *progressEventListener)
{
    changeEventListener_ = changeEventListener;
    statusEventListener_ = statusEventListener;
    progressEventListener_ = progressEventListener;
}

EventHandler *EventListener::Find(napi_env env, napi_value handler)
{
    EventHandler *result = nullptr;
    for (EventHandler *i = handlers_; i != nullptr; i = i->next) {
        napi_value callback = nullptr;
        napi_get_reference_value(env, i->callbackRef, &callback);
        bool isEquals = false;
        napi_strict_equals(env, handler, callback, &isEquals);
        if (isEquals) {
            result = i;
        }
    }
    return result;
}

void EventListener::Clear(napi_env env)
{
    for (EventHandler *i = handlers_; i != nullptr; i = handlers_) {
        handlers_ = i->next;
        napi_delete_reference(env, i->callbackRef);
        delete i;
    }
}

bool EventListener::Del(napi_env env, napi_value handler)
{
    EventHandler *temp = nullptr;
    napi_status status;
    for (EventHandler *i = handlers_; i != nullptr;) {
        napi_value callback = nullptr;
        status = napi_get_reference_value(env, i->callbackRef, &callback);
        if (status != napi_ok) {
            LOG_ERROR("error! %{public}d", status);
            return false;
        }
        bool isEquals = false;
        napi_strict_equals(env, handler, callback, &isEquals);
        if (isEquals) {
            EventHandler *delData = i;
            i = i->next;
            if (temp == nullptr) {
                handlers_ = delData->next;
            } else {
                temp->next = delData->next;
            }
            napi_delete_reference(env, delData->callbackRef);
            delete delData;
        } else {
            temp = i;
            i = i->next;
        }
    }
    return handlers_ == nullptr;
}

bool EventListener::Add(napi_env env, napi_value handler)
{
    if (Find(env, handler) != nullptr) {
        LOG_ERROR("has added,return");
        return false;
    }

    if (handlers_ == nullptr) {
        handlers_ = new (std::nothrow) EventHandler();
        if (handlers_ == nullptr) {
            LOG_ERROR("EventListener::Add no memory for EventHandler malloc!");
            return false;
        }
        handlers_->next = nullptr;
    } else {
        auto temp = new (std::nothrow) EventHandler();
        if (temp == nullptr) {
            LOG_ERROR("EventListener::Add no memory for EventHandler malloc!");
            return false;
        }
        temp->next = handlers_;
        handlers_ = temp;
    }
    napi_create_reference(env, handler, 1, &handlers_->callbackRef);
    return true;
}

void WatcherImpl::OnChanged(const std::string &sessionid, const std::vector<std::string> &changedData)
{
    std::shared_ptr<JSWatcher> lockedWatcher = watcher_.lock();
    if (lockedWatcher) {
        lockedWatcher->Emit(Constants::CHANGE, sessionid, changedData);
    } else {
        LOG_ERROR("watcher expired");
    }
}

WatcherImpl::~WatcherImpl()
{
    LOG_ERROR("destroy");
}

bool ChangeEventListener::Add(napi_env env, napi_value handler)
{
    if (!isWatched_ && object_ != nullptr) {
        std::shared_ptr<WatcherImpl> watcher = std::make_shared<WatcherImpl>(watcher_);
        uint32_t ret = objectStore_->Watch(object_, watcher);
        if (ret != SUCCESS) {
            LOG_ERROR("Watch %{public}s error", Anonymous::Change(object_->GetSessionId()).c_str());
        } else {
            LOG_INFO("Watch %{public}s success", Anonymous::Change(object_->GetSessionId()).c_str());
            isWatched_ = true;
        }
    }
    return EventListener::Add(env, handler);
}

bool ChangeEventListener::Del(napi_env env, napi_value handler)
{
    bool isEmpty = EventListener::Del(env, handler);
    if (isEmpty && isWatched_ && object_ != nullptr) {
        uint32_t ret = objectStore_->UnWatch(object_);
        if (ret != SUCCESS) {
            LOG_ERROR("UnWatch %{public}s error", Anonymous::Change(object_->GetSessionId()).c_str());
        } else {
            LOG_INFO("UnWatch %{public}s success", Anonymous::Change(object_->GetSessionId()).c_str());
            isWatched_ = false;
        }
    }
    return isEmpty;
}

void ChangeEventListener::Clear(napi_env env)
{
    EventListener::Clear(env);
    if (isWatched_ && object_ != nullptr) {
        uint32_t ret = objectStore_->UnWatch(object_);
        if (ret != SUCCESS) {
            LOG_ERROR("UnWatch %{public}s error", Anonymous::Change(object_->GetSessionId()).c_str());
        } else {
            LOG_INFO("UnWatch %{public}s success", Anonymous::Change(object_->GetSessionId()).c_str());
            isWatched_ = false;
        }
    }
}

ChangeEventListener::ChangeEventListener(
    std::weak_ptr<JSWatcher> watcher, DistributedObjectStore *objectStore, DistributedObject *object)
    : objectStore_(objectStore), object_(object), watcher_(watcher)
{
}

bool StatusEventListener::Add(napi_env env, napi_value handler)
{
    LOG_INFO("Add status watch %{public}s", Anonymous::Change(sessionId_).c_str());
    NotifierImpl::GetInstance()->AddWatcher(sessionId_, watcher_);
    return EventListener::Add(env, handler);
}

bool StatusEventListener::Del(napi_env env, napi_value handler)
{
    if (EventListener::Del(env, handler)) {
        LOG_INFO("Del status watch %{public}s", Anonymous::Change(sessionId_).c_str());
        NotifierImpl::GetInstance()->DelWatcher(sessionId_);
        return true;
    }
    return false;
}

void StatusEventListener::Clear(napi_env env)
{
    NotifierImpl::GetInstance()->DelWatcher(sessionId_);
    EventListener::Clear(env);
}

StatusEventListener::StatusEventListener(std::weak_ptr<JSWatcher> watcher, const std::string &sessionId)
    : watcher_(watcher), sessionId_(sessionId)
{
}

bool ProgressEventListener::Add(napi_env env, napi_value handler)
{
    LOG_INFO("Add progress watch %{public}s", Anonymous::Change(sessionId_).c_str());
    ProgressNotifierImpl::GetInstance()->AddWatcher(sessionId_, watcher_);
    return EventListener::Add(env, handler);
}

bool ProgressEventListener::Del(napi_env env, napi_value handler)
{
    if (EventListener::Del(env, handler)) {
        LOG_INFO("Del progress watch %{public}s", Anonymous::Change(sessionId_).c_str());
        ProgressNotifierImpl::GetInstance()->DelWatcher(sessionId_);
        return true;
    }
    return false;
}

void ProgressEventListener::Clear(napi_env env)
{
    ProgressNotifierImpl::GetInstance()->DelWatcher(sessionId_);
    EventListener::Clear(env);
}

ProgressEventListener::ProgressEventListener(std::weak_ptr<JSWatcher> watcher, const std::string &sessionId)
    : watcher_(watcher), sessionId_(sessionId)
{
}

JSWatcher::ChangeArgs::ChangeArgs(
    const napi_ref callback, const std::string &sessionId, const std::vector<std::string> &changeData)
    : callback_(callback), sessionId_(sessionId), changeData_(changeData)
{
}

JSWatcher::StatusArgs::StatusArgs(
    const napi_ref callback, const std::string &sessionId, const std::string &networkId, const std::string &status)
    : callback_(callback), sessionId_(sessionId), networkId_(networkId), status_(status)
{
}

JSWatcher::ProgressArgs::ProgressArgs(const napi_ref callback, const std::string &sessionId, int32_t progress)
    : callback_(callback), sessionId_(sessionId), progress_(progress)
{
}
} // namespace OHOS::ObjectStore
