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

#include "js_distributedobjectstore.h"

#include <cstring>

#include "ability_context.h"
#include "distributed_objectstore.h"
#include "js_common.h"
#include "js_distributedobject.h"
#include "js_object_wrapper.h"
#include "js_util.h"
#include "logger.h"
#include "objectstore_errors.h"

namespace OHOS::ObjectStore {
constexpr size_t TYPE_SIZE = 10;
static std::map<std::string, std::list<napi_ref>> g_statusCallBacks;
static std::map<std::string, std::list<napi_ref>> g_changeCallBacks;
void JSDistributedObjectStore::AddCallback(napi_env env, std::map<std::string, std::list<napi_ref>> &callbacks,
    const std::string &sessionId, napi_value callback)
{
    LOG_INFO("add callback %{public}s %{public}p", sessionId.c_str(), callback);
    napi_ref ref = nullptr;
    napi_status status = napi_create_reference(env, callback, 1, &ref);
    CHECK_EQUAL_WITH_RETURN_VOID(status, napi_ok);
    if (callbacks.count(sessionId) != 0) {
        auto lists = callbacks.at(sessionId);
        lists.push_back(ref);
        callbacks.insert_or_assign(sessionId, lists);
    } else {
        std::list<napi_ref> lists = { ref };
        callbacks.insert_or_assign(sessionId, lists);
    }
}
void JSDistributedObjectStore::DelCallback(napi_env env, std::map<std::string, std::list<napi_ref>> &callbacks,
    const std::string &sessionId, napi_value callback)
{
    LOG_INFO("del callback %{public}s %{public}p", sessionId.c_str(), callback);
    napi_status status;
    if (callback == nullptr) {
        if (callbacks.count(sessionId) != 0) {
            for (auto ref : callbacks.at(sessionId)) {
                status = napi_delete_reference(env, ref);
                CHECK_EQUAL_WITH_RETURN_VOID(status, napi_ok);
            }
            callbacks.erase(sessionId);
        }
        return;
    }
    napi_value callbackTmp;
    if (callbacks.count(sessionId) != 0) {
        auto lists = callbacks.at(sessionId);
        for (auto iter = lists.begin(); iter != lists.end();) {
            status = napi_get_reference_value(env, *iter, &callbackTmp);
            CHECK_EQUAL_WITH_RETURN_VOID(status, napi_ok);
            bool isEquals = false;
            napi_strict_equals(env, callbackTmp, callback, &isEquals);
            if (isEquals) {
                napi_delete_reference(env, *iter);
                iter = lists.erase(iter);
            } else {
                iter++;
            }
        }
        if (lists.empty()) {
            callbacks.erase(sessionId);
        } else {
            callbacks.insert_or_assign(sessionId, lists);
        }
    }
}
napi_value JSDistributedObjectStore::NewDistributedObject(
    napi_env env, DistributedObjectStore *objectStore, DistributedObject *object)
{
    napi_value result;
    napi_status status = napi_new_instance(env, JSDistributedObject::GetCons(env), 0, nullptr, &result);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    JSObjectWrapper *objectWrapper = new JSObjectWrapper(objectStore, object);
    status = napi_wrap(
        env, result, objectWrapper,
        [](napi_env env, void *data, void *hint) {
            auto objectWrapper = (JSObjectWrapper *)data;
            if (objectWrapper != nullptr) {
                delete objectWrapper;
            }
        },
        nullptr, nullptr);
    RestoreWatchers(env, objectWrapper);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    return result;
}

// function createObjectSync(sessionId: string): DistributedObject;
napi_value JSDistributedObjectStore::JSCreateObjectSync(napi_env env, napi_callback_info info)
{
    LOG_INFO("start JSCreateObjectSync");
    size_t requireArgc = 1;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    std::string sessionId;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(argc >= requireArgc);
    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, argv[0], &valueType);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    CHECK_EQUAL_WITH_RETURN_NULL(valueType, napi_string)
    status = JSUtil::GetValue(env, argv[0], sessionId);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    DistributedObjectStore *objectInfo =
        DistributedObjectStore::GetInstance(JSDistributedObjectStore::GetBundleName(env));
    ASSERT_MATCH_ELSE_RETURN_NULL(objectInfo != nullptr);
    DistributedObject *object = objectInfo->CreateObject(sessionId);
    ASSERT_MATCH_ELSE_RETURN_NULL(object != nullptr);
    return NewDistributedObject(env, objectInfo, object);
}

// function destroyObjectSync(object: DistributedObject): number;
napi_value JSDistributedObjectStore::JSDestroyObjectSync(napi_env env, napi_callback_info info)
{
    LOG_INFO("start");
    size_t requireArgc = 1;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    std::string sessionId;
    std::string bundleName;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(argc >= requireArgc);

    JSObjectWrapper *objectWrapper = nullptr;
    status = napi_unwrap(env, argv[0], (void **)&objectWrapper);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(objectWrapper != nullptr);
    DistributedObjectStore *objectInfo =
        DistributedObjectStore::GetInstance(JSDistributedObjectStore::GetBundleName(env));
    ASSERT_MATCH_ELSE_RETURN_NULL(objectInfo != nullptr && objectWrapper->GetObject() != nullptr);
    objectWrapper->DeleteWatch(env, CHANGE);
    objectWrapper->DeleteWatch(env, STATUS);
    uint32_t ret = objectInfo->DeleteObject(objectWrapper->GetObject()->GetSessionId());
    napi_value result = nullptr;
    napi_create_int32(env, ret, &result);
    return result;
}

// function on(type: 'change', object: DistributedObject, callback: Callback<ChangedDataObserver>): void;
// function on(type: 'status', object: DistributedObject, callback: Callback<ObjectStatusObserver>): void;
napi_value JSDistributedObjectStore::JSOn(napi_env env, napi_callback_info info)
{
    LOG_INFO("start");
    size_t requireArgc = 3;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(argc >= requireArgc);

    char type[TYPE_SIZE] = { 0 };
    size_t eventTypeLen = 0;
    napi_valuetype eventValueType = napi_undefined;
    status = napi_typeof(env, argv[0], &eventValueType);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(eventValueType == napi_string);
    status = napi_get_value_string_utf8(env, argv[0], type, TYPE_SIZE, &eventTypeLen);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);

    napi_valuetype objectType = napi_undefined;
    status = napi_typeof(env, argv[1], &objectType);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(objectType == napi_object);

    napi_valuetype callbackType = napi_undefined;
    status = napi_typeof(env, argv[2], &callbackType);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(callbackType == napi_function);

    JSObjectWrapper *wrapper = nullptr;
    status = napi_unwrap(env, argv[1], (void **)&wrapper);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(wrapper != nullptr);
    if (wrapper->AddWatch(env, type, argv[2])) {
        if (!strcmp(CHANGE, type)) {
            AddCallback(env, g_changeCallBacks, wrapper->GetObject()->GetSessionId(), argv[2]);
        } else if (!strcmp(STATUS, type)) {
            AddCallback(env, g_statusCallBacks, wrapper->GetObject()->GetSessionId(), argv[2]);
        }
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

// function off(type: 'change', object: DistributedObject, callback?: Callback<ChangedDataObserver>): void;
// function off(type: 'status', object: DistributedObject, callback?: Callback<ObjectStatusObserver>): void;
napi_value JSDistributedObjectStore::JSOff(napi_env env, napi_callback_info info)
{
    LOG_INFO("start");
    size_t requireArgc = 2;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    char type[TYPE_SIZE] = { 0 };
    size_t typeLen = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(argc >= requireArgc);
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        status = napi_typeof(env, argv[i], &valueType);
        CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);

        if (i == 0 && valueType == napi_string) {
            status = napi_get_value_string_utf8(env, argv[i], type, TYPE_SIZE, &typeLen);
            CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
        } else if (i == 1 && valueType == napi_object) {
            continue;
        } else if (i == 2 && (valueType == napi_function || valueType == napi_undefined)) {
            continue;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    JSObjectWrapper *wrapper = nullptr;
    status = napi_unwrap(env, argv[1], (void **)&wrapper);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    ASSERT_MATCH_ELSE_RETURN_NULL(wrapper != nullptr);
    if (argc == requireArgc) {
        LOG_INFO("delete all");
        wrapper->DeleteWatch(env, type);
        if (!strcmp(CHANGE, type)) {
            DelCallback(env, g_changeCallBacks, wrapper->GetObject()->GetSessionId());
        } else if (!strcmp(STATUS, type)) {
            DelCallback(env, g_statusCallBacks, wrapper->GetObject()->GetSessionId());
        }
    } else {
        LOG_INFO("delete %{public}p", argv[2]);
        wrapper->DeleteWatch(env, type, argv[2]);
        if (!strcmp(CHANGE, type)) {
            DelCallback(env, g_changeCallBacks, wrapper->GetObject()->GetSessionId(), argv[2]);
        } else if (!strcmp(STATUS, type)) {
            DelCallback(env, g_statusCallBacks, wrapper->GetObject()->GetSessionId(), argv[2]);
        }
    }

    napi_value result = nullptr;
    status = napi_get_undefined(env, &result);
    CHECK_EQUAL_WITH_RETURN_NULL(status, napi_ok);
    return result;
}

std::string JSDistributedObjectStore::GetBundleName(napi_env env)
{
    static std::string bundleName;
    if (bundleName.empty()) {
        bundleName = AbilityRuntime::Context::GetApplicationContext()->GetBundleName();
    }
    return bundleName;
}

void JSDistributedObjectStore::RestoreWatchers(napi_env env, OHOS::ObjectStore::JSObjectWrapper *wrapper)
{
    std::string &sessionId = wrapper->GetObject()->GetSessionId();
    napi_status status;
    napi_value callbackValue;
    LOG_DEBUG("start restore %{public}s", sessionId.c_str());
    if (g_changeCallBacks.count(sessionId) != 0) {
        LOG_INFO("restore change on %{public}s", sessionId.c_str());
        for (auto callback : g_changeCallBacks.at(sessionId)) {
            status = napi_get_reference_value(env, callback, &callbackValue);
            if (status != napi_ok) {
                LOG_ERROR("error! %{public}d", status);
                continue;
            }
            wrapper->AddWatch(env, CHANGE, callbackValue);
        }
    } else {
        LOG_INFO("no callback %{public}s", sessionId.c_str();
    if (g_statusCallBacks.count(sessionId) != 0) {
        LOG_INFO("restore status on %{public}s", sessionId.c_str());
        for (auto callback : g_statusCallBacks.at(sessionId)) {
            status = napi_get_reference_value(env, callback, &callbackValue);
            if (status != napi_ok) {
                LOG_ERROR("error! %{public}d", status);
                continue;
            }
            wrapper->AddWatch(env, STATUS, callbackValue);
        }
    } else {
        LOG_INFO("no status callback %{public}s", sessionId.c_str());
    }
}
} // namespace OHOS::ObjectStore
