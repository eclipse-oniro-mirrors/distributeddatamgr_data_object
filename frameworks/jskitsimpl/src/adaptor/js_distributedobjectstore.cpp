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

#include <random>

#include "accesstoken_kit.h"
#include "js_ability.h"
#include "js_common.h"
#include "js_distributedobject.h"
#include "js_util.h"
#include "logger.h"
#include "object_error.h"
#include "objectstore_errors.h"

namespace OHOS::ObjectStore {
constexpr size_t TYPE_SIZE = 20;
constexpr size_t PARAM_COUNT_MAX = 3;
static ConcurrentMap<std::string, std::list<napi_ref>> g_statusCallBacks;
static ConcurrentMap<std::string, std::list<napi_ref>> g_changeCallBacks;
static ConcurrentMap<std::string, std::list<napi_ref>> g_progressCallBacks;
bool JSDistributedObjectStore::AddCallback(napi_env env, ConcurrentMap<std::string, std::list<napi_ref>> &callbacks,
    const std::string &objectId, napi_value callback)
{
    LOG_INFO("add callback %{public}s", objectId.c_str());
    napi_ref ref = nullptr;
    napi_status status = napi_create_reference(env, callback, 1, &ref);
    if (status != napi_ok) {
        return false;
    }
    return callbacks.Compute(objectId, [&ref](const std::string &key, std::list<napi_ref> &lists) {
        lists.push_back(ref);
        return true;
    });
}

bool DeleteAllCallback(napi_env env, std::list<napi_ref> &lists)
{
    for (auto iter = lists.begin(); iter != lists.end();) {
        if (*iter == nullptr) {
            iter++;
            continue;
        }
        napi_status status = napi_delete_reference(env, *iter);
        NOT_MATCH_RETURN_FALSE(status == napi_ok);
        iter = lists.erase(iter);
    }
    return false;
}

bool DeleteSingleCallback(napi_env env, std::list<napi_ref> &lists, napi_value callback)
{
    napi_value callbackTmp;
    for (auto iter = lists.begin(); iter != lists.end();) {
        if (*iter == nullptr) {
            iter++;
            continue;
        }
        napi_status status = napi_get_reference_value(env, *iter, &callbackTmp);
        NOT_MATCH_RETURN_FALSE(status == napi_ok);
        bool isEquals = false;
        napi_strict_equals(env, callbackTmp, callback, &isEquals);
        if (isEquals) {
            napi_delete_reference(env, *iter);
            iter = lists.erase(iter);
        } else {
            iter++;
        }
    }
    return !lists.empty();
}

bool JSDistributedObjectStore::DelCallback(napi_env env, ConcurrentMap<std::string, std::list<napi_ref>> &callbacks,
    const std::string &sessionId, napi_value callback)
{
    LOG_INFO("del callback %{public}s", sessionId.c_str());
    auto execute = [&env, callback](const std::string &key, std::list<napi_ref> &lists) {
        if (callback == nullptr) {
            return DeleteAllCallback(env, lists);
        } else {
            return DeleteSingleCallback(env, lists, callback);
        }
    };
    return callbacks.ComputeIfPresent(sessionId, execute);
}

napi_value JSDistributedObjectStore::NewDistributedObject(
    napi_env env, DistributedObjectStore *objectStore, DistributedObject *object, const std::string &objectId)
{
    napi_value result;
    napi_status status = napi_new_instance(env, JSDistributedObject::GetCons(env), 0, nullptr, &result);
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    JSObjectWrapper *objectWrapper = new (std::nothrow) JSObjectWrapper(objectStore, object);
    if (objectWrapper == nullptr) {
        LOG_ERROR("JSDistributedObjectStore::NewDistributedObject no memory for objectWrapper malloc!");
        return nullptr;
    }
    objectWrapper->SetObjectId(objectId);
    status = napi_wrap(
        env, result, objectWrapper,
        [](napi_env env, void *data, void *hint) {
            if (data == nullptr) {
                LOG_WARN("objectWrapper is nullptr.");
                return;
            }
            auto objectWrapper = static_cast<JSObjectWrapper *>(data);

            JSDistributedObjectStore::DelCallback(env, g_changeCallBacks, objectWrapper->GetObjectId());
            JSDistributedObjectStore::DelCallback(env, g_statusCallBacks, objectWrapper->GetObjectId());

            if (objectWrapper->GetObject() == nullptr) {
                delete objectWrapper;
                return;
            }
            LOG_INFO("start delete object");
            DistributedObjectStore::GetInstance(JSDistributedObjectStore::GetBundleName(env))
                ->DeleteObject(objectWrapper->GetObject()->GetSessionId());
            delete objectWrapper;
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        LOG_WARN("error! napi_wrap failed.");
        delete objectWrapper;
        return nullptr;
    }

    RestoreWatchers(env, objectWrapper, objectId);
    objectStore->NotifyCachedStatus(object->GetSessionId());
    objectStore->NotifyProgressStatus(object->GetSessionId());
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    return result;
}

// function createObjectSync(version: number, sessionId: string, objectId:string): DistributedObject;
// function createObjectSync(version: number, sessionId: string, objectId:string, context: Context): DistributedObject;
napi_value JSDistributedObjectStore::JSCreateObjectSync(napi_env env, napi_callback_info info)
{
    size_t requireArgc = 3;
    size_t argc = 4;
    napi_value argv[4] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    double version = 8;
    std::string sessionId;
    std::string objectId;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    auto innerError = std::make_shared<InnerError>();
    NAPI_ASSERT_ERRCODE_V9(env, argc >= 1, version, innerError);

    status = JSUtil::GetValue(env, argv[0], version);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && argc >= requireArgc, version,
        std::make_shared<ParametersNum>("1 or 2"));
    NAPI_ASSERT_ERRCODE_V9(env, !IsSandBox(), version, innerError);
    LOG_INFO("start JSCreateObjectSync");
    status = JSUtil::GetValue(env, argv[1], sessionId);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok, version,
        std::make_shared<ParametersType>("sessionId", "string"));

    status = JSUtil::GetValue(env, argv[2], objectId);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok, version, innerError);
    std::string bundleName = "";
    if (argc > requireArgc) {
        bool executeResult = JSDistributedObjectStore::GetBundleNameWithContext(env, argv[3], bundleName);
        NAPI_ASSERT_ERRCODE_V9(env, executeResult, version, innerError);
    } else {
        bundleName = JSDistributedObjectStore::GetBundleName(env);
    }
    DistributedObjectStore *objectInfo = DistributedObjectStore::GetInstance(bundleName);
    NAPI_ASSERT_ERRCODE_V9(env, objectInfo != nullptr, version, innerError);
    uint32_t result = 0;
    DistributedObject *object = objectInfo->CreateObject(sessionId, result);
    NAPI_ASSERT_ERRCODE_V9(env, result != ERR_EXIST, version, std::make_shared<DatabaseError>());
    NAPI_ASSERT_ERRCODE_V9(env, result != ERR_NO_PERMISSION, version, std::make_shared<PermissionError>());
    NAPI_ASSERT_ERRCODE_V9(env, result == SUCCESS && object != nullptr, version, innerError);
    return NewDistributedObject(env, objectInfo, object, objectId);
}

// function destroyObjectSync(version: number, object: DistributedObject): number;
napi_value JSDistributedObjectStore::JSDestroyObjectSync(napi_env env, napi_callback_info info)
{
    double version = 8;
    LOG_INFO("start");
    size_t requireArgc = 2;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    std::string sessionId;
    std::string bundleName;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    status = JSUtil::GetValue(env, argv[0], version);
    NOT_MATCH_RETURN_NULL(status == napi_ok && argc >= requireArgc);

    JSObjectWrapper *objectWrapper = nullptr;
    status = napi_unwrap(env, argv[1], (void **)&objectWrapper);
    auto innerError = std::make_shared<InnerError>();
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && objectWrapper != nullptr, version, innerError);

    DistributedObjectStore *objectInfo =
        DistributedObjectStore::GetInstance(JSDistributedObjectStore::GetBundleName(env));
    NAPI_ASSERT_ERRCODE_V9(env, objectInfo != nullptr && objectWrapper->GetObject() != nullptr, version, innerError);

    objectWrapper->DeleteWatch(env, Constants::CHANGE);
    objectWrapper->DeleteWatch(env, Constants::STATUS);
    objectWrapper->DeleteWatch(env, Constants::PROGRESS);
    objectInfo->DeleteObject(objectWrapper->GetObject()->GetSessionId());
    objectWrapper->DestroyObject();
    return nullptr;
}

// function on(version: number, type: 'change', object: DistributedObject,
//             callback: Callback<ChangedDataObserver>): void;
// function on(version: number, type: 'status', object: DistributedObject,
//             callback: Callback<ObjectStatusObserver>): void;
napi_value JSDistributedObjectStore::JSOn(napi_env env, napi_callback_info info)
{
    double version = 8;
    LOG_INFO("start");
    size_t requireArgc = 4;
    size_t argc = 4;
    napi_value argv[4] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    auto innerError = std::make_shared<InnerError>();
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && argc >= 1, version, innerError);

    status = JSUtil::GetValue(env, argv[0], version);
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    NAPI_ASSERT_ERRCODE_V9(env, argc >= requireArgc, version, std::make_shared<ParametersNum>("2"));

    char type[TYPE_SIZE] = { 0 };
    size_t eventTypeLen = 0;
    status = napi_get_value_string_utf8(env, argv[1], type, TYPE_SIZE, &eventTypeLen);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok, version, std::make_shared<ParametersType>("type", "string"));

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, argv[2], &valueType);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && valueType == napi_object, version, innerError);

    JSObjectWrapper *wrapper = nullptr;
    status = napi_unwrap(env, argv[2], (void **)&wrapper);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && wrapper != nullptr, version, innerError);

    status = napi_typeof(env, argv[3], &valueType);
    NAPI_ASSERT_ERRCODE_V9(env, valueType == napi_function, version,
        std::make_shared<ParametersType>("callback", "function"));
    bool addResult = wrapper->AddWatch(env, type, argv[3]);
    NAPI_ASSERT_ERRCODE_V9(env, addResult, version, innerError);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

// function off(version: number, type: 'change', object: DistributedObject,
//              callback?: Callback<ChangedDataObserver>): void;
// function off(version: number, type: 'status', object: DistributedObject,
//              callback?: Callback<ObjectStatusObserver>): void;
napi_value JSDistributedObjectStore::JSOff(napi_env env, napi_callback_info info)
{
    double version = 8;
    LOG_INFO("start");
    size_t requireArgc = 3;
    size_t argc = 4;
    napi_value argv[4] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    char type[TYPE_SIZE] = { 0 };
    size_t typeLen = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    auto innerError = std::make_shared<InnerError>();
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && argc >= 1, version, innerError);

    status = JSUtil::GetValue(env, argv[0], version);
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    NAPI_ASSERT_ERRCODE_V9(env, argc >= requireArgc, version, std::make_shared<ParametersNum>("1"));

    status = napi_get_value_string_utf8(env, argv[1], type, TYPE_SIZE, &typeLen);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok, version, std::make_shared<ParametersType>("type", "string"));

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, argv[2], &valueType);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && valueType == napi_object, version, innerError);

    JSObjectWrapper *wrapper = nullptr;
    status = napi_unwrap(env, argv[2], (void **)&wrapper);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && wrapper != nullptr, version, innerError);
    if (argc == requireArgc) {
        LOG_INFO("delete all");
        wrapper->DeleteWatch(env, type);
    } else {
        LOG_INFO("delete");
        status = napi_typeof(env, argv[3], &valueType);
        NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && valueType == napi_function, version,
            std::make_shared<ParametersType>("callback", "function"));
        wrapper->DeleteWatch(env, type, argv[3]);
    }
    napi_value result = nullptr;
    status = napi_get_undefined(env, &result);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok, version, innerError);
    return result;
}

bool JSDistributedObjectStore::GetBundleNameWithContext(napi_env env, napi_value argv, std::string &bundleName)
{
    napi_valuetype objectType = napi_undefined;
    napi_status status = napi_typeof(env, argv, &objectType);
    if (status == napi_ok && objectType == napi_object) {
        std::shared_ptr<Context> context = JSAbility::GetContext(env, argv);
        if (context != nullptr) {
            bundleName = context->GetBundleName();
            return true;
        }
    }
    LOG_ERROR("arguments error, context.");
    return false;
}

std::string JSDistributedObjectStore::GetBundleName(napi_env env)
{
    static std::string bundleName;
    if (bundleName.empty()) {
        bundleName = AbilityRuntime::Context::GetApplicationContext()->GetBundleName();
    }
    return bundleName;
}

void JSDistributedObjectStore::RestoreWatchers(napi_env env, JSObjectWrapper *wrapper, const std::string &objectId)
{
    napi_status status;
    napi_value callbackValue;
    bool watchResult = true;
    LOG_DEBUG("start restore %{public}s", objectId.c_str());
    watchResult = g_changeCallBacks.ComputeIfPresent(objectId, [&](const std::string &key, std::list<napi_ref> &lists) {
        for (auto callback : lists) {
            status = napi_get_reference_value(env, callback, &callbackValue);
            if (status != napi_ok) {
                LOG_ERROR("error! %{public}d", status);
                continue;
            }
            wrapper->AddWatch(env, Constants::CHANGE, callbackValue);
        }
        return true;
    });
    if (!watchResult) {
        LOG_INFO("no callback %{public}s", objectId.c_str());
    }
    watchResult = g_statusCallBacks.ComputeIfPresent(objectId, [&](const std::string &key, std::list<napi_ref> &lists) {
        for (auto callback : lists) {
            status = napi_get_reference_value(env, callback, &callbackValue);
            if (status != napi_ok) {
                LOG_ERROR("error! %{public}d", status);
                continue;
            }
            wrapper->AddWatch(env, Constants::STATUS, callbackValue);
        }
        return true;
    });
    if (!watchResult) {
        LOG_INFO("no status %{public}s", objectId.c_str());
    }
    watchResult =
        g_progressCallBacks.ComputeIfPresent(objectId, [&](const std::string &key, std::list<napi_ref> &lists) {
            for (auto callback : lists) {
                status = napi_get_reference_value(env, callback, &callbackValue);
                if (status != napi_ok) {
                    LOG_ERROR("error! %{public}d", status);
                    continue;
                }
                wrapper->AddWatch(env, Constants::PROGRESS, callbackValue);
            }
            return true;
    });
    if (!watchResult) {
        LOG_INFO("no status %{public}s", objectId.c_str());
    }
}

// function recordCallback(version: number, type: 'change', objectId: string,
//                         callback: Callback<ChangedDataObserver>): void;
// function recordCallback(version: number, type: 'status', objectId: string,
//                         callback: Callback<ObjectStatusObserver>): void;
napi_value JSDistributedObjectStore::JSRecordCallback(napi_env env, napi_callback_info info)
{
    double version = 8;
    LOG_INFO("start");
    size_t requireArgc = 4;
    size_t argc = 4;
    napi_value argv[4] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    auto innerError = std::make_shared<InnerError>();
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && argc >= 1, version, innerError);

    status = JSUtil::GetValue(env, argv[0], version);
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    NAPI_ASSERT_ERRCODE_V9(env, argc >= requireArgc, version, std::make_shared<ParametersNum>("2"));

    char type[TYPE_SIZE] = { 0 };
    size_t eventTypeLen = 0;
    status = napi_get_value_string_utf8(env, argv[1], type, TYPE_SIZE, &eventTypeLen);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok, version, std::make_shared<ParametersType>("type", "string"));

    std::string objectId;
    status = JSUtil::GetValue(env, argv[2], objectId);
    NOT_MATCH_RETURN_NULL(status == napi_ok);

    napi_valuetype callbackType = napi_undefined;
    status = napi_typeof(env, argv[3], &callbackType);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && callbackType == napi_function, version,
        std::make_shared<ParametersType>("callback", "function"));

    bool addResult = true;
    if (!strcmp(Constants::CHANGE, type)) {
        addResult = AddCallback(env, g_changeCallBacks, objectId, argv[PARAM_COUNT_MAX]);
    } else if (!strcmp(Constants::STATUS, type)) {
        addResult = AddCallback(env, g_statusCallBacks, objectId, argv[PARAM_COUNT_MAX]);
    } else if (!strcmp(Constants::PROGRESS, type)) {
        addResult = AddCallback(env, g_progressCallBacks, objectId, argv[PARAM_COUNT_MAX]);
    }
    NAPI_ASSERT_ERRCODE_V9(env, addResult, version, innerError);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

// function deleteCallback(version: number, type: 'change', objectId: string,
//                         callback?: Callback<ChangedDataObserver>): void;
// function deleteCallback(version: number, type: 'status', objectId: string,
//                         callback?: Callback<ObjectStatusObserver>): void;
napi_value JSDistributedObjectStore::JSDeleteCallback(napi_env env, napi_callback_info info)
{
    double version = 8;
    LOG_INFO("start");
    size_t requireArgc = 3;
    size_t argc = 4;
    napi_value argv[4] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    auto innerError = std::make_shared<InnerError>();
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && argc >= 1, version, innerError);

    status = JSUtil::GetValue(env, argv[0], version);
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    NAPI_ASSERT_ERRCODE_V9(env, argc >= requireArgc, version, std::make_shared<ParametersNum>("1 or 2"));

    char type[TYPE_SIZE] = { 0 };
    size_t eventTypeLen = 0;

    status = napi_get_value_string_utf8(env, argv[1], type, TYPE_SIZE, &eventTypeLen);
    NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok, version, std::make_shared<ParametersType>("type", "string"));

    std::string objectId;
    status = JSUtil::GetValue(env, argv[2], objectId);
    NOT_MATCH_RETURN_NULL(status == napi_ok);

    bool delResult = true;
    if (argc == 3) {
        if (!strcmp(Constants::CHANGE, type)) {
            delResult = DelCallback(env, g_changeCallBacks, objectId);
        } else if (!strcmp(Constants::STATUS, type)) {
            delResult = DelCallback(env, g_statusCallBacks, objectId);
        } else if (!strcmp(Constants::PROGRESS, type)) {
            delResult = DelCallback(env, g_progressCallBacks, objectId);
        }
    } else {
        napi_valuetype callbackType = napi_undefined;
        status = napi_typeof(env, argv[3], &callbackType);
        NAPI_ASSERT_ERRCODE_V9(env, status == napi_ok && callbackType == napi_function, version,
            std::make_shared<ParametersType>("callback", "function"));
        if (!strcmp(Constants::CHANGE, type)) {
            delResult = DelCallback(env, g_changeCallBacks, objectId, argv[PARAM_COUNT_MAX]);
        } else if (!strcmp(Constants::STATUS, type)) {
            delResult = DelCallback(env, g_statusCallBacks, objectId, argv[PARAM_COUNT_MAX]);
        } else if (!strcmp(Constants::PROGRESS, type)) {
            delResult = DelCallback(env, g_progressCallBacks, objectId, argv[PARAM_COUNT_MAX]);
        }
    }
    NAPI_ASSERT_ERRCODE_V9(env, delResult, version, innerError);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value JSDistributedObjectStore::JSEquenceNum(napi_env env, napi_callback_info info)
{
    std::random_device randomDevice;
    std::uniform_int_distribution<uint32_t> distribution(0, std::numeric_limits<uint32_t>::max());
    std::string str = std::to_string(distribution(randomDevice));
    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, str.c_str(), str.size(), &result);
    NOT_MATCH_RETURN_NULL(status == napi_ok);
    return result;
}

// don't create distributed data object while this application is sandbox
bool JSDistributedObjectStore::IsSandBox()
{
    int32_t dlpFlag = Security::AccessToken::AccessTokenKit::GetHapDlpFlag(
        AbilityRuntime::Context::GetApplicationContext()->GetApplicationInfo()->accessTokenId);
    if (dlpFlag != 0) {
        return true;
    }
    return false;
}
} // namespace OHOS::ObjectStore
