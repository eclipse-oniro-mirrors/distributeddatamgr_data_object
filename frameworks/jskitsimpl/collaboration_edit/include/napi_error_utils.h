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

#ifndef COLLABORATION_EDIT_NAPI_ERROR_UTILS_H
#define COLLABORATION_EDIT_NAPI_ERROR_UTILS_H

#include <string>

#include "js_native_api.h"
#include "log_print.h"
#include "napi_errno.h"
#include "napi/native_common.h"

namespace OHOS::CollaborationEdit {

#define RETVAL_NOTHING

/* check condition, return and logging if condition not true. */
#define ASSERT(condition, message, retVal)                     \
    do {                                                       \
        if (!(condition)) {                                    \
            LOG_ERROR("test (" #condition ") go wrong: " message); \
            return retVal;                                     \
        }                                                      \
    } while (0)

#define ASSERT_VOID(condition, message)                        \
    do {                                                       \
        if (!(condition)) {                                    \
            LOG_ERROR("test (" #condition ") go wrong: " message); \
            return;                                            \
        }                                                      \
    } while (0)

#define ASSERT_THROW_BASE(env, condition, errCode, message, retVal)  \
    do {                                                       \
        if (!(condition)) {                                    \
            ThrowNapiError(env, errCode, message);             \
            return retVal;                                     \
        }                                                      \
    } while (0)

#define ASSERT_THROW(env, condition, errCode, message) ASSERT_THROW_BASE(env, condition, errCode, message, nullptr)
#define ASSERT_THROW_VOID(env, condition, errCode, message)  \
    ASSERT_THROW_BASE(env, condition, errCode, message, RETVAL_NOTHING)

void ThrowNapiError(napi_env env, int32_t errCode, const std::string &errMessage);

} // namespace OHOS::CollaborationEdit
#endif // COLLABORATION_EDIT_NAPI_ERROR_UTILS_H
