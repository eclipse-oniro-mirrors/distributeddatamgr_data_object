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

#ifndef JS_COMMON_H
#define JS_COMMON_H
#include "hilog/log.h"
#include "js_util.h"
#include "napi_queue.h"
namespace OHOS::ObjectStore
{

#define CHECK_EQUAL_WITH_RETURN_NULL(status, value)                   \
    {                                                                 \
        if (status != value)                                          \
        {                                                             \
            LOG_ERROR("error! %{public}d %{public}d", status, value); \
            return nullptr;                                           \
        }                                                             \
    }
#define CHECK_EQUAL_WITH_RETURN_VOID(status, value)                   \
    {                                                                 \
        if (status != value)                                          \
        {                                                             \
            LOG_ERROR("error! %{public}d %{public}d", status, value); \
            return;                                                   \
        }                                                             \
    }
#define ASSERT_MATCH_ELSE_RETURN_VOID(condition)        \
    {                                                   \
        if (!(condition))                               \
        {                                               \
            LOG_ERROR("error! %{public}s", #condition); \
            return;                                     \
        }                                               \
    }
#define ASSERT_MATCH_ELSE_RETURN_NULL(condition)        \
    {                                                   \
        if (!(condition))                               \
        {                                               \
            LOG_ERROR("error! %{public}s", #condition); \
            return nullptr;                             \
        }                                               \
    }
#define ASSERT_MATCH_ELSE_GOTO_ERROR(condition)         \
    {                                                   \
        if (!(condition))                               \
        {                                               \
            LOG_ERROR("error! %{public}s", #condition); \
            goto ERROR;                                 \
        }                                               \
    }
} // namespace OHOS::ObjectStore
static const char *CHANGE = "change";
static const char *STATUS = "status";
#endif // JS_COMMON_H
