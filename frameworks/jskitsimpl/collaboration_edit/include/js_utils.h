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

#ifndef COLLABORATION_EDIT_JS_UTILS_H
#define COLLABORATION_EDIT_JS_UTILS_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS::CollaborationEdit {
namespace JSUtils {
napi_value Convert2JSValue(napi_env env, int32_t value);
} // namespace JSUtils
} // namespace OHOS::CollaborationEdit
#endif // COLLABORATION_EDIT_JS_UTILS_H