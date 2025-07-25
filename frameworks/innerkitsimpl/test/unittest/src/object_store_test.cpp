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

#include <gtest/gtest.h>
#include <thread>

#include "accesstoken_kit.h"
#include "distributed_object.h"
#include "distributed_object_impl.h"
#include "distributed_objectstore.h"
#include "distributed_objectstore_impl.h"
#include "flat_object_storage_engine.h"
#include "flat_object_store.h"
#include "mock_flat_object_watcher.h"
#include "mock_object_watcher.h"
#include "nativetoken_kit.h"
#include "object_storage_engine.h"
#include "objectstore_errors.h"
#include "store_errno.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::ObjectStore;
using namespace OHOS::Security::AccessToken;
namespace {
// object service error code
enum Status : int32_t {
    OBJECT_SUCCESS,
    OBJECT_DBSTATUS_ERROR,
    OBJECT_INNER_ERROR,
    OBJECT_PERMISSION_DENIED,
    OBJECT_STORE_NOT_FOUND
};
constexpr static double SALARY = 100.5;
class TableWatcherImpl : public TableWatcher {
public:
    explicit TableWatcherImpl(const std::string &sessionId) : TableWatcher(sessionId) {}
    void OnChanged(
        const std::string &sessionid, const std::vector<std::string> &changedData, bool enableTransfer) override;
    virtual ~TableWatcherImpl();
};

TableWatcherImpl::~TableWatcherImpl() {}
void TableWatcherImpl::OnChanged(
    const std::string &sessionid, const std::vector<std::string> &changedData, bool enableTransfer) {}

class StatusNotifierImpl : public StatusWatcher {
public:
    void OnChanged(
        const std::string &sessionId, const std::string &networkId, const std::string &onlineStatus) override;
    virtual ~StatusNotifierImpl();
};
StatusNotifierImpl::~StatusNotifierImpl() {}

void StatusNotifierImpl::OnChanged(const std::string &sessionId,
                                   const std::string &networkId,
                                   const std::string &onlineStatus)
{
}

class ProgressNotifierImpl : public ProgressWatcher {
public:
void OnChanged(const std::string &sessionId, int32_t progress) override;
virtual ~ProgressNotifierImpl();
};
ProgressNotifierImpl::~ProgressNotifierImpl()
{
}

void ProgressNotifierImpl::OnChanged(const std::string &sessionId, int32_t progress)
{
}
void GrantPermissionNative()
{
    const char **perms = new const char *[3];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.DISTRIBUTED_SOFTBUS_CENTER";
    perms[2] = "ohos.permission.MONITOR_DEVICE_NETWORK_STATE"; // perms[2] is a permission parameter
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 3,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "distributed_object",
        .aplStr = "system_basic",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
}

class NativeObjectStoreTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NativeObjectStoreTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void NativeObjectStoreTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void NativeObjectStoreTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
    GrantPermissionNative();
}

void NativeObjectStoreTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 * @tc.name: DistributedObjectStore_Create_Destroy_001
 * @tc.desc: test Create DistributedObject and Destroy DistrbutedObject
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStore_Create_Destroy_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    uint32_t ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObjectStore_Create_Destroy_002
 * @tc.desc: test Create DistributedObject and Destroy DistrbutedObject
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStore_Create_Destroy_002, TestSize.Level1)
{
    std::string sessionId = "123456";

    auto objectStore = new DistributedObjectStoreImpl(nullptr);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_EQ(nullptr, object);
    delete objectStore;
}

/**
 * @tc.name: DistributedObjectStore_Create_Destroy_003
 * @tc.desc: test Create DistributedObject and Destroy DistrbutedObject
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStore_Create_Destroy_003, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    DistributedObject *object2 = objectStore->CreateObject(sessionId);
    EXPECT_EQ(nullptr, object2);

    uint32_t ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObjectStore_Create_Destroy_004
 * @tc.desc: test Create DistributedObject and Destroy DistrbutedObject
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStore_Create_Destroy_004, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    
    uint32_t status = -1;
    DistributedObject *object = objectStore->CreateObject(sessionId, status);
    ASSERT_NE(nullptr, object);
    EXPECT_EQ(SUCCESS, status);

    uint32_t ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObjectStoreImpl_CreateObject_001
 * @tc.desc: test Create DistributedObjectStoreImpl
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStoreImpl_CreateObject_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject("");
    EXPECT_EQ(nullptr, object);
}

/**
 * @tc.name: DistributedObjectStoreImpl_CreateObject_002
 * @tc.desc: test Create DistributedObjectStoreImpl
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStoreImpl_CreateObject_002, TestSize.Level1)
{
    std::string sessionId = "123456";
    auto objectStore = DistributedObjectStoreImpl(nullptr);
    uint32_t status = -1;
    DistributedObject *object = objectStore.CreateObject(sessionId, status);
    EXPECT_EQ(nullptr, object);
    EXPECT_EQ(ERR_NULL_OBJECTSTORE, status);

    status = objectStore.DeleteObject(sessionId);
    EXPECT_EQ(ERR_NULL_OBJECTSTORE, status);
}

/**
 * @tc.name: DistributedObjectStoreImpl_CreateObject_003
 * @tc.desc: test Create DistributedObjectStoreImpl
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStoreImpl_CreateObject_003, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);

    uint32_t status = -1;
    DistributedObject *object = objectStore->CreateObject(sessionId, status);
    EXPECT_EQ(nullptr, object);
    EXPECT_EQ(ERR_INVALID_ARGS, status);

    status = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(ERR_DB_NOT_EXIST, status);
}

/**
 * @tc.name: DistributedObjectStoreImpl_Get_001
 * @tc.desc: test DistributedObjectStoreImpl Get
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStoreImpl_Get_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "sessionId";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    DistributedObject *Object1 = nullptr;
    uint32_t status = objectStore->Get("", &Object1);
    EXPECT_EQ(ERR_GET_OBJECT, status);

    status = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, status);
}

/**
 * @tc.name: DistributedObjectStoreImpl_Watch_001
 * @tc.desc: test DistributedObjectStoreImpl Watch
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStoreImpl_Watch_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "sessionId";
    auto objectStore = new DistributedObjectStoreImpl(nullptr);

    std::shared_ptr<MockObjectWatcher> watcher = std::make_shared<MockObjectWatcher>();
    uint32_t status = objectStore->Watch(nullptr, watcher);
    EXPECT_EQ(ERR_NULL_OBJECT, status);

    auto flatObjectStore = new FlatObjectStore(bundleName);
    auto object = new DistributedObjectImpl(sessionId, flatObjectStore);

    status = objectStore->Watch(object, watcher);
    EXPECT_EQ(ERR_NULL_OBJECTSTORE, status);

    status = objectStore->UnWatch(object);
    EXPECT_EQ(ERR_NULL_OBJECTSTORE, status);
    delete objectStore;
    delete flatObjectStore;
    delete object;
}

/**
 * @tc.name: DistributedObjectStoreImpl_Watch_002
 * @tc.desc: test DistributedObjectStoreImpl Watch
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStoreImpl_Watch_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "sessionId";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    std::shared_ptr<MockObjectWatcher> watcher = std::make_shared<MockObjectWatcher>();
    uint32_t status = objectStore->Watch(object, watcher);
    EXPECT_EQ(SUCCESS, status);

    status = objectStore->Watch(object, watcher);
    EXPECT_EQ(ERR_EXIST, status);

    std::string bundleName1 = "default1";
    std::string sessionId1 = "sessionId1";
    auto flatObjectStore = new FlatObjectStore(bundleName1);
    auto object1 = new DistributedObjectImpl(sessionId1, flatObjectStore);
    status = objectStore->Watch(object1, watcher);
    EXPECT_EQ(ERR_DB_NOT_EXIST, status);

    status = objectStore->UnWatch(object1);
    EXPECT_EQ(ERR_DB_NOT_EXIST, status);

    status = objectStore->UnWatch(object);
    EXPECT_EQ(SUCCESS, status);

    status = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, status);
    delete flatObjectStore;
    delete object1;
}

/**
 * @tc.name: DistributedObjectStore_Get_001
 * @tc.desc: test DistributedObjectStore Get.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStore_Get_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    DistributedObject *object2 = nullptr;
    uint32_t ret = objectStore->Get(sessionId, &object2);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_EQ(object, object2);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObjectStore_Watch_UnWatch_001
 * @tc.desc: test DistributedObjectStore Watch and UnWatch.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStore_Watch_UnWatch_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    auto watcherPtr = std::shared_ptr<ObjectWatcher>();
    uint32_t ret = objectStore->Watch(object, watcherPtr);
    EXPECT_EQ(SUCCESS, ret);

    ret = objectStore->UnWatch(object);
    EXPECT_EQ(SUCCESS, ret);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObjectStore_SetStatusNotifier_001
 * @tc.desc: test DistributedObjectStore SetStatusNotifier.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStore_SetStatusNotifier_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    auto notifierPtr = std::shared_ptr<StatusNotifier>();
    uint32_t ret = objectStore->SetStatusNotifier(notifierPtr);
    EXPECT_EQ(ret, 0);

    objectStore->NotifyCachedStatus(sessionId);
    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: DistributedObject_Double_001
 * @tc.desc: test DistributedObjectStore PutDouble.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Double_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    uint32_t ret = object->PutDouble("salary", SALARY);
    EXPECT_EQ(ret, 0);

    double value = 0.0;
    object->GetDouble("salary", value);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(value, SALARY);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: DistributedObject_GetDouble_001
 * @tc.desc: test DistributedObjectStore GetDouble.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetDouble_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    double value = 0.0;
    uint32_t ret = object->GetDouble("salary", value);
    EXPECT_EQ(ret, DistributedDB::DBStatus::NOT_FOUND);
    EXPECT_EQ(value, 0.0);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: DistributedObject_Boolean_001
 * @tc.desc: test DistributedObjectStore PutBoolean.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Boolean_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    uint32_t ret = object->PutBoolean("isTrue", true);
    EXPECT_EQ(SUCCESS, ret);

    bool value = false;
    ret = object->GetBoolean("isTrue", value);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_EQ(true, value);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_GetBoolean_001
 * @tc.desc: test DistributedObjectStore GetBoolean.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetBoolean_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    bool value = false;
    uint32_t ret = object->GetBoolean("isTrue", value);
    EXPECT_EQ(DistributedDB::DBStatus::NOT_FOUND, ret);
    EXPECT_EQ(false, value);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_String_001
 * @tc.desc: test DistributedObjectStore String.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_String_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    uint32_t ret = object->PutString("name", "zhangsan");
    EXPECT_EQ(SUCCESS, ret);

    std::string value = "";
    ret = object->GetString("name", value);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_EQ(value, "zhangsan");

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_GetString_001
 * @tc.desc: test DistributedObjectStore GetString.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetString_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    std::string value = "";
    uint32_t ret = object->GetString("name", value);
    EXPECT_EQ(DistributedDB::DBStatus::NOT_FOUND, ret);
    EXPECT_EQ(value, "");

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_GetSessionId_001
 * @tc.desc: test DistributedObjectStore GetSessionId.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetSessionId_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);
    std::string getSessionId = object->GetSessionId();
    EXPECT_EQ(sessionId, getSessionId);
    uint32_t ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_PutComplex_001
 * @tc.desc: test DistributedObjectStore PutComplex.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_PutComplex_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    std::vector<uint8_t> value = {'z', 'h'};
    uint32_t ret = object->PutComplex("name", value);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_GetComplex_001
 * @tc.desc: test DistributedObjectStore GetComplex.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetComplex_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    std::vector<uint8_t> value = {'z', 'h'};
    uint32_t ret = object->PutComplex("name", value);
    EXPECT_EQ(SUCCESS, ret);
    ret = object->GetComplex("name", value);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_GetComplex_002
 * @tc.desc: test DistributedObjectStore GetComplex.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetComplex_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    std::vector<uint8_t> value = {'z', 'h'};
    uint32_t ret = object->GetComplex("name", value);
    EXPECT_EQ(DistributedDB::DBStatus::NOT_FOUND, ret);
    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_SetAsset_001
 * @tc.desc: test DistributedObjectStore SetAsset.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_SetAsset_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    uint32_t ret = object->PutString("attachment.name", "1.txt");
    EXPECT_EQ(SUCCESS, ret);

    std::string value;
    ret = object->GetString("attachment.name", value);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_EQ(value, "1.txt");

    std::string deviceId;
    ret = object->GetString("__deviceId", deviceId);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_FALSE(deviceId.empty());

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_TestSetSessionId_001
 * @tc.desc: test DistributedObjectStore TestSetSessionId.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_TestSetSessionId_001, TestSize.Level1)
{
    auto testSetSessionId = [] (std::string bundleName, std::string sessionId) {
        DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
        ASSERT_NE(nullptr, objectStore);
        DistributedObject *object = objectStore->CreateObject(sessionId);
        ASSERT_NE(nullptr, object);

        uint32_t ret = objectStore->DeleteObject(sessionId);
        EXPECT_EQ(SUCCESS, ret);
    };
    std::thread t1(testSetSessionId, "default1", "session1");
    std::thread t2(testSetSessionId, "default2", "session2");
    std::thread t3(testSetSessionId, "default3", "session3");
    t1.join();
    t2.join();
    t3.join();
}

/**
 * @tc.name: DistributedObject_GetType_001
 * @tc.desc: test DistributedObject GetType.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetType_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    uint32_t ret = object->PutString("name", "zhangsan");
    EXPECT_EQ(SUCCESS, ret);
    Type type;
    ret = object->GetType("name", type);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_EQ(TYPE_STRING, type);

    ret = object->PutDouble("salary", SALARY);
    EXPECT_EQ(SUCCESS, ret);
    ret = object->GetType("salary", type);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_EQ(TYPE_DOUBLE, type);

    ret = object->PutBoolean("isTrue", true);
    EXPECT_EQ(SUCCESS, ret);
    ret = object->GetType("isTrue", type);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_EQ(TYPE_BOOLEAN, type);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_GetType_002
 * @tc.desc: test DistributedObject GetType.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetType_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    Type type;
    uint32_t ret = object->GetType("name", type);
    EXPECT_EQ(DistributedDB::DBStatus::NOT_FOUND, ret);
    EXPECT_EQ(TYPE_STRING, type);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_Save_RevokeSave_001
 * @tc.desc: test DistributedObjectStore Save.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Save_RevokeSave_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);


    uint32_t ret = object->PutString("name", "zhangsan");
    EXPECT_EQ(SUCCESS, ret);
    ret = object->PutDouble("salary", SALARY);
    EXPECT_EQ(SUCCESS, ret);
    ret = object->PutBoolean("isTrue", true);
    EXPECT_EQ(SUCCESS, ret);

    ret = object->Save("local");
    EXPECT_EQ(SUCCESS, ret);
    ret = object->RevokeSave();
    EXPECT_EQ(SUCCESS, ret);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_Save_RevokeSave_002
 * @tc.desc: test DistributedObjectStore Save.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Save_RevokeSave_002, TestSize.Level1)
{
    auto testSaveAndRevokeSave = [](std::string bundleName, std::string sessionId) {
        DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
        ASSERT_NE(nullptr, objectStore);
        DistributedObject *object = objectStore->CreateObject(sessionId);
        ASSERT_NE(nullptr, object);

        uint32_t ret = object->PutString("name", "zhangsan");
        EXPECT_EQ(SUCCESS, ret);
        ret = object->PutDouble("salary", SALARY);
        EXPECT_EQ(SUCCESS, ret);
        ret = object->PutBoolean("isTrue", true);
        EXPECT_EQ(SUCCESS, ret);

        ret = object->Save("local");
        EXPECT_EQ(SUCCESS, ret);
        ret = object->RevokeSave();
        EXPECT_EQ(SUCCESS, ret);

        ret = objectStore->DeleteObject(sessionId);
        EXPECT_EQ(SUCCESS, ret);
    };
    std::thread t1(testSaveAndRevokeSave, "default1", "session1");
    std::thread t2(testSaveAndRevokeSave, "default2", "session2");
    std::thread t3(testSaveAndRevokeSave, "default3", "session3");
    t1.join();
    t2.join();
    t3.join();
}

/**
 * @tc.name: DistributedObject_Save_RevokeSave_003
 * @tc.desc: test DistributedObjectStore Save.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Save_RevokeSave_003, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);

    uint32_t ret = object->RevokeSave();
    EXPECT_EQ(SUCCESS, ret);

    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_Open_001
 * @tc.desc: test ObjectStorageEngine Open, calling Open repeatedly.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Open_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_CreateTable_001
 * @tc.desc: test ObjectStorageEngine CreateTable.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_CreateTable_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_CreateTable_002
 * @tc.desc: test ObjectStorageEngine CreateTable, calling CreateTable() repeatedly.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_CreateTable_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_NE(SUCCESS, ret);
    ret = objectStorageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_CreateTable_003
 * @tc.desc: test ObjectStorageEngine CreateTable, calling CreateTable after calling Close().
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_CreateTable_003, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->Close();
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_NE(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_GetTable_001
 * @tc.desc: test ObjectStorageEngine GetTable, not calling Open().
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetTable_001, TestSize.Level1)
{
    std::string sessionId = "session01";
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    std::map<std::string, Value> result = {};
    uint32_t ret = objectStorageEngine->GetTable(sessionId, result);
    EXPECT_NE(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_GetTable_002
 * @tc.desc: test ObjectStorageEngine GetTable, calling Open(),but not calling CreateTable().
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetTable_002, TestSize.Level1)
{
    std::string bundleName = "default02";
    std::string sessionId = "session02";
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    std::map<std::string, Value> result = {};
    ret = objectStorageEngine->GetTable(sessionId, result);
    EXPECT_NE(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_GetTable_003
 * @tc.desc: test ObjectStorageEngine GetTable, calling Open() and CreateTable(), but not calling UpdateItem().
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetTable_003, TestSize.Level1)
{
    std::string bundleName = "default03";
    std::string sessionId = "session03";
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    std::map<std::string, Value> result = {};
    ret = objectStorageEngine->GetTable(sessionId, result);
    EXPECT_NE(SUCCESS, ret);
    ret = objectStorageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_GetTable_004
 * @tc.desc: test ObjectStorageEngine GetTable.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetTable_004, TestSize.Level1)
{
    std::string bundleName = "default04";
    std::string sessionId = "session04";
    std::vector<uint8_t> value = { 1, 8 };
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->UpdateItem(sessionId, "age", value);
    EXPECT_EQ(SUCCESS, ret);
    std::map<std::string, Value> result = {};
    ret = objectStorageEngine->GetTable(sessionId, result);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: FlatObjectStore_UpdateItems_001
 * @tc.desc: test ObjectStorageEngine UpdateItems. input data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_UpdateItems_001, TestSize.Level1)
{
    std::string bundleName = "default06";
    std::string sessionId = "session06";
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    std::map<std::string, std::vector<uint8_t>> data = {};
    ret = objectStorageEngine->UpdateItems(sessionId, data);
    EXPECT_NE(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: FlatObjectStore_UpdateItems_002
 * @tc.desc: test FlatObjectStore UpdateItems.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_UpdateItems_002, TestSize.Level1)
{
    std::string bundleName = "default07";
    std::string sessionId = "session07";
    std::vector<uint8_t> value = { 1, 8 };
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    std::map<std::string, std::vector<uint8_t>> data = { { "age", value } };
    ret = objectStorageEngine->UpdateItems(sessionId, data);
    EXPECT_EQ(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_OpenAndClose_001
 * @tc.desc: test FlatObjectStorageEngine OpenAndClose and Close when FlatObjectStorageEngine is not open.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_OpenAndClose_001, TestSize.Level1)
{
    std::string bundleName = "default07";
    FlatObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->Close();
    EXPECT_EQ(SUCCESS, ret);
    objectStorageEngine->isOpened_ = false;
    ret = objectStorageEngine->Close();
    EXPECT_EQ(SUCCESS, ret);
    delete objectStorageEngine;
}

/**
 * @tc.name: DistributedObject_NotifyChange_001
 * @tc.desc: test FlatObjectStorageEngine NotifyChange.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_NotifyChange_001, TestSize.Level1)
{
    std::string bundleName = "default07";
    std::string sessionId = "session07";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    uint32_t ret = storageEngine->Open(bundleName);
    ret = storageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    std::map<std::string, std::vector<uint8_t>> filteredData;
    storageEngine->NotifyChange(sessionId, filteredData);
    ret = storageEngine->Close();
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: FlatObjectStore_CheckRetrieveCache_001
 * @tc.desc: test FlatObjectStore CheckRetrieveCache.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_CheckRetrieveCache_001, TestSize.Level1)
{
    std::string sessionId = "session05";
    std::string bundleName = "default07";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    flatObjectStore->CheckRetrieveCache(sessionId);
    ret = flatObjectStore->Delete(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: FlatObjectStore_Delete_001
 * @tc.desc: test FlatObjectStore Delete. wrong sessionId
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_Delete_001, TestSize.Level1)
{
    std::string sessionId = "session001";
    std::string bundleName = "default001";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    sessionId = "session002";
    ret = flatObjectStore->Delete(sessionId);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
}

/**
 * @tc.name: FlatObjectStore_Delete_002
 * @tc.desc: test FlatObjectStore Delete. wrong sessionId
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_Delete_002, TestSize.Level1)
{
    std::string sessionId = "session001";
    std::string bundleName = "";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(ERR_DB_GETKV_FAIL, ret);
}

/**
 * @tc.name: FlatObjectStore_Watch_001
 * @tc.desc: test FlatObjectStore Watch. wrong sessionId
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_Watch_001, TestSize.Level1)
{
    std::string sessionId = "session002";
    std::string bundleName = "default002";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    sessionId = "session003";
    std::shared_ptr<MockFlatObjectWatcher> watcher = std::make_shared<MockFlatObjectWatcher>(sessionId);
    ret = flatObjectStore->Watch(sessionId, watcher);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
}

/**
 * @tc.name: FlatObjectStore_UnWatch_001
 * @tc.desc: test FlatObjectStore UnWatch. wrong sessionId
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_UnWatch_001, TestSize.Level1)
{
    std::string sessionId = "session003";
    std::string bundleName = "default003";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    sessionId = "session004";
    std::shared_ptr<MockFlatObjectWatcher> watcher = std::make_shared<MockFlatObjectWatcher>(sessionId);
    ret = flatObjectStore->UnWatch(sessionId);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
}

/**
 * @tc.name: FlatObjectStore_Save_001
 * @tc.desc: test FlatObjectStore Save. wrong sessionId
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_Save_001, TestSize.Level1)
{
    std::string sessionId = "session004";
    std::string bundleName = "default004";
    std::string deviceId = "deviceId004";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    sessionId = "session005";
    std::shared_ptr<MockFlatObjectWatcher> watcher = std::make_shared<MockFlatObjectWatcher>(sessionId);
    ret = flatObjectStore->Save(sessionId, deviceId);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
}

/**
 * @tc.name: FlatObjectStore_OnComplete_001
 * @tc.desc: test FlatObjectStore OnComplete.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_OnComplete_001, TestSize.Level1)
{
    std::string bundleName = "default005";
    std::string sessionId = "session005";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    uint32_t ret = storageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = storageEngine->CreateTable(sessionId);
    std::shared_ptr<StatusNotifierImpl> statusWatcher = std::make_shared<StatusNotifierImpl>();
    DistributedDB::DBStatus status = DistributedDB::DBStatus::OK;
    std::map<std::string, DistributedDB::DBStatus> devices = { { sessionId, status } };
    storageEngine->OnComplete(sessionId, devices, statusWatcher);
    ret = storageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: CacheManager_Save_001
 * @tc.desc: test CacheManager Save.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, CacheManager_Save_001, TestSize.Level1)
{
    std::string bundleName = "";
    std::string sessionId = "";
    std::string deviceId = "";
    std::map<std::string, std::vector<uint8_t>> objectData;
    CacheManager cacheManager;
    auto ret = cacheManager.Save(bundleName, sessionId, deviceId, objectData);
    EXPECT_EQ(OHOS::DistributedKv::Status::INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: CacheManager_RevokeSave_001
 * @tc.desc: test CacheManager RevokeSave.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, CacheManager_RevokeSave_001, TestSize.Level1)
{
    std::string bundleName = "";
    std::string sessionId = "";
    CacheManager cacheManager;
    auto ret = cacheManager.RevokeSave(bundleName, sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: CacheManager_ResumeObject_001
 * @tc.desc: test CacheManager ResumeObject.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, CacheManager_ResumeObject_001, TestSize.Level1)
{
    std::string bundleName = "";
    std::string sessionId = "";
    CacheManager cacheManager;
    std::function<void(const std::map<std::string, std::vector<uint8_t>> &data, bool allReady)> callback =
        [](const std::map<std::string, std::vector<uint8_t>> &data, bool allReady) {};
    auto ret = cacheManager.ResumeObject(bundleName, sessionId, callback);
    EXPECT_EQ(OHOS::DistributedKv::Status::KEY_NOT_FOUND, ret);
}

/**
 * @tc.name: CacheManager_SubscribeDataChange_001
 * @tc.desc: test CacheManager SubscribeDataChange.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, CacheManager_SubscribeDataChange_001, TestSize.Level1)
{
    std::string bundleName = "";
    std::string sessionId = "";
    CacheManager cacheManager;
    std::function<void(const std::map<std::string, std::vector<uint8_t>> &data, bool allReady)> callback =
        [](const std::map<std::string, std::vector<uint8_t>> &data, bool allReady) {};
    auto ret = cacheManager.SubscribeDataChange(bundleName, sessionId, callback);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: CacheManager_UnregisterDataChange_001
 * @tc.desc: test CacheManager UnregisterDataChange.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, CacheManager_UnregisterDataChange_001, TestSize.Level1)
{
    std::string bundleName = "";
    std::string sessionId = "";
    CacheManager cacheManager;
    auto ret = cacheManager.UnregisterDataChange(bundleName, sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: CacheManager_IsContinue_001
 * @tc.desc: test CacheManager IsContinue.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, CacheManager_IsContinue_001, TestSize.Level1)
{
    auto cacheManager = std::make_shared<CacheManager>();
    auto result = cacheManager->IsContinue();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: DistributedObject_NotifyCachedStatus_001
 * @tc.desc: test DistributedObjectStore NotifyCachedStatus.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_NotifyCachedStatus_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    uint32_t status = 0;
    DistributedObject *object = objectStore->CreateObject(sessionId, status);
    ASSERT_NE(nullptr, object);
    EXPECT_EQ(SUCCESS, status);
    objectStore->NotifyCachedStatus(sessionId);
    uint32_t ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_UnWatch_001
 * @tc.desc: test DistributedObjectStore UnWatch, DistributedObject is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_UnWatch_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);
    uint32_t ret = objectStore->UnWatch(nullptr);
    EXPECT_EQ(ERR_NULL_OBJECT, ret);
    ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_CreateTable_004
 * @tc.desc: test FlatObjectStorageEngine CreateTable, sessionId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_CreateTable_004, TestSize.Level1)
{
    std::string bundleName = "default";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    uint32_t ret = storageEngine->CreateTable("");
    EXPECT_EQ(ERR_DB_GETKV_FAIL, ret);
}

/**
 * @tc.name: DistributedObject_GetTable_005
 * @tc.desc: test FlatObjectStorageEngine GetTable, storageEngine is not open or sessionId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetTable_005, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    std::map<std::string, Value> tableResult;
    storageEngine->isOpened_ = false;
    uint32_t ret = storageEngine->GetTable(sessionId, tableResult);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
    storageEngine->isOpened_ = true;
    ret = storageEngine->GetTable("", tableResult);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
    storageEngine->DeleteTable(sessionId);
}

/**
 * @tc.name: DistributedObject_UpdateItem_003
 * @tc.desc: test FlatObjectStorageEngine UpdateItem, storageEngine is not open or error sessionid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_UpdateItem_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    storageEngine->isOpened_ = false;
    std::vector<uint8_t> value = { 1, 8 };
    uint32_t ret = storageEngine->UpdateItem(sessionId, "age", value);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
    storageEngine->isOpened_ = true;
    ret = storageEngine->UpdateItem("123", "age", value);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
    storageEngine->DeleteTable(sessionId);
}

/**
 * @tc.name: DistributedObject_UpdateItems_004
 * @tc.desc: test FlatObjectStorageEngine UpdateItems, storageEngine is not open or error sessionid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_UpdateItems_003, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    storageEngine->isOpened_ = false;
    std::vector<uint8_t> value = { 1, 8 };
    std::map<std::string, std::vector<uint8_t>> data = { { "age", value } };
    uint32_t ret = storageEngine->UpdateItems(sessionId, data);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);

    storageEngine->isOpened_ = true;
    ret = storageEngine->UpdateItems("123", data);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
    storageEngine->DeleteTable(sessionId);
}

/**
 * @tc.name: DistributedObject_DeleteTable_001
 * @tc.desc: test FlatObjectStorageEngine DeleteTable, storageEngine is not open or error sessionid.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_DeleteTable_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    storageEngine->isOpened_ = false;
    uint32_t ret = storageEngine->DeleteTable(sessionId);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
    storageEngine->isOpened_ = true;
    ret = storageEngine->DeleteTable("123");
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
    storageEngine->DeleteTable(sessionId);
}

/**
 * @tc.name: DistributedObject_GetItem_002
 * @tc.desc: test FlatObjectStorageEngine GetItem, storageEngine is not open or error key.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetItem_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    storageEngine->isOpened_ = false;
    std::vector<uint8_t> value = { 1, 8 };
    uint32_t ret = storageEngine->GetItem(sessionId, "", value);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
    storageEngine->Open(bundleName);
    ret = storageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_GetItem_003
 * @tc.desc: test FlatObjectStorageEngine GetItem, error key.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetItem_003, TestSize.Level1)
{
    std::string sessionId = "123456";
    std::string bundleName = "default";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    std::vector<uint8_t> value = { 1, 8 };
    storageEngine->Open(bundleName);
    uint32_t ret = storageEngine->GetItem(sessionId, "123", value);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
}

/**
 * @tc.name: DistributedObject_RegisterObserver_001
 * @tc.desc: test FlatObjectStorageEngine RegisterObserver, storageEngine is not open.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_RegisterObserver_001, TestSize.Level1)
{
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->isOpened_ = false;
    auto tableWatcherPtr = std::make_shared<TableWatcherImpl>(sessionId);
    uint32_t ret = storageEngine->RegisterObserver(sessionId, tableWatcherPtr);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
}

/**
 * @tc.name: DistributedObject_RegisterObserver_002
 * @tc.desc: test FlatObjectStorageEngine RegisterObserver, empty sessionId.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_RegisterObserver_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    auto tableWatcherPtr = std::make_shared<TableWatcherImpl>(sessionId);
    uint32_t ret = storageEngine->RegisterObserver("", tableWatcherPtr);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
    ret = storageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_RegisterObserver_003
 * @tc.desc: test FlatObjectStorageEngine RegisterObserver, repeat RegisterObserver.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_RegisterObserver_003, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    auto tableWatcherPtr = std::make_shared<TableWatcherImpl>(sessionId);
    // RegisterObserver observer already exist
    uint32_t ret = storageEngine->RegisterObserver(sessionId, tableWatcherPtr);
    EXPECT_EQ(SUCCESS, ret);
    storageEngine->RegisterObserver(sessionId, tableWatcherPtr);
    EXPECT_EQ(SUCCESS, ret);
    ret = storageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_UnRegisterObserver_001
 * @tc.desc: test FlatObjectStorageEngine UnRegisterObserver, storageEngine is not open.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_UnRegisterObserver_001, TestSize.Level1)
{
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->isOpened_ = false;
    uint32_t ret = storageEngine->UnRegisterObserver(sessionId);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
}

/**
 * @tc.name: DistributedObject_UnRegisterObserver_001
 * @tc.desc: test FlatObjectStorageEngine UnRegisterObserver, empty sessionId.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_UnRegisterObserver_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    uint32_t ret = storageEngine->UnRegisterObserver("");
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
}

/**
 * @tc.name: DistributedObject_SetStatusNotifier_002
 * @tc.desc: test FlatObjectStorageEngine SetStatusNotifier.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_SetStatusNotifier_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    auto statusNotifier = std::make_shared<StatusNotifierImpl>();
    uint32_t ret = storageEngine->SetStatusNotifier(statusNotifier);
    EXPECT_EQ(SUCCESS, ret);
    ret = storageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_SetStatusNotifier_003
 * @tc.desc: test FlatObjectStorageEngine SetStatusNotifier, storageEngine is not open.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_SetStatusNotifier_003, TestSize.Level1)
{
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    auto statusNotifier = std::make_shared<StatusNotifierImpl>();
    storageEngine->isOpened_ = false;
    uint32_t ret = storageEngine->SetStatusNotifier(statusNotifier);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
}

/**
 * @tc.name: DistributedObject_GetItems_001
 * @tc.desc: test FlatObjectStorageEngine GetItems, storageEngine is not open or error key.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetItems_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    storageEngine->isOpened_ = false;
    std::vector<uint8_t> value = { 1, 8 };
    std::map<std::string, std::vector<uint8_t>> data = { { "age", value } };
    uint32_t ret = storageEngine->GetItems(sessionId, data);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
    storageEngine->Open(bundleName);
    ret = storageEngine->GetItems("", data);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
    ret = storageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_NotifyStatus_001
 * @tc.desc: test FlatObjectStorageEngine NotifyStatus.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_NotifyStatus_001, TestSize.Level1)
{
    std::string bundleName = "default07";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    uint32_t ret = storageEngine->Open(bundleName);
    storageEngine->NotifyStatus(sessionId, "local", "restored");
    ret = storageEngine->Close();
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_SyncAllData_002
 * @tc.desc: test FlatObjectStorageEngine SyncAllData.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_SyncAllData_002, TestSize.Level1)
{
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    auto onComplete = [](const std::map<std::string, DistributedDB::DBStatus> &) {};
    std::vector<std::string> deviceIds = { "deviceIds" };
    uint32_t ret = storageEngine->SyncAllData("", deviceIds, onComplete);
    EXPECT_EQ(ERR_DB_NOT_EXIST, ret);
}

/**
 * @tc.name: DistributedObject_UpdateItem_002
 * @tc.desc: test FlatObjectStorageEngine UpdateItem, error status.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_UpdateItem_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->Open(bundleName);
    storageEngine->CreateTable(sessionId);
    std::vector<uint8_t> value = { 1, 2 };
    uint32_t ret = storageEngine->UpdateItem(sessionId, std::string(1025, 't'), value);
    EXPECT_EQ(ERR_CLOSE_STORAGE, ret);
    ret = storageEngine->DeleteTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObjectStore_SetProgressNotifier_001
 * @tc.desc: test DistributedObjectStore SetProgressNotifier.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObjectStore_SetProgressNotifier_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    ASSERT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    ASSERT_NE(nullptr, object);
    objectStore->NotifyProgressStatus(sessionId);
    auto progressNotifierPtr = std::shared_ptr<ProgressNotifier>();
    auto ret = objectStore->SetProgressNotifier(progressNotifierPtr);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: DistributedObject_SetProgressNotifier_002
 * @tc.desc: test FlatObjectStorageEngine SetProgressNotifier.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_SetProgressNotifier_002, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->isOpened_ = true;
    auto progressNotifier = std::make_shared<ProgressNotifierImpl>();
    uint32_t ret = storageEngine->SetProgressNotifier(progressNotifier);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_SetProgressNotifier_003
 * @tc.desc: test FlatObjectStorageEngine SetProgressNotifier, storageEngine is not open.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_SetProgressNotifier_003, TestSize.Level1)
{
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    auto progressNotifier = std::make_shared<ProgressNotifierImpl>();
    storageEngine->isOpened_ = false;
    uint32_t ret = storageEngine->SetProgressNotifier(progressNotifier);
    EXPECT_EQ(ERR_DB_NOT_INIT, ret);
}

/**
 * @tc.name: DistributedObject_NotifyProgress_001
 * @tc.desc: test FlatObjectStorageEngine NotifyProgress.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_NotifyProgress_001, TestSize.Level1)
{
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    std::string sessionId = "123456";
    int32_t progress = 100;
    auto ret = storageEngine->NotifyProgress(sessionId, progress);
    EXPECT_EQ(ret, false);
    auto progressNotifier = std::make_shared<ProgressNotifierImpl>();
    storageEngine->isOpened_ = true;
    ret = storageEngine->SetProgressNotifier(progressNotifier);
    ret = storageEngine->NotifyProgress(sessionId, progress);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CacheManager_SubscribeProgressChange_001
 * @tc.desc: test CacheManager SubscribeProgressChange.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, CacheManager_SubscribeProgressChange_001, TestSize.Level1)
{
    std::string bundleName = "";
    std::string sessionId = "";
    CacheManager cacheManager;
    std::function<void(int32_t progress)> callback = [sessionId, this](int32_t progress) {};
    auto ret = cacheManager.SubscribeProgressChange(bundleName, sessionId, callback);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: CacheManager_UnregisterProgressChange_001
 * @tc.desc: test CacheManager UnregisterProgressChange.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, CacheManager_UnregisterProgressChange_001, TestSize.Level1)
{
    std::string bundleName = "";
    std::string sessionId = "";
    CacheManager cacheManager;
    auto ret = cacheManager.UnregisterProgressChange(bundleName, sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: FlatObjectStore_CheckProgressCache_001
 * @tc.desc: test FlatObjectStore CheckProgressCache.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_CheckProgressCache_001, TestSize.Level1)
{
    std::string sessionId = "session001";
    std::string bundleName = "default001";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    flatObjectStore->CheckProgressCache(sessionId);
    flatObjectStore->SubscribeProgressChange(sessionId);
    flatObjectStore->CheckProgressCache(sessionId);
    int32_t progress = 100;
    flatObjectStore->progressInfoCache_[sessionId] = progress;
    flatObjectStore->CheckProgressCache(sessionId);
    auto progressNotifier = std::make_shared<ProgressNotifierImpl>();
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    storageEngine->isOpened_ = true;
    ret = storageEngine->SetProgressNotifier(progressNotifier);
    ret = storageEngine->NotifyProgress(sessionId, progress);
    EXPECT_EQ(ret, true);
    flatObjectStore->CheckProgressCache(sessionId);
    ret = flatObjectStore->Delete(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: FlatObjectStore_SubscribeProgressChange_001
 * @tc.desc: test FlatObjectStore SubscribeProgressChange.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_SubscribeProgressChange_001, TestSize.Level1)
{
    std::string sessionId = "session001";
    std::string bundleName = "default001";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    flatObjectStore->SubscribeProgressChange(sessionId);
    ret = flatObjectStore->Delete(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: FlatObjectStore_SetProgressNotifier_001
 * @tc.desc: test FlatObjectStore SetProgressNotifier.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_SetProgressNotifier_001, TestSize.Level1)
{
    std::string sessionId = "session001";
    std::string bundleName = "default001";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    auto progressNotifier = std::make_shared<ProgressNotifierImpl>();
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    flatObjectStore->storageEngine_->isOpened_ = true;
    flatObjectStore->SetProgressNotifier(progressNotifier);
    flatObjectStore->storageEngine_->isOpened_ = false;
    flatObjectStore->SetProgressNotifier(progressNotifier);
    ret = flatObjectStore->Delete(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: FlatObjectStore_SetProgressNotifier_002
 * @tc.desc: test FlatObjectStore SetProgressNotifier，storageEngine is not open.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, FlatObjectStore_SetProgressNotifier_002, TestSize.Level1)
{
    std::string sessionId = "session001";
    std::string bundleName = "default001";
    std::shared_ptr<FlatObjectStore> flatObjectStore = std::make_shared<FlatObjectStore>(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    auto progressNotifier = std::make_shared<ProgressNotifierImpl>();
    std::shared_ptr<FlatObjectStorageEngine> storageEngine = std::make_shared<FlatObjectStorageEngine>();
    auto notifier = std::shared_ptr<ProgressNotifier>();
    std::shared_ptr<ProgressNotifierProxy> progressNotifierProxy = std::make_shared<ProgressNotifierProxy>(notifier);
    int32_t progress = 100;
    progressNotifierProxy->OnChanged(sessionId, progress);
    progressNotifierProxy->notifier = notifier;
    progressNotifierProxy->OnChanged(sessionId, progress);
    storageEngine->isOpened_ = false;
    flatObjectStore->SetProgressNotifier(progressNotifier);
    EXPECT_EQ(SUCCESS, ret);
    ret = flatObjectStore->Delete(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}
} // namespace
