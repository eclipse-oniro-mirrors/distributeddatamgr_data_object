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

#include <string>
#include <thread>

#include "auto_launch_export.h"
#include "flat_object_store.h"
#include "flat_object_storage_engine.h"
#include "distributed_object.h"
#include "distributed_objectstore.h"
#include "distributed_objectstore_impl.h"
#include "kv_store_delegate_manager.h"
#include "object_storage_engine.h"
#include "objectstore_errors.h"
#include "store_observer.h"
#include "ipc_skeleton.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::ObjectStore;
using namespace OHOS::Security::AccessToken;

constexpr static double SALARY = 100.5;

static void TestSetSessionId(std::string bundleName, std::string sessionId)
{
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    EXPECT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

    uint32_t ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

static void TestSaveAndRevokeSave(std::string bundleName, std::string sessionId)
{
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    EXPECT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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

void GrantPermissionNative()
{
    const char **perms = new const char *[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.DISTRIBUTED_SOFTBUS_CENTER";
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
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
    EXPECT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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
    EXPECT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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
    EXPECT_NE(nullptr, objectStore);
    
    uint32_t status = -1;
    DistributedObject *object = objectStore->CreateObject(sessionId, status);
    EXPECT_NE(nullptr, object);
    EXPECT_EQ(SUCCESS, status);

    uint32_t ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
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
    EXPECT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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
    EXPECT_NE(nullptr, objectStore);

    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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
    EXPECT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

    auto notifierPtr = std::shared_ptr<StatusNotifier>();
    uint32_t ret = objectStore->SetStatusNotifier(notifierPtr);
    EXPECT_EQ(ret, 0);

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
    EXPECT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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
 * @tc.name: DistributedObject_Boolean_001
 * @tc.desc: test DistributedObjectStore PutBoolean.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Boolean_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    EXPECT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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
 * @tc.name: DistributedObject_String_001
 * @tc.desc: test DistributedObjectStore String.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_String_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    EXPECT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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
 * @tc.name: DistributedObject_GetSessionId_001
 * @tc.desc: test DistributedObjectStore GetSessionId.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_GetSessionId_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    DistributedObjectStore *objectStore = DistributedObjectStore::GetInstance(bundleName);
    EXPECT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);
    std::string getSessionId = object->GetSessionId();
    EXPECT_EQ(sessionId, getSessionId);
    uint32_t ret = objectStore->DeleteObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name: DistributedObject_TestSetSessionId_001
 * @tc.desc: test DistributedObjectStore TestSetSessionId.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_TestSetSessionId_001, TestSize.Level1)
{
    std::thread t1(TestSetSessionId, "default1", "session1");
    std::thread t2(TestSetSessionId, "default2", "session2");
    std::thread t3(TestSetSessionId, "default3", "session3");
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
    EXPECT_NE(nullptr, objectStore);
    DistributedObject *object = objectStore->CreateObject(sessionId);
    EXPECT_NE(nullptr, object);

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
 * @tc.name: DistributedObject_Save_RevokeSave_001
 * @tc.desc: test DistributedObjectStore Save.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Save_RevokeSave_001, TestSize.Level1)
{
    std::string bundleName = "default";
    std::string sessionId = "123456";
    TestSaveAndRevokeSave(bundleName, sessionId);
}

/**
 * @tc.name: DistributedObject_Save_RevokeSave_002
 * @tc.desc: test DistributedObjectStore Save.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_Save_RevokeSave_002, TestSize.Level1)
{
    std::thread t1(TestSaveAndRevokeSave, "default1", "session1");
    std::thread t2(TestSaveAndRevokeSave, "default2", "session2");
    std::thread t3(TestSaveAndRevokeSave, "default3", "session3");
    t1.join();
    t2.join();
    t3.join();
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
    std::vector<uint8_t> value = { 1, 8 };
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
    std::vector<uint8_t> value = { 1, 8 };
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
    std::vector<uint8_t> value = { 1, 8 };
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
    std::vector<uint8_t> value = { 1, 8 };
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
    std::string bundleName = "default01";
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
 * @tc.name: FlatObjectStore_FilterData_001
 * @tc.desc: test FlatObjectStore FilterData.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_FilterData_001, TestSize.Level1)
{
    std::string bundleName = "default05";
    std::string sessionId = "session05";
    std::vector<uint8_t> value = { 1, 8 };
    FlatObjectStore *flatObjectStore = new FlatObjectStore(bundleName);
    uint32_t ret = flatObjectStore->CreateObject(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    ret = flatObjectStore->Put(sessionId, "phone", value);
    EXPECT_EQ(SUCCESS, ret);
    ret = flatObjectStore->Put(sessionId, "age", value);
    EXPECT_EQ(SUCCESS, ret);
    std::map<std::string, std::vector<uint8_t>> data = {{"age", value}, {"age", value}};
    auto dataSize = data.size();
    flatObjectStore->FilterData(sessionId, data);
    EXPECT_GT(dataSize, data.size());
    ret = flatObjectStore->Delete(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    delete flatObjectStore;
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
    std::vector<uint8_t> value = { 1, 8 };
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
 * @tc.desc: test FlatObjectStore FilterData.
 * @tc.type: FUNC
 */
HWTEST_F(NativeObjectStoreTest, DistributedObject_UpdateItems_002, TestSize.Level1)
{
    std::string bundleName = "default07";
    std::string sessionId = "session07";
    std::vector<uint8_t> value = { 1, 8 };
    ObjectStorageEngine *objectStorageEngine = new FlatObjectStorageEngine();
    uint32_t ret = objectStorageEngine->Open(bundleName);
    EXPECT_EQ(SUCCESS, ret);
    ret = objectStorageEngine->CreateTable(sessionId);
    EXPECT_EQ(SUCCESS, ret);
    std::map<std::string, std::vector<uint8_t>> data = {{"age", value}};
    ret = objectStorageEngine->UpdateItems(sessionId, data);
    EXPECT_EQ(SUCCESS, ret);
    delete objectStorageEngine;
}