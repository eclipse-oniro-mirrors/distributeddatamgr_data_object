/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index';
import distributedObject from '@ohos.data.distributedDataObject';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import bundle from '@ohos.bundle';

const TAG = "OBJECTSTORE_TEST";
function changeCallback(sessionId, changeData) {
    console.info("changeCallback start");
    console.info(TAG + "sessionId:" + " " + sessionId);
    if (changeData != null && changeData != undefined) {
        changeData.forEach(element => {
            console.info(TAG + "data changed !" + element);
        });
    }
    console.info("changeCallback end");
}

function statusCallback1(sessionId, networkId, status) {
    console.info(TAG + "statusCallback1" + " " + sessionId);
    this.response += "\nstatus changed " + sessionId + " " + status + " " + networkId;
}

function statusCallback2(sessionId, networkId, status) {
    console.info(TAG + "statusCallback2" + " " + sessionId);
    this.response += "\nstatus changed " + sessionId + " " + status + " " + networkId;
}

const PERMISSION_USER_SET = 1;
const PERMISSION_USER_NAME = "ohos.permission.DISTRIBUTED_DATASYNC";
var tokenID = undefined;
async function grantPerm() {
    console.info("====grant Permission start====");
    var appInfo = await bundle.getApplicationInfo('com.example.myapplication', 0, 100);
    tokenID = appInfo.accessTokenId;
    console.info("accessTokenId" + appInfo.accessTokenId + " bundleName:" + appInfo.bundleName);
    var atManager = abilityAccessCtrl.createAtManager();
    var result = await atManager.grantUserGrantedPermission(tokenID, PERMISSION_USER_NAME, PERMISSION_USER_SET);
    console.info("tokenId" + tokenID + " result:" + result);
    console.info("====grant Permission end====");
}
describe('objectStoreTest',function () {
    beforeAll(async function (done) {
        await grantPerm();
        done();
    })

    beforeEach(function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(function () {
        console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name: V9testsetSessionId001
     * @tc.desc: object join session and on,object can receive callback when data has been changed
     * @tc.type: FUNC
     */
    it('V9testsetSessionId001', 0, function () {
        console.log(TAG + "************* V9testsetSessionId001 start *************");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);
        try {
            g_object.setSessionId(123).then(() => {
                console.info(TAG + "setSessionId test");
            });
        } catch (error) {
            expect(error.code == 401).assertEqual(true);
            expect(error.message == "Parameter error. The type of 'sessionId' must be 'string'").assertEqual(true);
        }
        console.log(TAG + "************* V9testsetSessionId001 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name: V9testsetSessionId002
     * @tc.desc: object join session and on,object can receive callback when data has been changed
     * @tc.type: FUNC
     */
    it('V9testsetSessionId002', 0, function () {
        console.log(TAG + "************* V9testsetSessionId002 start *************");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);
        g_object.setSessionId("session1");
        expect("session1" == g_object.__sessionId).assertEqual(true);
        g_object.setSessionId("session1").then(() => {
            console.info(TAG + "setSessionId test");
        }).catch((error) => {
            expect(error.code == 15400001).assertEqual(true);
            expect(error.message == "error.message: create table failed").assertEqual(true);
        });
        console.log(TAG + "************* V9testsetSessionId002 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name: V9testOn001
     * @tc.desc: object join session and on,object can receive callback when data has been changed
     * @tc.type: FUNC
     */
    it('V9testOn001', 0, function () {
        console.log(TAG + "************* V9testOn001 start *************");
        var g_object = distributedObject.create({ name: "Amy", age: 18, isVis: false });
        expect(g_object == undefined).assertEqual(false);
        g_object.setSessionId("session1");
        expect("session1" == g_object.__sessionId).assertEqual(true);
        console.info(TAG + " start call watch change");
        g_object.on("change", function (sessionId, changeData) {
            console.info("V9testOn001 callback start.");
            if (changeData != null && changeData != undefined) {
                changeData.forEach(element => {
                    console.info(TAG + "data changed !" + element);
                });
            }
            console.info("V9testOn001 callback end.");
        });

        if (g_object != undefined && g_object != null) {
            g_object.name = "jack1";
            g_object.age = 19;
            g_object.isVis = true;
            expect(g_object.name == "jack1").assertEqual(true);
            expect(g_object.age == 19).assertEqual(true);
            console.info(TAG + " set data success!");
        } else {
            console.info(TAG + " object is null,set name fail");
        }

        console.log(TAG + "************* V9testOn001 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name: V9testOn002
     * @tc.desc: object join session and on,then object change data twice,object can receive two callbacks when data has been changed
     * @tc.type: FUNC
     */
    it('V9testOn002', 0, function () {
        console.log(TAG + "************* V9testOn002 start *************");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);
        g_object.setSessionId("session1");
        expect("session1" == g_object.__sessionId).assertEqual(true);
        console.info(TAG + " start call watch change");
        try {
            g_object.on(123, function (sessionId, changeData) {
                console.info("V9testOn002 callback start.");
                if (changeData != null && changeData != undefined) {
                    changeData.forEach(element => {
                        console.info(TAG + "data changed !" + element);
                    });
                }
                console.info("V9testOn002 callback end.");
            });

        } catch (error) {
            expect(error.code == 401).assertEqual(true);
            expect(error.message == "Parameter error. The type of 'type' must be 'string'").assertEqual(true);
        }
        console.log(TAG + "************* V9testOn002 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name: testOn003
     * @tc.desc object join session and on,then object do not change data,object can not receive callbacks
     * @tc.type: FUNC
     */
    it('V9testOn003', 0, function () {
        console.log(TAG + "************* V9testOn003 start *************");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);
        g_object.setSessionId("session1");
        expect("session1" == g_object.__sessionId).assertEqual(true);
        console.info(TAG + " start call watch change");
        try {
            g_object.on("error", function (sessionId, changeData) {
                console.info("V9testOn003 callback start.");
                if (changeData != null && changeData != undefined) {
                    changeData.forEach(element => {
                        console.info(TAG + "data changed !" + element);
                    });
                }
                console.info("V9testOn003 callback end.");
            });
        } catch (error) {
            console.info(error);
            expect(error == undefined).assertEqual(true);
        }
        console.log(TAG + "************* V9testOn003 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name V9testOff001
     * @tc.desc object join session and on&off,object can not receive callback after off
     * @tc.type: FUNC
     */
    it('V9testOff001', 0, function () {
        console.log(TAG + "************* V9testOff001 start *************");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);
        g_object.setSessionId("session5");
        expect("session5" == g_object.__sessionId).assertEqual(true);

        g_object.on("change", changeCallback);
        console.info(TAG + " start call watch change");
        if (g_object != undefined && g_object != null) {
            g_object.name = "jack1";
            g_object.age = 19;
            g_object.isVis = true;
            expect(g_object.name == "jack1").assertEqual(true);
            expect(g_object.age == 19).assertEqual(true);
            console.info(TAG + " set data success!");
        } else {
            console.info(TAG + " object is null,set name fail");
        }
        g_object.off("change", changeCallback);
        console.info(TAG + " end call watch change");
        if (g_object != undefined && g_object != null) {
            g_object.name = "jack2";
            g_object.age = 20;
            g_object.isVis = false;
            expect(g_object.name == "jack2").assertEqual(true);
            expect(g_object.age == 20).assertEqual(true);
            console.info(TAG + " set data success!");
        } else {
            console.info(TAG + " object is null,set name fail");
        }
        console.log(TAG + "************* V9testOff001 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name:V9testOff002
     * @tc.desc object join session and off,object can not receive callback
     * @tc.type: FUNC
     */
    it('V9testOff002', 0, function () {
        console.log(TAG + "************* V9testOff002 start *************");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);
        g_object.setSessionId("session6");
        expect("session6" == g_object.__sessionId).assertEqual(true);
        try {
            g_object.off(123);
        } catch (error) {
            console.info(error.code);
            console.info(error.message);
            expect(error.code == 401).assertEqual(true);
            expect(error.message == "Parameter error. type mismatch").assertEqual(true);
        }
        console.info(TAG + " end call watch change");
        console.log(TAG + "************* V9testOff002 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name: V9testOnStatus001
     * @tc.desc: object set a listener to watch another object online/offline
     * @tc.type: FUNC
     */
    it('V9testOnStatus001', 0, function () {
        console.log(TAG + "************* V9testOnStatus001 start *************");
        console.log(TAG + "start watch status");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);
        try {
            g_object.on("status", null);
        } catch (error) {
            expect(error.code == 401).assertEqual(true);
            expect(error.message == "Parameter error. The type of 'callback' must be 'function'").assertEqual(true);
        }
        console.log(TAG + "watch success");
        console.log(TAG + "************* V9testOnStatus001 end *************");
    })

    /**
     * @tc.name: V9testOnStatus002
     * @tc.desc: object set several listener and can unWatch all watcher
     * @tc.type: FUNC
     */
    it('V9testOnStatus002', 0, function () {
        console.log(TAG + "************* V9testOnStatus002 start *************");
        console.log(TAG + "start watch status");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);
        expect(g_object.name == "Amy").assertEqual(true);
        g_object.on("status", statusCallback1);
        console.log(TAG + "watch success");
        console.log(TAG + "start call unwatch status");
        try {
            g_object.off("status", statusCallback2);
        } catch (error) {
            console.info(error);
            expect(error == undefined).assertEqual(true);
        }
        console.log(TAG + "unwatch success");
        console.log(TAG + "************* V9testOnStatus002 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name: V9testSave001
     * @tc.desc: test save local
     * @tc.type: FUNC
     */
    it('V9testSave001', 0, async function () {
        console.log(TAG + "************* V9testSave001 start *************");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);

        g_object.setSessionId("tmpsession1");
        expect("tmpsession1" == g_object.__sessionId).assertEqual(true);

        let result = await g_object.save("local");
        expect(result.sessionId == "tmpsession1").assertEqual(true);
        expect(result.version == g_object.__version).assertEqual(true);
        expect(result.deviceId == "local").assertEqual(true);

        g_object.setSessionId("");
        g_object.name = undefined;
        g_object.age = undefined;
        g_object.isVis = undefined;
        g_object.setSessionId("tmpsession1");

        expect(g_object.name == "Amy").assertEqual(true);
        expect(g_object.age == 18).assertEqual(true);
        expect(g_object.isVis == false).assertEqual(true);
        console.log(TAG + "************* V9testSave001 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name: V9testSave002
     * @tc.desc: test save local
     * @tc.type: FUNC
     */
    it('V9testSave002', 0, async function () {
        console.log(TAG + "************* V9testSave002 start *************");
        var g_object = distributedObject.create({name: "Amy", age: 18, isVis: false});
        expect(g_object == undefined).assertEqual(false);

        g_object.setSessionId("tmpsession1");
        expect("tmpsession1" == g_object.__sessionId).assertEqual(true);
        try {
            g_object.save(1234).then((result) => {
                expect(result.sessionId == "tmpsession1").assertEqual(true);
                expect(result.version == g_object.__version).assertEqual(true);
                expect(result.deviceId == "local").assertEqual(true);
            })
        } catch (error) {
            expect(error.message == "Parameter error. The type of 'deviceId' must be 'string'").assertEqual(true);
        }

        g_object.save("errorDeviceId").then((result) => {
            expect(result.sessionId == "tmpsession1").assertEqual(true);
            expect(result.version == g_object.__version).assertEqual(true);
            expect(result.deviceId == "local").assertEqual(true);
        }).catch((error) => {
            expect(error == undefined).assertEqual(true);
        });
        console.log(TAG + "************* V9testSave002 end *************");
        g_object.setSessionId("");
    })

    /**
     * @tc.name: V9testRevokeSave001
     * @tc.desc: test save local
     * @tc.type: FUNC
     */
    it('V9testRevokeSave001', 0, async function () {
        console.log(TAG + "************* V9testRevokeSave001 start *************");
        var g_object = distributedObject.create({ name: "Amy", age: 18, isVis: false });
        expect(g_object == undefined).assertEqual(false);

        g_object.setSessionId("123456");
        expect("123456" == g_object.__sessionId).assertEqual(true);

        let result = await g_object.save("local");
        expect(result.sessionId == "123456").assertEqual(true);
        expect(result.version == g_object.__version).assertEqual(true);
        expect(result.deviceId == "local").assertEqual(true);

        result = await g_object.revokeSave();

        g_object.setSessionId("");
        g_object.name = undefined;
        g_object.age = undefined;
        g_object.isVis = undefined;
        g_object.setSessionId("123456");
        
        console.info("result:" + g_object.name);
        console.info("result:" + g_object.age);
        console.info("result:" + g_object.isVis);
        console.info("result:" + result.sessionId);
        console.log(TAG + "************* V9testRevokeSave001 end *************");
    })
    
    console.log(TAG + "*************Unit Test End*************");
})