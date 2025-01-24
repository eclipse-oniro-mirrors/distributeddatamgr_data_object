/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file expect in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
import { describe, beforeEach, afterEach, beforeAll, afterAll, it, expect } from 'deccjsunit/index'
import collaboration_edit from "@ohos.data.collaborationEditObject"
import ability_featureAbility from '@ohos.ability.featureAbility'
 
const TAG = "[CollaborationEdit_JsTest]"
const DOC_CONFIG = {name: "doc_test"}
const EDIT_UNIT_NAME = "top"
 
var context = ability_featureAbility.getContext()
var editObject = undefined;
var editUnit = undefined;
 
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
 
describe('collaborationUndoRedoTest', () => {
    beforeAll(async () => {
      console.log(TAG + "beforeAll");
    })
 
    beforeEach(async () => {
      console.log(TAG + "beforeEach");
      try {
        editObject = collaboration_edit.getCollaborationEditObject(context, DOC_CONFIG);
        editUnit = editObject.getEditUnit(EDIT_UNIT_NAME);
      } catch (err) {
        console.log(TAG + "get edit object failed. err: %s", err.message);
      }
    })
 
    afterEach(async () => {
      console.log(TAG + "afterEach");
      try {
        collaboration_edit.deleteCollaborationEditObject(context, DOC_CONFIG);
        console.log(TAG + "delete edit object successfully");
      } catch (err) {
        console.log(TAG + "delete edit object failed. err: %s", err.message);
        expect().assertFail();
      }
    })
 
    afterAll(async () => {
      console.log(TAG + "afterAll");
    })

    /**
     * @tc.number CollaborationEdit_UndoRedo_0001
     * @tc.name getUndoRedoManager when editUnitName is non-empty, captureTimeout is float
     * @tc.desc 
     *  1. editUnitName is any non-empty string
     *  2. captureTimeout is float
     */
    it("CollaborationEdit_UndoRedo_0001", 0, async () => {
      console.log(TAG + "*****************CollaborationEdit_UndoRedo_0001 Start*****************");
      expect(editUnit !== undefined).assertTrue();
      let undoManager = undefined;
      try {
        // captureTimeout非整数，向下取整
        undoManager = editObject?.getUndoRedoManager("notFound", {captureTimeout: 500.95});
      } catch (err) {
        console.log(TAG + "getUndoRedoManager failed. err: %s", err);
      }
      expect(undoManager !== undefined).assertTrue();
    })

    /**
     * @tc.number CollaborationEdit_UndoRedo_0002
     * @tc.name getUndoRedoManager when captureTimeout is negative
     * @tc.desc 
     *  1. captureTimeout is negative, then check 401 error code
     */
    it("CollaborationEdit_UndoRedo_0002", 0, async () => {
      console.log(TAG + "*****************CollaborationEdit_UndoRedo_0002 Start*****************");
      expect(editUnit !== undefined).assertTrue();
      let undoManager = undefined;
      let errCode = "";
      try {
        undoManager = editObject?.getUndoRedoManager("top", {captureTimeout: -1});
      } catch (err) {
        console.log(TAG + "getUndoRedoManager failed. err: %s", err);
        errCode = err.code;
      }
      expect(undoManager).assertUndefined();
      expect(errCode).assertEqual("401");
    })

    /**
     * @tc.number CollaborationEdit_UndoRedo_0003
     * @tc.name Noraml case of undo/redo after setAttributes
     * @tc.desc 
     *  1. get undoRedoManager
     *  2. construct a node and insert it into edit unit
     *  3. wait for 500ms
     *  4. set attributes into the node, then check attributes
     *  5. call undo, then check attributes undefined
     *  6. call redo, then check attributes
     */
    it("CollaborationEdit_UndoRedo_0003", 0, async () => {
      console.log(TAG + "*****************CollaborationEdit_UndoRedo_0003 Start*****************");
      expect(editUnit !== undefined).assertTrue();
      let undoManager = undefined;
      try {
        undoManager = editObject?.getUndoRedoManager("top", {captureTimeout: 500});
        expect(undoManager !== undefined).assertTrue();
        let node1 = new collaboration_edit.Node("p1");
        editUnit?.insertNodes(0, [node1]);
        let nodeList = editUnit?.getChildren(0, 1);
        expect(nodeList !== undefined).assertTrue();
        expect(1).assertEqual(nodeList?.length);
 
        // sleep for 500ms then set attributes
        await sleep(500);
        node1.setAttributes({"align": "left", "width": 36, "italics": true});
        let attrs = node1.getAttributes();
        expect(attrs["align"]).assertEqual("left");
        expect(attrs["width"]).assertEqual("36");
        expect(attrs["italics"]).assertEqual("true");
 
        // undo
        undoManager?.undo();
        attrs = node1.getAttributes();
        expect(attrs["align"]).assertUndefined();
        expect(attrs["width"]).assertUndefined();
        expect(attrs["italics"]).assertUndefined();
 
        // redo
        undoManager?.redo();
        attrs = node1.getAttributes();
        expect(attrs["align"]).assertEqual("left");
        expect(attrs["width"]).assertEqual("36");
        expect(attrs["italics"]).assertEqual("true");
      } catch (err) {
        console.log(TAG + "CollaborationEdit_UndoRedo_0003 failed. err: %s", err);
        expect().assertFail();
      }
    })

    /**
     * @tc.number CollaborationEdit_UndoRedo_0004
     * @tc.name Noraml case of undo/redo after insertTexts
     * @tc.desc 
     *  1. get undoRedoManager
     *  2. construct a node and insert it into edit unit
     *  3. wait for 500ms
     *  4. insert texts into the node, then check clock of the text
     *  5. call undo, then check result
     *  6. call redo, then check clock of the texts children
     */
    it("CollaborationEdit_UndoRedo_0004", 0, async () => {
      console.log(TAG + "*****************CollaborationEdit_UndoRedo_0004 Start*****************");
      expect(editUnit !== undefined).assertTrue();
      let undoManager = undefined;
      try {
        undoManager = editObject?.getUndoRedoManager("top", {captureTimeout: 500});
        expect(undoManager !== undefined).assertTrue();
        let node1 = new collaboration_edit.Node("p1");
        editUnit?.insertNodes(0, [node1]);
        let nodeList = editUnit?.getChildren(0, 1);
        expect(nodeList !== undefined).assertTrue();
        expect(1).assertEqual(nodeList?.length);
 
        // sleep for 500ms then insert Texts
        await sleep(500);
        let text1 = new collaboration_edit.Text();
        let text2 = new collaboration_edit.Text();
        node1.insertTexts(0, [text1, text2]);
        nodeList = node1.getChildren(0, 2);
        expect(nodeList !== undefined).assertTrue();
        expect(2).assertEqual(nodeList.length);
        if (nodeList !== undefined) {
          expect(nodeList[0].getId().clock).assertEqual(1);
          expect(nodeList[1].getId().clock).assertEqual(2);
        }
        let jsonStr = node1.getJsonResult();
        expect(jsonStr !== undefined).assertTrue();
        expect(jsonStr).assertEqual("{\"array\":[{\"ele\":{\"name\":\"p1\",\"attr\":{},\"children\":[{\"text\":\"[]\"},{\"text\":\"[]\"}]}}]}");
 
        // undo
        undoManager?.undo();
        jsonStr = node1.getJsonResult();
        expect(jsonStr !== undefined).assertTrue();
        expect(jsonStr).assertEqual("{\"array\":[{\"ele\":{\"name\":\"p1\",\"attr\":{},\"children\":[]}}]}");
 
        // redo
        undoManager?.redo();
        nodeList = node1.getChildren(0, 2);
        expect(nodeList !== undefined).assertTrue();
        expect(2).assertEqual(nodeList.length);
        if (nodeList !== undefined) {
          expect(nodeList[0].getId().clock).assertEqual(3);
          expect(nodeList[1].getId().clock).assertEqual(4);
        }
        jsonStr = node1.getJsonResult();
        expect(jsonStr !== undefined).assertTrue();
        expect(jsonStr).assertEqual("{\"array\":[{\"ele\":{\"name\":\"p1\",\"attr\":{},\"children\":[{\"text\":\"[]\"},{\"text\":\"[]\"}]}}]}");
      } catch (err) {
        console.log(TAG + "CollaborationEdit_UndoRedo_0004 failed. err: %s", err);
        expect().assertFail();
      }
    })

    /**
     * @tc.number CollaborationEdit_UndoRedo_0005
     * @tc.name Noraml case of undo/redo after inserting strings into text
     * @tc.desc 
     *  1. get undoRedoManager
     *  2. construct a node and insert it into edit unit
     *  3. construct a text and insert it into the node
     *  4. wait for 500ms
     *  5. insert strings into texts and check result
     *  5. call undo, then check the content of the text is empty
     *  6. call redo, then check the content of the text
     */
    it("CollaborationEdit_UndoRedo_0005", 0, async () => {
      console.log(TAG + "*****************CollaborationEdit_UndoRedo_0005 Start*****************");
      expect(editUnit !== undefined).assertTrue();
      let undoManager = undefined;
      try {
        undoManager = editObject?.getUndoRedoManager("top", {captureTimeout: 500});
        expect(undoManager !== undefined).assertTrue();
        let node1 = new collaboration_edit.Node("p1");
        editUnit?.insertNodes(0, [node1]);
        let nodeList = editUnit?.getChildren(0, 1);
        expect(nodeList !== undefined).assertTrue();
        expect(1).assertEqual(nodeList?.length);
 
        // insert Texts
        let text = new collaboration_edit.Text();
        node1.insertTexts(0, [text]);
 
        // sleep for 500ms then insert strings into text
        await sleep(500);
        text.insert(0, "abc");
        text.insert(3, "def", {"color": "red", "font-size":12});
        let plainText = text.getPlainText();
        expect(plainText).assertEqual("abcdef");
        let jsonStr = text.getJsonResult();
        expect(jsonStr).assertEqual("[{\"insert\":\"abc\"},{\"insert\":\"def\",\"attributes\":{\"color\":\"red\",\"font-size\":\"12\"}}]");
 
        // undo
        undoManager?.undo();
        plainText = text.getPlainText();
        expect(plainText).assertEqual("");
        jsonStr = text.getJsonResult();
        expect(jsonStr).assertEqual("[]");
 
        // redo
        undoManager?.redo();
        plainText = text.getPlainText();
        expect(plainText).assertEqual("abcdef");
        jsonStr = text.getJsonResult();
        expect(jsonStr).assertEqual("[{\"insert\":\"abc\"},{\"insert\":\"def\",\"attributes\":{\"color\":\"red\",\"font-size\":\"12\"}}]");
 
      } catch (err) {
        console.log(TAG + "CollaborationEdit_UndoRedo_0005 failed. err: %s", err);
        expect().assertFail();
      }
    })
})