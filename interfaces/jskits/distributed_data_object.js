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

const distributedObject = requireInternal('data.distributedDataObject');
const fs = requireInternal('file.fs');
const SESSION_ID = '__sessionId';
const VERSION = '__version';
const COMPLEX_TYPE = '[COMPLEX]';
const STRING_TYPE = '[STRING]';
const NULL_TYPE = '[NULL]';
const ASSET_KEYS = ['status', 'name', 'uri', 'path', 'createTime', 'modifyTime', 'size'];
const STATUS_INDEX = 0;
const ASSET_KEY_SEPARATOR = '.';
const JS_ERROR = 1;
const SDK_VERSION_8 = 8;
const SDK_VERSION_9 = 9;
const SESSION_ID_REGEX = /^\w+$/;
const SESSION_ID_MAX_LENGTH = 128;
const ASSETS_MAX_NUMBER = 50;
const HEAD_SIZE = 3;
const END_SIZE = 3;
const MIN_SIZE = HEAD_SIZE + END_SIZE + 3;
const REPLACE_CHAIN = '***';
const DEFAULT_ANONYMOUS = '******';

class Distributed {
  constructor(obj) {
    constructorMethod(this, obj);
  }

  setSessionId(sessionId) {
    if (sessionId == null || sessionId === '') {
      leaveSession(this.__sdkVersion, this.__proxy);
      return false;
    }
    if (this.__proxy[SESSION_ID] === sessionId) {
      return true;
    }
    leaveSession(this.__sdkVersion, this.__proxy);
    let object = joinSession(this.__sdkVersion, this.__proxy, this.__objectId, sessionId);
    if (object != null) {
      this.__proxy = object;
      return true;
    }
    return false;
  }

  on(type, callback) {
    onWatch(this.__sdkVersion, type, this.__proxy, callback);
    distributedObject.recordCallback(this.__sdkVersion, type, this.__objectId, callback);
  }

  off(type, callback) {
    offWatch(this.__sdkVersion, type, this.__proxy, callback);
    if (callback !== undefined || callback != null) {
      distributedObject.deleteCallback(this.__sdkVersion, type, this.__objectId, callback);
    } else {
      distributedObject.deleteCallback(this.__sdkVersion, type, this.__objectId);
    }
  }

  save(deviceId, callback) {
    if (this.__proxy[SESSION_ID] == null || this.__proxy[SESSION_ID] === '') {
      console.info('not join a session, can not do save');
      return JS_ERROR;
    }
    return this.__proxy.save(deviceId, this[VERSION], callback);
  }

  revokeSave(callback) {
    if (this.__proxy[SESSION_ID] == null || this.__proxy[SESSION_ID] === '') {
      console.info('not join a session, can not do revoke save');
      return JS_ERROR;
    }
    return this.__proxy.revokeSave(callback);
  }

  __proxy;
  __objectId;
  __version;
  __sdkVersion = SDK_VERSION_8;
}

function constructorMethod(result, obj) {
  result.__proxy = obj;
  Object.keys(obj).forEach(key => {
    Object.defineProperty(result, key, {
      enumerable: true,
      configurable: true,
      get: function () {
        return result.__proxy[key];
      },
      set: function (newValue) {
        result[VERSION]++;
        result.__proxy[key] = newValue;
      }
    });
  });
  Object.defineProperty(result, SESSION_ID, {
    enumerable: true,
    configurable: true,
    get: function () {
      return result.__proxy[SESSION_ID];
    },
    set: function (newValue) {
      result.__proxy[SESSION_ID] = newValue;
    }
  });
  result.__objectId = randomNum();
  result[VERSION] = 0;
  console.info('constructor success ');
}

function randomNum() {
  return distributedObject.sequenceNum();
}

function newDistributed(obj) {
  console.info('start newDistributed');
  if (obj == null) {
    console.error('object is null');
    return null;
  }
  return new Distributed(obj);
}

function getObjectValue(object, key) {
  console.info('start get ' + key);
  let result = object.get(key);
  if (typeof result === 'string') {
    if (result.startsWith(STRING_TYPE)) {
      result = result.substr(STRING_TYPE.length);
    } else if (result.startsWith(COMPLEX_TYPE)) {
      result = JSON.parse(result.substr(COMPLEX_TYPE.length));
    } else if (result.startsWith(NULL_TYPE)) {
      result = null;
    } else {
      console.error('error type');
    }
  }
  console.info('get success');
  return result;
}

function setObjectValue(object, key, newValue) {
  console.info('start set ' + key);
  if (typeof newValue === 'object') {
    let value = COMPLEX_TYPE + JSON.stringify(newValue);
    object.put(key, value);
  } else if (typeof newValue === 'string') {
    let value = STRING_TYPE + newValue;
    object.put(key, value);
  } else if (newValue == null) {
    let value = NULL_TYPE;
    object.put(key, value);
  } else {
    object.put(key, newValue);
  }
}

function isAsset(obj) {
  if (Object.prototype.toString.call(obj) !== '[object Object]') {
    return false;
  }
  let length = Object.prototype.hasOwnProperty.call(obj, ASSET_KEYS[STATUS_INDEX]) ? ASSET_KEYS.length : ASSET_KEYS.length - 1;
  if (Object.keys(obj).length !== length) {
    return false;
  }
  if (Object.prototype.hasOwnProperty.call(obj, ASSET_KEYS[STATUS_INDEX]) &&
    typeof obj[ASSET_KEYS[STATUS_INDEX]] !== 'number' && typeof obj[ASSET_KEYS[STATUS_INDEX]] !== 'undefined') {
    return false;
  }
  for (const key of ASSET_KEYS.slice(1)) {
    if (!Object.prototype.hasOwnProperty.call(obj, key) || typeof obj[key] !== 'string') {
      return false;
    }
  }
  return true;
}

function defineAsset(object, key, data) {
  Object.defineProperty(object, key, {
    enumerable: true,
    configurable: true,
    get: function () {
      return getAssetValue(object, key);
    },
    set: function (newValue) {
      setAssetValue(object, key, newValue);
    }
  });
  let asset = object[key];
  Object.keys(data).forEach(subKey => {
    if (data[subKey] !== '') {
      asset[subKey] = data[subKey];
    }
  });
}

function getAssetValue(object, key) {
  let asset = {};
  ASSET_KEYS.forEach(subKey => {
    Object.defineProperty(asset, subKey, {
      enumerable: true,
      configurable: true,
      get: function () {
        return getObjectValue(object, key + ASSET_KEY_SEPARATOR + subKey);
      },
      set: function (newValue) {
        setObjectValue(object, key + ASSET_KEY_SEPARATOR + subKey, newValue);
      }
    });
  });
  return asset;
}

function setAssetValue(object, key, newValue) {
  if (!isAsset(newValue)) {
    throw {
      code: 401,
      message: 'cannot set ' + key + ' by non Asset type data'
    };
  }
  Object.keys(newValue).forEach(subKey => {
    setObjectValue(object, key + ASSET_KEY_SEPARATOR + subKey, newValue[subKey]);
  });
}

function joinSession(version, obj, objectId, sessionId, context) {
  if (obj == null || sessionId == null || sessionId === '') {
    console.error('object is null');
    return null;
  }

  let object = null;
  if (context !== undefined || context != null) {
    object = distributedObject.createObjectSync(version, sessionId, objectId, context);
  } else {
    object = distributedObject.createObjectSync(version, sessionId, objectId);
  }

  if (object == null) {
    console.error('create fail');
    return null;
  }
  Object.keys(obj).forEach(key => {
    console.info('start define ' + key);
    if (isAsset(obj[key])) {
      defineAsset(object, key, obj[key]);
    } else {
      Object.defineProperty(object, key, {
        enumerable: true,
        configurable: true,
        get: function () {
          return getObjectValue(object, key);
        },
        set: function (newValue) {
          setObjectValue(object, key, newValue);
        }
      });
      if (obj[key] !== undefined) {
        object[key] = obj[key];
      }
    }
  });

  Object.defineProperty(object, SESSION_ID, {
    value: sessionId,
    configurable: true,
  });
  return object;
}

function leaveSession(version, obj) {
  console.info('start leaveSession');
  if (obj == null || obj[SESSION_ID] == null || obj[SESSION_ID] === '') {
    console.warn('object is null');
    return;
  }
  Object.keys(obj).forEach(key => {
    Object.defineProperty(obj, key, {
      value: obj[key],
      configurable: true,
      writable: true,
      enumerable: true,
    });
    if (isAsset(obj[key])) {
      Object.keys(obj[key]).forEach(subKey => {
        Object.defineProperty(obj[key], subKey, {
          value: obj[key][subKey],
          configurable: true,
          writable: true,
          enumerable: true,
        });
      });
    }
  });
  // disconnect,delete object
  distributedObject.destroyObjectSync(version, obj);
  delete obj[SESSION_ID];
}

function toBeAnonymous(name) {
  if (name.length <= HEAD_SIZE) {
    return DEFAULT_ANONYMOUS;
  }
  if (name.length < MIN_SIZE) {
    return name.substring(0, HEAD_SIZE) + REPLACE_CHAIN;
  }
  return name.substring(0, HEAD_SIZE) + REPLACE_CHAIN + name.substring(name.length - END_SIZE);
}

function onWatch(version, type, obj, callback) {
  console.info('start on ' + toBeAnonymous(obj[SESSION_ID]));
  if (obj[SESSION_ID] != null && obj[SESSION_ID] !== undefined && obj[SESSION_ID].length > 0) {
    distributedObject.on(version, type, obj, callback);
  }
}

function offWatch(version, type, obj, callback = undefined) {
  console.info('start off ' + toBeAnonymous(obj[SESSION_ID]) + ' ' + callback);
  if (obj[SESSION_ID] != null && obj[SESSION_ID] !== undefined && obj[SESSION_ID].length > 0) {
    if (callback !== undefined || callback != null) {
      distributedObject.off(version, type, obj, callback);
    } else {
      distributedObject.off(version, type, obj);
    }
  }
}

function newDistributedV9(context, obj) {
  console.info('start newDistributed');
  let checkparameter = function(parameter, type) {
    throw {
      code: 401,
      message :"Parameter error. The type of '" + parameter + "' must be '" + type + "'."};
  };
  if (typeof context !== 'object') {
    checkparameter('context', 'Context');
  }
  if (typeof obj !== 'object') {
    checkparameter('source', 'object');
  }
  if (obj == null) {
    console.error('object is null');
    return null;
  }
  return new DistributedV9(obj, context);
}

function appendPropertyToObj(result, obj) {
  result.__proxy = Object.assign(result.__proxy, obj);
  Object.keys(obj).forEach(key => {
    Object.defineProperty(result, key, {
      enumerable: true,
      configurable: true,
      get: function () {
        return result.__proxy[key];
      },
      set: function (newValue) {
        result.__proxy[key] = newValue;
      }
    });
  });
}

function getDefaultAsset(uri, distributedDir) {
  if (uri == null) {
    throw {
      code: 15400002,
      message: 'The asset uri to be set is null.'
    };
  }
  const fileName = uri.substring(uri.lastIndexOf('/') + 1);
  const filePath = distributedDir + '/' + fileName;
  let stat;
  try {
    stat = fs.statSync(filePath);
    return {
      name: fileName,
      uri: uri,
      path: filePath,
      createTime: stat.ctime.toString(),
      modifyTime: stat.mtime.toString(),
      size: stat.size.toString()
    };
  } catch (error) {
    console.error(error);
    return {
      name: '',
      uri: '',
      path: '',
      createTime: 0,
      modifyTime: 0,
      size: 0
    };
  }
}

class DistributedV9 {

  constructor(obj, context) {
    this.__context = context;
    constructorMethod(this, obj);
  }

  setSessionId(sessionId, callback) {
    if (typeof sessionId === 'function' || sessionId == null || sessionId === '') {
      leaveSession(this.__sdkVersion, this.__proxy);
      if (typeof sessionId === 'function') {
        return sessionId(this.__proxy);
      } else if (typeof callback === 'function') {
        return callback(null, this.__proxy);
      } else {
        return Promise.resolve(null, this.__proxy);
      }
    }
    if (this.__proxy[SESSION_ID] === sessionId) {
      if (typeof callback === 'function') {
        return callback(null, this.__proxy);
      } else {
        return Promise.resolve(null, this.__proxy);
      }
    }
    leaveSession(this.__sdkVersion, this.__proxy);
    if (sessionId.length > SESSION_ID_MAX_LENGTH || !SESSION_ID_REGEX.test(sessionId)) {
      throw {
        code: 401,
        message: 'The sessionId allows only letters, digits, and underscores(_), and cannot exceed 128 in length.'
      };
    }
    let object = joinSession(this.__sdkVersion, this.__proxy, this.__objectId, sessionId, this.__context);
    if (object != null) {
      this.__proxy = object;
      if (typeof callback === 'function') {
        return callback(null, this.__proxy);
      } else {
        return Promise.resolve(null, object);
      }
    } else {
      if (typeof callback === 'function') {
        return callback(null, null);
      } else {
        return Promise.reject(null, null);
      }
    }
  }

  on(type, callback) {
    onWatch(this.__sdkVersion, type, this.__proxy, callback);
    distributedObject.recordCallback(this.__sdkVersion, type, this.__objectId, callback);
  }

  off(type, callback) {
    offWatch(this.__sdkVersion, type, this.__proxy, callback);
    if (callback !== undefined || callback != null) {
      distributedObject.deleteCallback(this.__sdkVersion, type, this.__objectId, callback);
    } else {
      distributedObject.deleteCallback(this.__sdkVersion, type, this.__objectId);
    }
  }

  save(deviceId, callback) {
    if (this.__proxy[SESSION_ID] == null || this.__proxy[SESSION_ID] === '') {
      console.info('not join a session, can not do save');
      return JS_ERROR;
    }
    return this.__proxy.save(deviceId, this[VERSION], callback);
  }

  revokeSave(callback) {
    if (this.__proxy[SESSION_ID] == null || this.__proxy[SESSION_ID] === '') {
      console.info('not join a session, can not do revoke save');
      return JS_ERROR;
    }
    return this.__proxy.revokeSave(callback);
  }

  bindAssetStore(assetkey, bindInfo, callback) {
    if (this.__proxy[SESSION_ID] == null || this.__proxy[SESSION_ID] === '') {
      console.info('not join a session, can not do bindAssetStore');
      return JS_ERROR;
    }
    return this.__proxy.bindAssetStore(assetkey, bindInfo, callback);
  }

  setAsset(assetKey, uri) {
    if (this.__proxy[SESSION_ID] != null && this.__proxy[SESSION_ID] !== '') {
      throw {
        code: 15400003,
        message: 'SessionId has been set, and asset cannot be set.'
      };
    }
    if (!assetKey || !uri) {
      throw {
        code: 15400002,
        message: 'The property or uri of the asset is invalid.'
      };
    }

    let assetObj = {};
    const distributedDir = this.__context.distributedFilesDir;
    const asset = getDefaultAsset(uri, distributedDir);
    assetObj[assetKey] = [asset];
    assetObj[assetKey + '0'] = asset;
    appendPropertyToObj(this, assetObj);
    return Promise.resolve();
  }

  setAssets(assetsKey, uris) {
    if (this.__proxy[SESSION_ID] != null && this.__proxy[SESSION_ID] !== '') {
      throw {
        code: 15400003,
        message: 'SessionId has been set, and assets cannot be set.'
      };
    }
    if (!assetsKey) {
      throw {
        code: 15400002,
        message: 'The property of the assets is invalid.'
      };
    }
    if (!Array.isArray(uris) || uris.length <= 0 || uris.length > ASSETS_MAX_NUMBER) {
      throw {
        code: 15400002,
        message: 'The uri array of the set assets is not an array or the length is invalid.'
      };
    }
    for (let index = 0; index < uris.length; index++) {
      if (!uris[index]) {
        throw {
          code: 15400002,
          message: 'Uri in assets array is invalid.'
        };
      }
    }

    let assetObj = {};
    let assets = [];
    const distributedDir = this.__context.distributedFilesDir;
    for (let index = 0; index < uris.length; index++) {
      const asset = getDefaultAsset(uris[index], distributedDir);
      assets.push(asset);
      assetObj[assetsKey + index] = asset;
    }
    assetObj[assetsKey] = assets;
    appendPropertyToObj(this, assetObj);
    return Promise.resolve();
  }

  __context;
  __proxy;
  __objectId;
  __version;
  __sdkVersion = SDK_VERSION_9;
}

export default {
  createDistributedObject: newDistributed,
  create: newDistributedV9,
  genSessionId: randomNum
};
