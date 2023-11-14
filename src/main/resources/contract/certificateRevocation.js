
'use strict';

/*合约中的关键字*/
const key_g = {
  INIT: 'init',
  BLACKLIST: 'blacklist'
};

/*合约版本号*/
const version_g = '1.0.0';

/*合约操作者*/
const sender_g = Chain.msg.sender;

/*
 * 判断值是否是false
 * 参数：
 *   obj_：对象
 * 返回值：
 *   是false：true
 *   不是false: false
 */
function _isFalse(obj_) {
  return false === obj_;
}

/*
 * 判断值是否是undefined
 * 参数：
 *   obj_：对象
 * 返回值：
 *   是undefined：true
 *   不是undefined: false
 */
function _isNull(obj_) {
  return undefined === obj_;
}

/*
 * 地址有效性校验
 * 参数：
 *   addr_：string 账号地址
 *   ckChainCode_：bool 是否校验链码
 *   ckExist_：bool 是否校验账号是否在链上
 * 返回值：
 *   成功：true
 *   失败：false
 */
function _ckAddr(addr_, ckChainCode_, ckExist_) {
  return (_isNull(ckChainCode_) ? Utils.addressCheck(addr_) : Utils.addressCheck(addr_, ckChainCode_)) && (_isNull(ckExist_) ? true : !_isFalse(Chain.getAccountPrivilege(addr_)));
}

/*
 * JSON转换为字符串
 * 参数：
 *   jsn_: JSON对象
 * 返回值：
 *  字符串
 */
function _jsn2Str(jsn_) {
  return JSON.stringify(jsn_);
}

/*
 * 保存到区块链
 * 参数：
 *   key_：string 关键字
 *   val_：string 内容
 */
function _save(key_, val_) {
  Chain.store(key_, val_);
}

/*
 * 保存到区块链
 * 参数：
 *   key_：string, 关键字
 *   obj_：JSON对象
 */
function _saveObj(key_, obj_) {
  let str_ = JSON.stringify(obj_);
  _save(key_, str_);
}

/*
 * 读取区块链信息
 * 参数：
 *   key_：string 关键字
 * 返回值：
 *   string
 */
function _load(key_) {
  return Chain.load(key_);
}

/*
 * 读取区块链信息
 * 参数：
 *   key_：string 关键字
 * 返回值：
 *   JSON对象
 */
function _loadObj(key_) {
  let val_ = _load(key_);
  if (_isFalse(val_)) {
    return false;
  }
  return JSON.parse(val_);
}

function _statusVal(status_) {
  return {
    'status': status_
  };
}

/**
 * 判断是否有操作权限
 * 参数：
 *   bid_: string bid地址标识
 * 返回值：
 *   失败：抛异常
 **/
function _checkPrivilege() {
  /*校验操作者是否是发行人*/
  let issuer = _loadObj(key_g.INIT).issuer;
  Utils.assert(sender_g === issuer, '凭证的操作者必须是issuer, bid是' + issuer + '.');
}

/*
 * 添加至黑名单
 * 参数：
 *   bid_: string bid地址标识
 */
function addToBlackList(bid_) {
  Utils.assert(_ckAddr(bid_), 'bid地址标识无效.');
  let status_ = _statusVal(true);
  let val_ = _jsn2Str(status_);
  _save(bid_, val_);
  
  Chain.tlog('addToBlackList', sender_g, bid_, val_);
}

/**
 * 查询合约指定的发行人
 * 返回值：
 *   string 发行人bid
 **/
function queryIssuer() {
  return _loadObj(key_g.INIT).issuer;
}

/**
 * 查询合约版本
 * 返回值
 *   string 版本号
 **/
function queryVersion() {
  return _loadObj(key_g.INIT).version;
}

/**
 * 查询bid在黑名单中的状态
 * 参数：
 *   bid_：string bid地址标识
 * 返回值：
 *   JSON字符串  状态
 * 
 **/
function queryStatus(bid_) {
  let status_ = _load(bid_);
  return _isFalse(status_) ? _jsn2Str(_statusVal(false)) : status_;
}


/*
 * 初始化函数
 * 参数：
 *   input_: string 入参
 */
function init(input_) {
  let input  = JSON.parse(input_);
  Utils.assert(_ckAddr(input.issuer), '参数issuer无效.');
  let init_val = {
    'issuer': input.issuer,
    'version': version_g
  };
  _saveObj(key_g.INIT, init_val);
}

/*
 * 主函数
 * 参数：
 *   input_: string 入参
 */
function main(input_) {
  let input  = JSON.parse(input_);
  let params = input.params;
  
  _checkPrivilege();
  
  switch (input.method) {
    case 'addToBlackList':
      addToBlackList(params.bid);
      break;
    default:
      throw 'Unknown method:  ' + input.method + '.';
  }
}

/*
 * 查询函数
 * 参数：
 *   input_: string 入参
 * 返回值：
 *   字符串
 */
function query(input_) {
  let input  = JSON.parse(input_);
  let params = input.params;
  
  let result = '';
  switch (input.method) {
    case 'queryIssuer':
      result = queryIssuer();
      break;
    case 'queryVersion':
      result = queryVersion();
      break;
    case 'queryStatus':
      result = queryStatus(params.bid);
      break;
    default:
      throw 'Unknown query: ' + input.method + '.';
  }
  return result;
}