"""TRAE SOLO CN / TraeWork CN 本机登录后自动签到（Windows，Python 标准库）。

python trae_signin.py doctor                 # 离线检查，不联网
python trae_signin.py status                 # 只查今日状态
python trae_signin.py auto --dry-run         # 查询，不领取
python trae_signin.py auto                   # 未签才领取
python trae_signin.py silent                 # 同 auto，静默写 trae_signin.log

默认只读 %APPDATA%/TRAE SOLO CN/User/globalStorage/storage.json。
--auth-dir / TRAE_AUTH_DIR 可指定另一数据目录；不自动选择普通 Trae。
不会改写登录态或刷新令牌。协议对照本机 SOLO CN 0.2.2 main.js，并参考：
https://github.com/starxxy/workbuddy-trae-auto-signin
https://github.com/hiclaw168-163/auto-signin-kit
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


BASE_URL = "https://api.trae.cn"
API_PATH = "/trae/api/v2/ug/checkin_credits/"
AUTH_KEY = "iCubeAuthInfo://icube.cloudide"
STORAGE_PATH = Path("User") / "globalStorage" / "storage.json"
REQUEST_TIMEOUT = 30
BUDGET_SECONDS = 240  # 小于安装器的 PT5M，给日志收尾留一分钟。
RETRY_DELAYS = (5, 15, 30)
INPUT_LIMIT = 16 << 20
AUTH_LIMIT = 256 << 10
RESPONSE_LIMIT = 1 << 20
TZ_CN = timezone(timedelta(hours=8))

# byteCrypto.js 中的公开格式常量（两组掩码异或），不是用户密钥。
# 每份密文另带 32 字节随机种子；AES-CBC 解密后必须验证 SHA-512 摘要。
FORMAT_SALTS = {
    bytes.fromhex("746305100000"): bytes.fromhex(
        "4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524"
        "f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58"),
    bytes.fromhex("123920200203"): bytes.fromhex(
        "490cc21292b05d0cc06ccbe91fb92e21b5a7c538811dc85e27a96e28104e1cf"
        "69c7166efab232807390da78a8b91e49c44b49a43feb941a1e46f2656e613e47b"),
}
_sensitive_values = set()


class AuthError(Exception):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def _aes_cbc_decrypt(key, iv, ciphertext):
    """Windows CNG AES-128-CBC + PKCS7；不安装额外密码库。"""
    if sys.platform != "win32":
        raise AuthError("UNSUPPORTED_PLATFORM", "自动解密目前支持 Windows")
    import ctypes
    from ctypes import wintypes as wt

    bcrypt = ctypes.WinDLL("bcrypt.dll")
    handle = ctypes.c_void_p
    ptr = ctypes.c_void_p
    ulong = wt.ULONG
    declarations = {
        "BCryptOpenAlgorithmProvider": [ctypes.POINTER(handle), wt.LPCWSTR, wt.LPCWSTR, ulong],
        "BCryptSetProperty": [handle, wt.LPCWSTR, ptr, ulong, ulong],
        "BCryptGenerateSymmetricKey": [handle, ctypes.POINTER(handle), ptr, ulong, ptr, ulong, ulong],
        "BCryptDecrypt": [handle, ptr, ulong, ptr, ptr, ulong, ptr, ulong, ctypes.POINTER(ulong), ulong],
        "BCryptDestroyKey": [handle],
        "BCryptCloseAlgorithmProvider": [handle, ulong],
    }
    for name, args in declarations.items():
        function = getattr(bcrypt, name)
        function.argtypes = args
        function.restype = wt.LONG

    def check(status):
        if status != 0:
            raise AuthError("DECRYPT_FAILED", "登录态解密失败，请检查客户端版本或重新登录")

    algorithm, symmetric_key = handle(), handle()
    key_buffer = ctypes.create_string_buffer(key, len(key))
    output = ctypes.create_string_buffer(len(ciphertext))
    try:
        check(bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(algorithm), "AES", None, 0))
        mode = ctypes.create_unicode_buffer("ChainingModeCBC")
        check(bcrypt.BCryptSetProperty(algorithm, "ChainingMode", mode, ctypes.sizeof(mode), 0))
        check(bcrypt.BCryptGenerateSymmetricKey(
            algorithm, ctypes.byref(symmetric_key), None, 0, key_buffer, len(key), 0))
        iv_buffer = ctypes.create_string_buffer(iv, len(iv))
        source = ctypes.create_string_buffer(ciphertext, len(ciphertext))
        size = ulong()
        check(bcrypt.BCryptDecrypt(symmetric_key, source, len(ciphertext), None,
                                  iv_buffer, len(iv), output, len(output),
                                  ctypes.byref(size), 1))  # BCRYPT_BLOCK_PADDING
        return output.raw[:size.value]
    finally:
        ctypes.memset(key_buffer, 0, len(key_buffer))
        ctypes.memset(output, 0, len(output))
        if symmetric_key:
            bcrypt.BCryptDestroyKey(symmetric_key)
        if algorithm:
            bcrypt.BCryptCloseAlgorithmProvider(algorithm, 0)


def decrypt_auth(value):
    if not isinstance(value, str) or not value or len(value) > AUTH_LIMIT:
        raise AuthError("INVALID_FORMAT", "登录态字段格式无效")
    try:
        envelope = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise AuthError("INVALID_FORMAT", "登录态不是有效的 base64") from None
    salt = FORMAT_SALTS.get(envelope[:6])
    if salt is None:
        raise AuthError("UNSUPPORTED_ENVELOPE", "尚不支持此登录态加密格式，请检查客户端版本")
    ciphertext = envelope[38:]
    if len(envelope) < 118 or not ciphertext or len(ciphertext) % 16:
        raise AuthError("INVALID_FORMAT", "登录态密文长度无效")
    derived = hashlib.sha512(hashlib.sha512(envelope[6:38]).digest() + salt).digest()
    plaintext = _aes_cbc_decrypt(derived[:16], derived[16:32], ciphertext)
    if len(plaintext) <= 64 or not hmac.compare_digest(
            plaintext[:64], hashlib.sha512(plaintext[64:]).digest()):
        raise AuthError("DECRYPT_FAILED", "登录态完整性校验失败，请检查客户端版本或重新登录")
    try:
        auth = json.loads(plaintext[64:].decode("utf-8"))
    except (ValueError, UnicodeError):
        raise AuthError("INVALID_FORMAT", "登录态解密后不是有效 JSON") from None
    if not isinstance(auth, dict):
        raise AuthError("INVALID_FORMAT", "登录态必须为 JSON 对象")
    return auth


def auth_directory(override=None):
    configured = override or os.environ.get("TRAE_AUTH_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    appdata = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    return appdata / "TRAE SOLO CN"


def _read_storage(path):
    try:
        with path.open("rb") as handle:
            raw = handle.read(INPUT_LIMIT + 1)
    except FileNotFoundError:
        raise AuthError("NO_AUTH", "未找到 SOLO CN 登录数据，请先登录 TRAE SOLO CN 或设置 --auth-dir") from None
    except OSError:
        raise AuthError("READ_FAILED", "无法读取 SOLO CN 登录数据，请检查目录权限") from None
    if len(raw) > INPUT_LIMIT:
        raise AuthError("INVALID_FORMAT", "storage.json 超过读取上限")
    try:
        storage = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeError):
        raise AuthError("INVALID_FORMAT", "storage.json 不是有效 JSON，请稍后重试") from None
    if not isinstance(storage, dict):
        raise AuthError("INVALID_FORMAT", "storage.json 必须为 JSON 对象")
    return storage


def _safe_header(value):
    return (isinstance(value, str) and 0 < len(value) <= 1024
            and all(32 <= ord(char) <= 126 for char in value))


def _token_expiry(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        expiry = payload.get("exp") if isinstance(payload, dict) else None
        if type(expiry) in (int, float) and math.isfinite(expiry) and 0 < expiry < 253402300800:
            return float(expiry)
    except (ValueError, UnicodeError, binascii.Error):
        pass
    return None


def _stored_expiry(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (ValueError, OverflowError, OSError):
        return None


def load_session(auth_dir=None):
    root = auth_directory(auth_dir)
    storage = _read_storage(root / STORAGE_PATH)
    value = storage.get(AUTH_KEY)
    if not value:
        raise AuthError("NO_AUTH", "SOLO CN 尚未保存登录态，请先登录 TRAE SOLO CN")
    auth = decrypt_auth(value)
    token = auth.get("token")
    if isinstance(token, str) and token:
        _sensitive_values.add(token)
    if (not isinstance(token, str) or not 0 < len(token) <= 32768
            or re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token) is None):
        raise AuthError("INVALID_FORMAT", "登录态缺少有效 access token")
    account = auth.get("account")
    if not isinstance(account, dict) or account.get("scope") != "marscode":
        raise AuthError("UNSUPPORTED_ACCOUNT", "签到仅支持 TRAE 中国版个人账号（marscode）")
    # 使用客户端持久化的设备标识，不生成新指纹；具体 key 与客户端保持一致。
    prefix = "iCubeAuthInfo://icube-dc:"
    device_ids = [key[len(prefix):] for key in storage if key.startswith(prefix)]
    if len(device_ids) != 1 or not _safe_header(device_ids[0]):
        raise AuthError("NO_DEVICE_ID", "登录数据缺少设备标识，请打开 TRAE SOLO CN 后重试")
    device_id = device_ids[0]
    expiries = [value for value in (_token_expiry(token), _stored_expiry(auth.get("expiredAt")))
                if value is not None]
    expiry = min(expiries) if expiries else None
    if expiry is not None and expiry <= time.time():
        raise AuthError("EXPIRED", "本地 access token 已过期，请打开 TRAE SOLO CN 更新登录态")
    return {"token": token, "device_id": device_id,
            "auth_dir": str(root), "token_expires_at": expiry}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 登录态只发往固定官方 API，重定向按失败处理。


class Api:
    def __init__(self, session):
        self.headers = {"Authorization": "Cloud-IDE-JWT " + session["token"],
                        "Content-Type": "application/json", "Accept": "application/json",
                        "x-device-id": session["device_id"]}
        self.opener = urllib.request.build_opener(_NoRedirect())
        self.deadline = time.monotonic() + BUDGET_SECONDS

    def _request(self, operation):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return -1, None
        request = urllib.request.Request(BASE_URL + API_PATH + operation,
                                         data=b'{"req_source":2}',
                                         headers=self.headers, method="POST")
        try:
            with self.opener.open(request, timeout=min(REQUEST_TIMEOUT, remaining)) as response:
                code, raw = response.status, response.read(RESPONSE_LIMIT + 1)
        except urllib.error.HTTPError as exc:
            code = exc.code
            try:
                raw = exc.read(RESPONSE_LIMIT + 1)
            except OSError:
                raw = b""
            finally:
                exc.close()
        except (urllib.error.URLError, OSError):
            return 0, None
        if len(raw) > RESPONSE_LIMIT:
            return code, None
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError):
            payload = None
        return code, payload

    def status(self, retry=True):
        for attempt in range(len(RETRY_DELAYS) + 1):
            code, body = self._request("status")
            if (not retry or (code not in (0, 429) and not 500 <= code <= 599)
                    or attempt == len(RETRY_DELAYS)):
                return code, body
            delay = RETRY_DELAYS[attempt]
            if self.deadline - time.monotonic() <= delay + REQUEST_TIMEOUT:
                return code, body
            time.sleep(delay)
        return code, body

    def claim(self):
        # 写请求只发一次。超时后查状态确认，下一触发点再处理仍未签的情况。
        return self._request("claim")


def result(name, report, **extra):
    return {"platform": "trae-solo-cn", "result": name, "report": report,
            "needs_attention": name not in ("OK", "CLAIMED", "ALREADY", "INACTIVE", "DRY_RUN"),
            **extra}


def _request_error(code, body, operation):
    if code == -1:
        return result("TIMEOUT", "本次运行的时间预算已用完")
    if code == 0:
        return result("NETWORK", operation + "失败：网络不可达或超时")
    if code == 401:
        return result("AUTH_REJECTED", "服务端拒绝登录态，请打开 TRAE SOLO CN 检查登录", http=code)
    if code == 403:
        return result("FORBIDDEN", operation + "被服务端拒绝，请检查账号或活动条件", http=code)
    if code != 200:
        return result("ERROR", operation + "失败：HTTP %s" % code, http=code)
    if not isinstance(body, dict):
        return result("PROTOCOL_ERROR", operation + "响应不是有效 JSON 对象", http=code)
    if "code" in body and (type(body["code"]) not in (int, float)
                           or not math.isfinite(body["code"])):
        return result("PROTOCOL_ERROR", operation + "响应业务码格式无效", http=code)
    if body.get("code", 0) != 0:
        return result("BUSINESS_ERROR", operation + "未成功，业务码 %s" % body["code"],
                      http=code, code=body["code"])
    return None


def _status_error(code, body):
    error = _request_error(code, body, "查询签到状态")
    if error:
        return error
    if type(body.get("enable")) is not bool or type(body.get("checked_in")) is not bool:
        return result("PROTOCOL_ERROR", "签到状态缺少布尔 enable / checked_in 字段")
    if "did_checked_in" in body and type(body["did_checked_in"]) is not bool:
        return result("PROTOCOL_ERROR", "签到状态 did_checked_in 字段格式无效")
    return None


def _credits(body):
    # 服务端决定奖励数，不在脚本里假定每天固定奖励。
    return {key: body[key] for key in ("credits", "extra_credits")
            if type(body.get(key)) in (int, float) and math.isfinite(body[key]) and body[key] >= 0}


def run_daily(api, action="auto", dry_run=False, once=False):
    code, status = api.status(retry=not once)
    error = _status_error(code, status)
    if error:
        return error
    already = status["checked_in"] or status.get("did_checked_in") is True
    details = {"enable": status["enable"], "checked_in": status["checked_in"],
               "did_checked_in": status.get("did_checked_in", False), **_credits(status)}
    if action == "status":
        return result("OK", "今日已签到" if already else "今日尚未签到", **details)
    if already:
        return result("ALREADY", "今日已签到", **details)
    if not status["enable"]:
        return result("INACTIVE", "当前未开放签到活动", **details)
    if dry_run:
        return result("DRY_RUN", "今日可签到（仅查询，尚未领取）", **details)
    code, claim = api.claim()
    error = _request_error(code, claim, "领取签到奖励")
    if error and error["result"] not in ("NETWORK", "ERROR", "BUSINESS_ERROR", "PROTOCOL_ERROR"):
        return error
    # 领取成功及网络结果不明时都回查，绝不把不完整响应当成成功。
    verify_code, verified = api.status(retry=not once)
    verify_error = _status_error(verify_code, verified)
    if not verify_error and (verified["checked_in"] or verified.get("did_checked_in") is True):
        return result("CLAIMED", "签到已完成，已回查确认今日签到状态", checked_in=verified["checked_in"],
                      did_checked_in=verified.get("did_checked_in", False),
                      **_credits(verified))
    if error:
        return error
    return result("PENDING", "领取请求已提交，但尚未确认签到成功，下次任务会重新查询",
                  verification=verify_error["result"] if verify_error else "NOT_CHECKED_IN")


def emit(out, action):
    payload = json.dumps(out, ensure_ascii=False)
    for secret in _sensitive_values:
        payload = payload.replace(secret, "[REDACTED]")
    if action != "silent" and sys.stdout is not None:
        try:
            print(payload)
            return
        except (UnicodeError, OSError):
            pass
    if action == "silent" and out["result"] in ("ALREADY", "INACTIVE") and not (
            os.environ.get("TRAE_SIGNIN_LOG_EMPTY", "").lower() in ("1", "true", "yes", "on")):
        return
    default_log = Path(__file__).resolve().with_name("trae_signin.log")
    log = Path(os.environ.get("TRAE_SIGNIN_LOG") or default_log).expanduser()
    line = "[%s] %s\n" % (datetime.now(TZ_CN).strftime("%Y-%m-%d %H:%M:%S%z"), payload)
    try:
        with log.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        if log == default_log:
            raise
        with default_log.open("a", encoding="utf-8") as handle:
            handle.write(line)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", nargs="?", default="auto", choices=("doctor", "status", "auto", "silent"))
    parser.add_argument("--auth-dir", help="TRAE SOLO CN 数据目录，内含 User/globalStorage/storage.json")
    parser.add_argument("--dry-run", action="store_true", help="只查询，不领取")
    parser.add_argument("--once", action="store_true", help="查询不做网络重试")
    args = parser.parse_args(argv)
    try:
        session = load_session(args.auth_dir)
        if args.action == "doctor":
            expiry = session["token_expires_at"]
            out = result("OK", "本地 SOLO CN 登录态可解密；尚未验证服务端认证", auth_dir=session["auth_dir"],
                         device_identity=True, decrypted=True,
                         token_expires_at=datetime.fromtimestamp(expiry, TZ_CN).isoformat() if expiry else None)
        else:
            out = run_daily(Api(session), args.action, args.dry_run, args.once)
    except AuthError as exc:
        out = result("NO_AUTH" if exc.reason == "NO_AUTH" else "AUTH_ERROR", str(exc), reason=exc.reason)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        out = result("ERROR", "脚本运行异常（%s）" % type(exc).__name__)
    emit(out, args.action)
    return 1 if out["needs_attention"] else 0


if __name__ == "__main__":
    sys.exit(main())
