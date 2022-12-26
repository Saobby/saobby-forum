from flask import *
import basic
import database_action
import hashlib
import requests
import time
import json
import random

app = Flask(__name__)
CAPTCHA_URL = "https://captcha.saobby.com/api/check_token"
DEF_AVATAR = "https://cfstatic.saobby.com/i/default_avatar.png"


def get_md5(sth: str):
    return hashlib.md5(sth.encode("utf-8")).hexdigest()


def gen_returns(success=True, message="OK", data=None, **kwargs):
    ret = {"success": success, "message": message, "data": data}
    for k, v in kwargs.items():
        ret[k] = v
    return json.dumps(ret)


def gen_random_str(lens=64):
    ret = ""
    for i in range(lens):
        ret += random.choice("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return ret


def check_captcha(token):
    ret = requests.post(CAPTCHA_URL, data={"s-captcha-token": token})
    ret = json.loads(ret.text)
    if not ret["validity"]:
        return False
    return True


@app.route("/api/login", methods=["post"])
def api_login():
    if request.json is None:
        return abort(400)
    username = request.json.get("username")
    password = request.json.get("password")
    captcha_token = request.json.get("captcha_token")
    if None in [username, password, captcha_token]:
        return abort(400)
    if check_captcha(captcha_token) is False:
        return gen_returns(False, "验证码错误")
    db_session = database_action.get_session()
    user_obj = db_session.query(database_action.Users).filter_by(username=username).first()
    if user_obj is None:
        db_session.close()
        return gen_returns(False, "该用户不存在")
    if get_md5(password) != user_obj.password:
        db_session.close()
        return gen_returns(False, "密码错误")
    ret_data = {"access_token": user_obj.access_token,
                "avatar_url": user_obj.avatar_url,
                "username": user_obj.username}
    db_session.close()
    return gen_returns(True, "OK!", ret_data)


@app.route("/api/register", methods=["post"])
def api_reg():
    if request.json is None:
        return abort(400)
    username = request.json.get("username")
    password = request.json.get("password")
    captcha_token = request.json.get("captcha_token")
    if None in [username, password, captcha_token]:
        return abort(400)
    if len(username) < 1:
        return gen_returns(False, "用户名太短!")
    if len(username) > 32:
        return gen_returns(False, "用户名太长!最长只能为32个字符!")
    if len(password) < 6:
        return gen_returns(False, "密码太短!至少需要6个字符!")
    if len(password) > 32:
        return gen_returns(False, "密码太长!最长只能为32个字符!")
    if not check_captcha(captcha_token):
        return gen_returns(False, "验证码错误")
    db_session = database_action.get_session()
    if db_session.query(database_action.Users).filter_by(username=username).first():
        db_session.close()
        return gen_returns(False, "此用户名已被占用!请换一个用户名后再试")
    access_token = gen_random_str()
    psw_md5 = get_md5(password)
    ip_addr = request.headers.get("CF-Connecting-IP")
    if ip_addr is None:
        ip_addr = request.headers.get("x-forwarded-for")
    ug = db_session.query(database_action.UserGroup).filter_by(is_default=True, is_deleted=False)
    ugs = []
    for user_group in ug:
        ugs.append(user_group.id)
    db_session.add(database_action.Users(username, psw_md5, access_token, DEF_AVATAR, "这个人还没有设置个性签名",
                                         str(time.time()), ip_addr, json.dumps(ugs), "[]", "[]", "{}"))
    db_session.commit()
    db_session.close()
    return gen_returns(True, "OK!", {"access_token": access_token, "avatar_url": DEF_AVATAR, "username": username})


@app.errorhandler(400)
def error_400(err):
    return gen_returns(False, "参数错误"), 400


@app.errorhandler(404)
def error_404(err):
    return gen_returns(False, "Page not found."), 404


@app.errorhandler(500)
def error_500(err):
    return gen_returns(False, "服务器内部错误!请发邮件到bugs@saobby.com以报告问题"), 500


@app.after_request
def add_header(r):
    if request.headers.get("origin") is not None:
        r.headers["Access-Control-Allow-Origin"] = request.headers.get("origin")
    r.headers["Access-Control-Allow-Headers"] = "*"
    r.headers["Access-Control-Allow-Credentials"] = "true"
    r.headers["Access-Control-Allow-Methods"] = "*"
    r.headers["Access-Control-Max-Age"] = "600"
    r.headers["Access-Control-Expose-Headers"] = "*"
    r.headers["Content-Type"] = "application/json; charset=utf-8"
    if "/api/" in request.path:
        r.headers["Content-Type"] = "application/json; charset=utf-8"
    return r


def ts2str(ts, fmt="%Y-%m-%d %H:%M:%S"):
    time_array = time.localtime(ts)
    return time.strftime(fmt, time_array)


if __name__ == "__main__":
    app.run(port=14514, debug=True)
