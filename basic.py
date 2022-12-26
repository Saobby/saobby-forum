from functools import wraps
from flask import *
import json
import database_action


def gen_returns(success=True, message="OK", data=None, **kwargs):
    ret = {"success": success, "message": message, "data": data}
    for k, v in kwargs.items():
        ret[k] = v
    return json.dumps(ret)


def check_permission(permission_name):
    pn = permission_name

    def check_p(permissions, pname):
        status = "undefined"
        for p in permissions:
            pn = p.split("=")[0]
            pv = p.split("=")[1]
            if pn == pname and pv == "false":
                return "false"
            if pn == pname and pv == "true":
                status = "true"
        return status

    def check_pg(db_session, pgid, pname):
        pg_obj = db_session.query(database_action.PermissionGroup).filter_by(id=pgid, is_deleted=False).first()
        if pg_obj is None:
            db_session.close()
            raise RuntimeError("权限检查:不存在ID为`{}`的权限组".format(pgid))
        permissions = json.loads(pg_obj.permissions)
        status0 = check_p(permissions, pname)
        if status0 == "false":
            return "false"
        per_groups = json.loads(pg_obj.permission_group)
        status1 = "undefined"
        for pg in per_groups:
            ret = check_pg(db_session, pg, pname)
            if ret == "false":
                return "false"
            if ret == "true":
                status1 = "true"
        if status0 == "undefined" and status1 == "undefined":
            return "undefined"
        return "true"

    def check_ug(db_session, ugid, pname):
        ug_obj = db_session.query(database_action.UserGroup).filter_by(id=ugid, is_deleted=False).first()
        if ug_obj is None:
            db_session.close()
            raise RuntimeError("权限检查:不存在ID为`{}`的用户组".format(ugid))
        permissions = json.loads(ug_obj.permissions)
        status0 = check_p(permissions, pname)
        if status0 == "false":
            return "false"
        permission_group = json.loads(ug_obj.permission_group)
        status1 = "undefined"
        for pg in permission_group:
            ret = check_pg(db_session, pg, pname)
            if ret == "false":
                return "false"
            if ret == "true":
                status1 = "true"
        user_group = json.loads(ug_obj.user_group)
        status2 = "undefined"
        for ug in user_group:
            ret = check_ug(db_session, ug, pname)
            if ret == "false":
                return "false"
            if ret == "true":
                status2 = "true"
        if status0 == "undefined" and status1 == "undefined" and status2 == "undefined":
            return "undefined"
        return "true"

    def check_permission_(func):
        # 权限检查:如果用户组/权限组/权限K_0说用户有权限P，但是用户组/权限组/权限K_1说用户没有权限P，
        # 那么最终用户就**没有**权限P
        @wraps(func)
        def wrapper(*args, **kwargs):
            db_session = database_action.get_session()
            # access_token = request.json.get()
            access_token = None
            if access_token is None:
                user_groups = [1]  # 未登录用户默认用户组
                permission_groups = []
                permissions = []
            else:
                user_obj = db_session.query(database_action.Users).filter_by(access_token=access_token).first()
                if user_obj is None:
                    db_session.close()
                    return gen_returns(False, "权限检查:无效的accessToken")
                permissions = json.loads(user_obj.permissions)
                permission_groups = json.loads(user_obj.permission_group)
                user_groups = json.loads(user_obj.user_group)
            status0 = check_p(permissions, pn)
            if status0 == "false":
                db_session.close()
                return gen_returns(False, "权限检查:权限不足!你需要权限{}以执行此操作".format(pn))
            status1 = "undefined"
            for pg in permission_groups:
                ret = check_pg(db_session, pg, pn)
                if ret == "false":
                    db_session.close()
                    return gen_returns(False, "权限检查:权限不足!你需要权限{}以执行此操作".format(pn))
                if ret == "true":
                    status1 = "true"
            status2 = "undefined"
            for ug in user_groups:
                ret = check_ug(db_session, ug, pn)
                if ret == "false":
                    db_session.close()
                    return gen_returns(False, "权限检查:权限不足!你需要权限{}以执行此操作".format(pn))
                if ret == "true":
                    status2 = "true"
            if status0 == "undefined" and status1 == "undefined" and status2 == "undefined":
                db_session.close()
                return gen_returns(False, "权限检查:权限不足!你需要权限{}以执行此操作".format(pn))
            db_session.close()
            return func(*args, **kwargs)
        return wrapper
    return check_permission_
