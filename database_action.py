import pymysql

pymysql.install_as_MySQLdb()
from sqlalchemy import *
from sqlalchemy.ext.declarative import *
from sqlalchemy.orm import *

DATABASE_USERNAME = "root"
DATABASE_PASSWORD = "saobby114514"
DATABASE_HOST = "localhost:3306"
DATABASE_NAME = "forum"
engine = create_engine("mysql://{}:{}@{}/{}".format(DATABASE_USERNAME, DATABASE_PASSWORD, DATABASE_HOST, DATABASE_NAME),
                       echo=False,
                       connect_args={"ssl": {"ssl_ca": "/etc/ssl/cert.pem"}})
base = declarative_base()


class Users(base):
    __tablename__ = "saobby_forum$users"
    id = Column(Integer, primary_key=True)  # 用户ID
    username = Column(VARCHAR(128))  # 用户名，字符串
    password = Column(VARCHAR(64))  # 密码md5值
    access_token = Column(VARCHAR(128))  # 访问密钥
    avatar_url = Column(TEXT(1024))  # 头像图片url
    signature = Column(TEXT(1024))  # 用户个性签名，512字以内
    timestamp = Column(VARCHAR(64))  # 账号创建时间戳，字符串
    ip_address = Column(VARCHAR(64))  # 创建账号者的IP地址
    user_group = Column(TEXT(4096))  # 所处用户组的ID，json形式字符串，例如[0,1]
    permission_group = Column(TEXT(4096))  # 所单独获得权限组的ID，json形式字符串，例如[0,1,2]
    permissions = Column(TEXT(4096))  # 所单独获得的权限名，json形式字符串，例如["user.login=true"]
    info = Column(TEXT(4096))  # 用户的其他信息，json形式字符串

    def __init__(self, username, password, access_token, avatar_url, signature, timestamp, ip_address, user_group,
                 permission_group, permissions, info):
        self.username = username
        self.password = password
        self.access_token = access_token
        self.avatar_url = avatar_url
        self.signature = signature
        self.timestamp = timestamp
        self.ip_address = ip_address
        self.user_group = user_group
        self.permission_group = permission_group
        self.permissions = permissions
        self.info = info


class UserGroup(base):
    __tablename__ = "saobby_forum$user_group"
    id = Column(Integer, primary_key=True)  # 用户组ID
    # 注意!系统用户组id:
    # 1 为游客用户组
    # 2 为注册用户默认用户组
    # 3 为禁言用户组
    # 4 为封禁用户组
    name = Column(VARCHAR(128))  # 用户组名
    user_group = Column(TEXT(4096))  # 所继承的用户组id，json格式
    permission_group = Column(TEXT(4096))  # 所包含的权限组id，json格式
    permissions = Column(TEXT(4096))  # 所包含的权限,json,例如["user.login=true"]
    is_default = Column(BOOLEAN)  # 是否是默认用户组
    is_system = Column(BOOLEAN)  # 是否为系统用户组
    is_deleted = Column(BOOLEAN)  # 该用户组是否被删除

    def __init__(self, name, user_group, permission_group, permissions, is_default, is_system, is_deleted):
        self.name = name
        self.user_group = user_group
        self.permission_group = permission_group
        self.permissions = permissions
        self.is_default = is_default
        self.is_system = is_system
        self.is_deleted = is_deleted


class PermissionGroup(base):
    __tablename__ = "saobby_forum$permission_group"
    id = Column(Integer, primary_key=True)  # 权限组ID
    name = Column(VARCHAR(128))  # 权限组名
    permission_group = Column(TEXT(4096))  # 所包含的权限组id，json格式
    permissions = Column(TEXT(4096))  # 所包含的权限,json,例如["user.login=true"]
    is_deleted = Column(BOOLEAN)  # 该用户组是否被删除

    def __init__(self, name, permission_group, permissions, is_deleted):
        self.name = name
        self.permission_group = permission_group
        self.permissions = permissions
        self.is_deleted = is_deleted


def get_session():
    db_session = sessionmaker(bind=engine)
    session = db_session()
    return session


# base.metadata.create_all(engine)
if __name__ == "__main__":
    s = get_session()
    s.add(UserGroup("__banned__", "[]", "[]", "[\"forum.test=true\"]", False, True, False))
    s.commit()
    s.close()
