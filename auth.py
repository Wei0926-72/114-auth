from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

# 假資料（注意：生產環境請用安全儲存與 hash 密碼）
fake_users_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

# JWT 設定（生產請把 SECRET_KEY 改為更複雜且從環境變數讀取）
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_token(data: dict, expires_delta: Optional[timedelta] = None, token_type: str = "access"):
    """
    建立 access 或 refresh token（token_type = "access" 或 "refresh"）
    payload 會包含 sub（username）、type（access/refresh）與 exp
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "type": token_type})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_access_token(username: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    return create_token({"sub": username}, expires_delta=timedelta(minutes=expires_minutes), token_type="access")

def create_refresh_token(username: str, expires_days: int = REFRESH_TOKEN_EXPIRE_DAYS):
    return create_token({"sub": username}, expires_delta=timedelta(days=expires_days), token_type="refresh")

def verify_token(token: str, expected_type: str = "access"):
    """
    驗證 token 並檢查 token type（access / refresh）
    失敗會丟出 HTTPException(401)
    成功回傳 username（sub）
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        token_type = payload.get("type")
        if username is None or token_type != expected_type:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    """
    登入：驗證帳密，回傳 access token 與 refresh token，並將它們分別設在 cookie
    access token 存在 cookie 'jwt'
    refresh token 存在 cookie 'refresh_jwt'
    """
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token(user["username"])
    refresh_token = create_refresh_token(user["username"])

    # 設定 cookie
    response.set_cookie(
        key="jwt",
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    response.set_cookie(
        key="refresh_jwt",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
    )

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/refresh")
def refresh(response: Response, refresh_token: Optional[str] = Cookie(None), token: Optional[str] = None):
    """
    刷新 access token：
    - 優先從 cookie 'refresh_jwt' 讀取 refresh token
    - 或可直接傳入 body / query 的 token（這裡示範 cookie 為主）
    回傳新的 access token 並更新 cookie 'jwt'
    """
    token_to_verify = refresh_token or token
    if not token_to_verify:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    username = verify_token(token_to_verify, expected_type="refresh")

    new_access_token = create_access_token(username)

    # 更新 access token cookie
    response.set_cookie(
        key="jwt",
        value=new_access_token,
        httponly=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    return {"access_token": new_access_token, "token_type": "bearer"}

@app.get("/protected")
def protected(token: Optional[str] = Depends(oauth2_scheme), jwt_cookie: Optional[str] = Cookie(None)):
    """
    受保護的路由：接受 header 的 Bearer token 或 cookie 'jwt'
    """
    if token:
        username = verify_token(token, expected_type="access")
    elif jwt_cookie:
        username = verify_token(jwt_cookie, expected_type="access")
    else:
        raise HTTPException(status_code=401, detail="Missing token or cookie")

    return {"message": f"Hello, {username}! You are authenticated."}

@app.post("/logout")
def logout(response: Response):
    """
    可選：登出時清除 cookie（讓瀏覽器刪除 cookie）
    """
    response.delete_cookie("jwt")
    response.delete_cookie("refresh_jwt")
    return {"message": "Logged out"}
