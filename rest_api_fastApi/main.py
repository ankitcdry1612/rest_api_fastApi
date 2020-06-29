from datetime import datetime, timedelta

import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import PyJWTError
from passlib.context import CryptContext
from pydantic import BaseModel
import motor
import tornado.ioloop as ioloop

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "7d52177e22d4c040330c99ffc2db7055e1642212de342e6a0ca16605551593f0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def get_db():
	client = motor.motor_tornado.MotorClient('mongodb://localhost:27017')
	db = client.test_datbase
	return db

def do_insert(doc,db):
	db.collection.insert_one(doc)


async def do_find(key,value,db):
	doc = await db.collection.find_one({key:{'$eq':value}},{'_id':0})
	return doc

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str = None


class User(BaseModel):
    username: str
    email: str = None
    full_name: str = None
    disabled: bool = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user(db, username: str):
	user_dict = await do_find("username",username,db)
	if user_dict:
		return UserInDB(**user_dict)


async def authenticate_user(db, username: str, password: str):
    user = await get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except PyJWTError:
        raise credentials_exception
    db = get_db()
    user = await get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_db()
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.put("/create_user")
async def sign_up(full_name: str=Form(...),email: str=Form(...),username: str=Form(...),password: str=Form(...)):
	other_db = get_db()
	user = await get_user(other_db,username)
	if user is not None:
		return "change name"
	psw = get_password_hash(password)
	data = {"username": username,
			"full_name": full_name,
			"email": email,
			"hashed_password": psw,
			"disabled": False}
	do_insert(data,other_db)
	return "user created"



@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

async def update(key,newValue,username,coll):
	old_document = await coll.collection.find_one({'username':{'$eq':username}})
	old_document[key]=newValue
	_id = old_document['_id']
	result = await coll.collection.replace_one({'_id':_id},old_document)


@app.put("/users/me/update/")
async def update_info(current_user: User = Depends(get_current_active_user),full_name: str=None,email: str=None,password: str=Form(...)):
    result = verify_password(password, current_user.hashed_password)
    db = get_db()
    if result==False:
    	return "Wrong Password"
    if(full_name!=None):
    	await update('full_name',full_name,current_user.username,db)
    if(email!=None):
    	await update('email',email,current_user.username,db)
    return "Information updated"

@app.delete("/user/me/delete_account")
async def delete_account(current_user: User = Depends(get_current_active_user)):
	db = get_db()
	await db.collection.delete_one({'username':{'$eq':current_user.username}})
	return "Deleted account"