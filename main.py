from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, status, Response
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, Session, create_engine, select
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv 
import os
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-to-a-long-random-string")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# model using BaseModel---->

# class NoteBase(BaseModel):
#     title: str
#     content: str

# class NoteCreate(NoteBase):
#     pass

# class NoteUpdate(BaseModel):
#     title:  Optional[str] = None
#     content: Optional[str] = None

# class Note(NoteBase):
#     id : int
#     created_at : datetime
#     updated_at : datetime

# model using SQLModel ---->

# class NoteBase(SQLModel):
#     title: str
#     content: str

# class Note(NoteBase, table=True):
#     id : Optional[int] = Field(default=None, primary_key=True)
#     created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
#     updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
# class NoteCreate(NoteBase):
#     pass

# class NoteRead(NoteBase):
#     id: int
#     created_at: datetime
#     updated_at: datetime

# class NoteUpdate(SQLModel):
#     title: Optional[str] = None
#     content: Optional[str] = None



"""Auth and notes models and routes."""

# auth added ----- >

# class UserBase(SQLModel):
#     username: str = Field(
#         min_length=3,
#         max_length=20,
#         regex=r"^[a-zA-Z0-9_]+$",
#     )


# class User(UserBase, table=True):
#     id: Optional[int] = Field(default=None, primary_key=True)
#     hashed_password: str


# class UserCreate(UserBase):
#     # bcrypt safely supports up to 72 bytes; enforce this at API level
#     password: str = Field(min_length=8, max_length=72)


# class UserRead(UserBase):
#     id: int


# class NoteBase(SQLModel):
#     title: str
#     content: str


# class Note(NoteBase, table=True):
#     id: Optional[int] = Field(default=None, primary_key=True)
#     created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
#     updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
#     user_id: int = Field(foreign_key="user.id")


# class NoteCreate(NoteBase):
#     pass


# class NoteRead(NoteBase):
#     id: int
#     created_at: datetime
#     updated_at: datetime


# class NoteUpdate(SQLModel):
#     title: Optional[str] = None
#     content: Optional[str] = None


# class Token(SQLModel):
#     access_token: str
#     token_type: str


# class TokenData(SQLModel):
#     username: Optional[str] = None

# ---------- Models ----------

class UserBase(BaseModel):
    username: str


class UserInDB(UserBase):
    id: str = Field(alias="_id")
    hashed_password: str

    class Config:
        populate_by_name = True


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: str


class NoteBase(BaseModel):
    title: str
    content: str


class NoteInDB(NoteBase):
    id: str = Field(alias="_id")
    created_at: datetime
    updated_at: datetime
    user_id: str

    class Config:
        populate_by_name = True


class NoteCreate(NoteBase):
    pass


class NoteRead(NoteBase):
    id: str
    created_at: datetime
    updated_at: datetime


class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

# # database setup ---->

# DATABASE_URL = "sqlite:///./notes.db"
# engine = create_engine(DATABASE_URL, echo=False)

# def create_db_and_tables():
#     SQLModel.metadata.create_all(engine)

app = FastAPI()
# create_db_and_tables()

# mongodb model--->

# MongoDB setup
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client.notesdb

users_collection = db.users
notes_collection = db.notes


# ---------- Auth helpers ----------

# def verify_password(plain_password: str, hashed_password: str) -> bool:
#     return pwd_context.verify(plain_password, hashed_password)


# def get_password_hash(password: str) -> str:
#     """Hash password with bcrypt, enforcing its 72-byte limit.

#     bcrypt works on bytes and rejects inputs >72 bytes. We therefore
#     encode to UTF-8 and truncate by bytes before hashing.
#     """
#     password_bytes = password.encode("utf-8")[:72]
#     return pwd_context.hash(password_bytes)


# def get_user_by_username(session: Session, username: str) -> Optional[User]:
#     statement = select(User).where(User.username == username)
#     return session.exec(statement).first()


# def authenticate_user(session: Session, username: str, password: str) -> Optional[User]:
#     user = get_user_by_username(session, username)
#     if not user:
#         return None
#     if not verify_password(password, user.hashed_password):
#         return None
#     return user


# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
#     to_encode = data.copy()
#     expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )

#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str | None = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username)
#     except JWTError:
#         raise credentials_exception

#     with Session(engine) as session:
#         user = get_user_by_username(session, token_data.username)
#         if user is None:
#             raise credentials_exception
#         return user

# ---------- Auth helpers ----------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


async def get_user_by_username(username: str) -> Optional[UserInDB]:
    user_doc = await users_collection.find_one({"username": username})
    if user_doc:
        user_doc["_id"] = str(user_doc["_id"])
        return UserInDB(**user_doc)
    return None


async def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = await get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = await get_user_by_username(token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Routes ---->

# notes : List[Note] = []  #this will hold the notes 
# next_id : int = 1

@app.get("/")
async def root():
    return FileResponse("index.html", media_type="text/html")

# get and create the notes

# @app.get("/notes")
# async def list_notes(search: Optional[str] = None):
#     if search is None or search.strip() == "":
#         return notes
    
#     temp = search.lower()
#     return [
#         note for note in notes
#         if temp in note.title.lower() or temp in note.content.lower()
#     ]

# @app.get("/notes", response_model=List[NoteRead])
# def list_notes(
#     search: Optional[str] = None,
#     current_user: User = Depends(get_current_user),
# ):
#     with Session(engine) as session:
#         statement = select(Note).where(Note.user_id == current_user.id)
#         notes = session.exec(statement).all()

#         if not search or search.strip() == "":
#             return notes

#         q = search.lower()
#         return [
#             note
#             for note in notes
#             if q in note.title.lower() or q in note.content.lower()
#         ]

@app.get("/notes", response_model=List[NoteRead])
async def list_notes(
    search: Optional[str] = None,
    current_user: UserInDB = Depends(get_current_user),
):
    query = {"user_id": current_user.id}
    
    if search and search.strip():
        q = search.lower()
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"content": {"$regex": q, "$options": "i"}},
        ]

    cursor = notes_collection.find(query)
    notes = []
    async for note_doc in cursor:
        notes.append(
            NoteRead(
                id=str(note_doc["_id"]),
                title=note_doc["title"],
                content=note_doc["content"],
                created_at=note_doc["created_at"],
                updated_at=note_doc["updated_at"],
            )
        )
    return notes

# @app.post("/notes", response_model=Note)
# async def create_note(note_in : NoteCreate):
#     global next_id
    
#     now = datetime.now(timezone.utc)
#     note = Note(
#         id = next_id,
#         title=note_in.title,
#         content=note_in.content,
#         created_at=now,
#         updated_at=now,
#     )
    
#     notes.append(note)
#     next_id += 1
#     return note

# @app.post("/notes", response_model=NoteRead)
# async def create_note(
#     note_in: NoteCreate,
#     current_user: User = Depends(get_current_user),
# ):
#     now = datetime.now(timezone.utc)
#     note = Note(
#       title=note_in.title,
#       content=note_in.content,
#       created_at=now,
#       updated_at=now,
#       user_id=current_user.id,
#     )

#     with Session(engine) as session:
#         session.add(note)
#         session.commit()
#         session.refresh(note)
#         return note

@app.post("/notes", response_model=NoteRead)
async def create_note(
    note_in: NoteCreate,
    current_user: UserInDB = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    note_doc = {
        "title": note_in.title,
        "content": note_in.content,
        "created_at": now,
        "updated_at": now,
        "user_id": current_user.id,
    }
    result = await notes_collection.insert_one(note_doc)
    return NoteRead(
        id=str(result.inserted_id),
        title=note_in.title,
        content=note_in.content,
        created_at=now,
        updated_at=now,
    )

# get and edit a specific note by id 

# @app.get("/notes/{note_id}", response_model=Note)
# async def get_note(note_id: int):
#     for note in notes:
#         if note.id == note_id:
#             return note
#     raise HTTPException(status_code=404, detail="Note not found")   

# @app.get("/notes/{note_id}", response_model=NoteRead)
# async def get_note(
#     note_id: int,
#     current_user: User = Depends(get_current_user),
# ):
#     with Session(engine) as session:
#         note = session.get(Note, note_id)
#         if not note or note.user_id != current_user.id:
#             raise HTTPException(status_code=404, detail="Note not found")
#         return note

@app.get("/notes/{note_id}", response_model=NoteRead)
async def get_note(
    note_id: str,
    current_user: UserInDB = Depends(get_current_user),
):
    try:
        note_doc = await notes_collection.find_one({"_id": ObjectId(note_id)})
    except:
        raise HTTPException(status_code=404, detail="Note not found")

    if not note_doc or note_doc["user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")

    return NoteRead(
        id=str(note_doc["_id"]),
        title=note_doc["title"],
        content=note_doc["content"],
        created_at=note_doc["created_at"],
        updated_at=note_doc["updated_at"],
    )


# @app.put("/notes/{note_id}", response_model=Note)
# async def update_note(note_id:int, note_in: NoteUpdate):
#     for index, note in enumerate(notes):
#         if note.id == note_id:
#             updated_data = note.model_dump()
            
#         if note_in.title is not None:
#             updated_data["title"] = note_in.title
#         if note_in.content is not None:
#             updated_data["content"] = note_in.content
        
#         updated_data["updated_at"] = datetime.now(timezone.utc)
        
#         updated_note = Note(**updated_data)
#         notes[index] = updated_note
#         return updated_note

#     raise HTTPException(status_code=404, detail="Note not found")

# @app.put("/notes/{note_id}", response_model=NoteRead)
# async def update_note(
#     note_id: int,
#     note_in: NoteUpdate,
#     current_user: User = Depends(get_current_user),
# ):
#     with Session(engine) as session:
#         note = session.get(Note, note_id)
#         if not note or note.user_id != current_user.id:
#             raise HTTPException(status_code=404, detail="Note not found")

#         if note_in.title is not None:
#             note.title = note_in.title
#         if note_in.content is not None:
#             note.content = note_in.content

#         note.updated_at = datetime.now(timezone.utc)

#         session.add(note)
#         session.commit()
#         session.refresh(note)
#         return note

@app.put("/notes/{note_id}", response_model=NoteRead)
async def update_note(
    note_id: str,
    note_in: NoteUpdate,
    current_user: UserInDB = Depends(get_current_user),
):
    try:
        note_doc = await notes_collection.find_one({"_id": ObjectId(note_id)})
    except:
        raise HTTPException(status_code=404, detail="Note not found")

    if not note_doc or note_doc["user_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")

    update_data = {"updated_at": datetime.now(timezone.utc)}
    if note_in.title is not None:
        update_data["title"] = note_in.title
    if note_in.content is not None:
        update_data["content"] = note_in.content

    await notes_collection.update_one(
        {"_id": ObjectId(note_id)}, {"$set": update_data}
    )

    updated_doc = await notes_collection.find_one({"_id": ObjectId(note_id)})
    return NoteRead(
        id=str(updated_doc["_id"]),
        title=updated_doc["title"],
        content=updated_doc["content"],
        created_at=updated_doc["created_at"],
        updated_at=updated_doc["updated_at"],
    )

# delete a specific note by id

# @app.delete("/notes/{note_id}")
# async def delete_note(note_id: int):
#     for index, note in enumerate(notes):
#         if note.id == note_id:
#             notes.pop(index)
#             return {"detail": "Note deleted"}
        
#     raise HTTPException(status_code=404, detail="Note not found")

# @app.delete("/notes/{note_id}")
# async def delete_note(
#     note_id: int,
#     current_user: User = Depends(get_current_user),
# ):
#     with Session(engine) as session:
#         note = session.get(Note, note_id)
#         if not note or note.user_id != current_user.id:
#             raise HTTPException(status_code=404, detail="Note not found")

#         session.delete(note)
#         session.commit()
#         return {"detail": "Note deleted"}


# faulty user deletion route---->
# @app.delete("/users/{user_id}")
# async def delete_user(
#     user_id: str,
#     current_user: UserInDB = Depends(get_current_user),
# ):
#     # Optional: only allow a user to delete their own account
#     if user_id != current_user.id:
#         raise HTTPException(status_code=403, detail="Not allowed to delete this user")

#     # Delete the user document
#     result = await users_collection.delete_one({"_id": ObjectId(user_id)})
#     if result.deleted_count == 0:
#         raise HTTPException(status_code=404, detail="User not found")

#     # Delete all notes belonging to this user
#     await notes_collection.delete_many({"user_id": user_id})

#     return {"detail": "User and all their notes deleted"}
    
    
# ---------- Auth routes ----------

# @app.post("/register", response_model=UserRead)
# def register_user(user_in: UserCreate):
#     with Session(engine) as session:
#         existing = get_user_by_username(session, user_in.username)
#         if existing:
#             raise HTTPException(status_code=400, detail="Username already registered")

#         user = User(
#             username=user_in.username,
#             hashed_password=get_password_hash(user_in.password),
#         )
#         session.add(user)
#         session.commit()
#         session.refresh(user)
#         return user


# @app.post("/token", response_model=Token)
# async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     with Session(engine) as session:
#         user = authenticate_user(session, form_data.username, form_data.password)
#         if not user:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Incorrect username or password",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )

#         access_token = create_access_token(data={"sub": user.username})
#         return {"access_token": access_token, "token_type": "bearer"}

# ---------- Auth routes ----------

@app.post("/register", response_model=UserRead)
async def register_user(user_in: UserCreate):
    existing = await get_user_by_username(user_in.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")

    user_doc = {
        "username": user_in.username,
        "hashed_password": get_password_hash(user_in.password),
    }
    result = await users_collection.insert_one(user_doc)
    return UserRead(id=str(result.inserted_id), username=user_in.username)


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.delete("/users/me")
async def delete_current_user(current_user: UserInDB = Depends(get_current_user)):
    result = await users_collection.delete_one({"_id": ObjectId(current_user.id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    await notes_collection.delete_many({"user_id": current_user.id})
    return {"detail": "User and all their notes deleted"}


@app.post("/users/me/change-password")
async def change_password(
    payload: PasswordChange,
    current_user: UserInDB = Depends(get_current_user),
):
    # Load fresh user doc from DB
    user_doc = await users_collection.find_one({"_id": ObjectId(current_user.id)})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify current password
    if not verify_password(payload.current_password, user_doc["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Hash new password and update
    new_hashed = get_password_hash(payload.new_password)
    await users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$set": {"hashed_password": new_hashed}},
    )

    return {"detail": "Password updated"}


