from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, status, Response
from pydantic import BaseModel, Field, EmailStr, field_validator
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, Session, create_engine, select
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv 
import os
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import secrets
import smtplib
from email.message import EmailMessage

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-to-a-long-random-string")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

EMAIL_FROM = os.getenv("EMAIL_FROM")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

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
    username: EmailStr


class UserInDB(UserBase):
    id: str = Field(alias="_id")
    hashed_password: str
    is_verified: bool = False
    verification_code: Optional[str] = None
    verification_expires_at: Optional[datetime] = None

    class Config:
        populate_by_name = True


class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v, info):
        username = getattr(info.data, "username", "")  # username from same model

        # length
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")

        # character classes
        if not any(c.islower() for c in v):
            raise ValueError("Password must include a lowercase letter")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must include an uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must include a number")
        if not any(c in "!@#$%^&*()-_=+[]{};:,<.>/?\\|`~" for c in v):
            raise ValueError("Password must include a special character")

        uname = str(username).lower()
        local_part = uname.split("@")[0] if "@" in uname else uname
        lower_pw = v.lower()

        if uname and uname in lower_pw:
            raise ValueError("Password must not contain your email")
        if local_part and local_part in lower_pw:
            raise ValueError("Password must not contain your name/username")

        common_words = ["password", "qwerty", "letmein", "123456", "123456789", "admin"]
        if any(w in lower_pw for w in common_words):
            raise ValueError("Password is too common")

        return v


class UserRead(UserBase):
    id: str
    is_verified: bool = False


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


class EmailVerification(BaseModel):
    code: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str


class VerifyResetCodeRequest(BaseModel):
    email: EmailStr
    code: str

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
deleted_notes_collection = db.deleted_notes


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


def validate_password_strength(password: str, username: str) -> None:
    """Validate password using the same rules as UserCreate.password."""
    if len(password) < 12:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 12 characters long",
        )

    if not any(c.islower() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must include a lowercase letter",
        )
    if not any(c.isupper() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must include an uppercase letter",
        )
    if not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must include a number",
        )
    if not any(c in "!@#$%^&*()-_=+[]{};:,<.>/?\\|`~" for c in password):
        raise HTTPException(
            status_code=400,
            detail="Password must include a special character",
        )

    uname = str(username).lower()
    local_part = uname.split("@")[0] if "@" in uname else uname
    lower_pw = password.lower()

    if uname and uname in lower_pw:
        raise HTTPException(
            status_code=400,
            detail="Password must not contain your email",
        )
    if local_part and local_part in lower_pw:
        raise HTTPException(
            status_code=400,
            detail="Password must not contain your name/username",
        )

    common_words = [
        "password",
        "qwerty",
        "letmein",
        "123456",
        "123456789",
        "admin",
    ]
    if any(w in lower_pw for w in common_words):
        raise HTTPException(
            status_code=400,
            detail="Password is too common",
        )


def send_verification_email(to_email: str, code: str) -> None:
    subject = "Your Secure Notes verification code"
    body = (
        f"Your email verification code is: {code}\n\n"
        "This code will expire in 10 minutes."
    )

    # If SMTP is configured, send a real email. Otherwise, log to console for dev.
    if SMTP_HOST and EMAIL_FROM and SMTP_USERNAME and SMTP_PASSWORD:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email
        msg.set_content(body)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_USE_TLS:
                server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    else:
        # Dev fallback: print code to server logs
        print(f"[DEV] Verification code for {to_email}: {code}")


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


@app.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest):
    """Initiate password reset. Always return generic success message."""
    user_doc = await users_collection.find_one({"username": payload.email})

    if user_doc:
        code = f"{secrets.randbelow(10**6):06d}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        await users_collection.update_one(
            {"_id": user_doc["_id"]},
            {
                "$set": {
                    "reset_code": code,
                    "reset_expires_at": expires_at,
                }
            },
        )

        try:
            subject = "Your Secure Notes password reset code"
            body = (
                f"Your password reset code is: {code}\n\n"
                "This code will expire in 15 minutes."
            )

            if SMTP_HOST and EMAIL_FROM and SMTP_USERNAME and SMTP_PASSWORD:
                msg = EmailMessage()
                msg["Subject"] = subject
                msg["From"] = EMAIL_FROM
                msg["To"] = payload.email
                msg.set_content(body)

                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                    if SMTP_USE_TLS:
                        server.starttls()
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                    server.send_message(msg)
            else:
                print(f"[DEV] Password reset code for {payload.email}: {code}")
        except Exception as e:
            print(f"Error sending password reset email: {e}")

    return {"detail": "If an account with that email exists, a reset code has been sent."}


@app.post("/verify-reset-code")
async def verify_reset_code(payload: VerifyResetCodeRequest):
    """Verify reset code without changing the password yet."""
    user_doc = await users_collection.find_one({"username": payload.email})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    stored_code = user_doc.get("reset_code")
    expires_at = user_doc.get("reset_expires_at")
    now = datetime.now(timezone.utc)

    if expires_at is not None and getattr(expires_at, "tzinfo", None) is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if (
        not stored_code
        or not expires_at
        or expires_at < now
        or payload.code != stored_code
    ):
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")

    # Code is valid; do not clear it yet so /reset-password can still use it once
    return {"detail": "Reset code verified"}


@app.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest):
    user_doc = await users_collection.find_one({"username": payload.email})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    stored_code = user_doc.get("reset_code")
    expires_at = user_doc.get("reset_expires_at")
    now = datetime.now(timezone.utc)

    if expires_at is not None and getattr(expires_at, "tzinfo", None) is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if (
        not stored_code
        or not expires_at
        or expires_at < now
        or payload.code != stored_code
    ):
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")

    validate_password_strength(payload.new_password, payload.email)

    new_hashed = get_password_hash(payload.new_password)

    await users_collection.update_one(
        {"_id": user_doc["_id"]},
        {
            "$set": {"hashed_password": new_hashed},
            "$unset": {"reset_code": "", "reset_expires_at": ""},
        },
    )

    return {"detail": "Password has been reset"}


@app.get("/users/me", response_model=UserRead)
async def read_current_user(current_user: UserInDB = Depends(get_current_user)):
    user_doc = await users_collection.find_one({"_id": ObjectId(current_user.id)})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    return UserRead(
        id=str(user_doc["_id"]),
        username=user_doc["username"],
        is_verified=bool(user_doc.get("is_verified", False)),
    )

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

# delete a specific note by id (with undo support)

@app.delete("/notes/{note_id}")
async def delete_note(
    note_id: str,
    current_user: UserInDB = Depends(get_current_user),
):
    """Soft-delete a note: move it to deleted_notes so it can be undone once."""
    try:
        note_doc = await notes_collection.find_one({"_id": ObjectId(note_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Note not found")

    if not note_doc or note_doc.get("user_id") != current_user.id:
        raise HTTPException(status_code=404, detail="Note not found")

    # Add deleted_at timestamp and move to deleted_notes_collection
    note_doc["deleted_at"] = datetime.now(timezone.utc)
    await deleted_notes_collection.insert_one(note_doc)

    # Remove from main notes collection
    await notes_collection.delete_one({"_id": ObjectId(note_id)})
    return {"detail": "Note deleted"}


@app.post("/notes/undo-delete", response_model=NoteRead)
async def undo_delete_note(current_user: UserInDB = Depends(get_current_user)):
    """Restore the most recently deleted note for the current user.

    Each deleted note can only be restored once because it is removed
    from deleted_notes_collection after being re-inserted into notes.
    """

    # Find the most recently deleted note for this user
    deleted_note = await deleted_notes_collection.find_one(
        {"user_id": current_user.id}, sort=[("deleted_at", -1)]
    )

    if not deleted_note:
        raise HTTPException(status_code=404, detail="No deleted note to undo")

    # Remove from the deleted collection so it can't be undone twice
    await deleted_notes_collection.delete_one({"_id": deleted_note["_id"]})

    # Reinsert into main notes collection (preserve original _id)
    restored_doc = deleted_note.copy()
    await notes_collection.insert_one(restored_doc)

    return NoteRead(
        id=str(restored_doc["_id"]),
        title=restored_doc["title"],
        content=restored_doc["content"],
        created_at=restored_doc["created_at"],
        updated_at=restored_doc["updated_at"],
    )


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
        "is_verified": False,
    }
    result = await users_collection.insert_one(user_doc)
    return UserRead(id=str(result.inserted_id), username=user_in.username, is_verified=False)


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


@app.post("/users/me/send-verification-code")
async def send_verification_code_route(
    current_user: UserInDB = Depends(get_current_user),
):
    user_doc = await users_collection.find_one({"_id": ObjectId(current_user.id)})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    if user_doc.get("is_verified"):
        raise HTTPException(status_code=400, detail="Email already verified")

    code = f"{secrets.randbelow(10**6):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    await users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$set": {"verification_code": code, "verification_expires_at": expires_at}},
    )

    try:
        send_verification_email(user_doc["username"], code)
    except Exception as e:
        print(f"Error sending verification email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send verification email")

    return {"detail": "Verification code sent"}


@app.post("/users/me/verify-email")
async def verify_email(
    payload: EmailVerification,
    current_user: UserInDB = Depends(get_current_user),
):
    user_doc = await users_collection.find_one({"_id": ObjectId(current_user.id)})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    if user_doc.get("is_verified"):
        return {"detail": "Email already verified"}

    stored_code = user_doc.get("verification_code")
    expires_at = user_doc.get("verification_expires_at")
    now = datetime.now(timezone.utc)

    # Normalize expires_at to be timezone-aware (UTC) to avoid naive/aware comparison issues
    if expires_at is not None and getattr(expires_at, "tzinfo", None) is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if (
        not stored_code
        or not expires_at
        or expires_at < now
        or payload.code != stored_code
    ):
        raise HTTPException(status_code=400, detail="Invalid or expired verification code")

    await users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {
            "$set": {"is_verified": True},
            "$unset": {"verification_code": "", "verification_expires_at": ""},
        },
    )

    return {"detail": "Email verified"}


