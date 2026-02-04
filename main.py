from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, Session, create_engine, select
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv 
import os

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



# auth added ----- >

class UserBase(SQLModel):
    username: str


class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: int


class NoteBase(SQLModel):
    title: str
    content: str


class Note(NoteBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: int = Field(foreign_key="user.id")


class NoteCreate(NoteBase):
    pass


class NoteRead(NoteBase):
    id: int
    created_at: datetime
    updated_at: datetime


class NoteUpdate(SQLModel):
    title: Optional[str] = None
    content: Optional[str] = None


class Token(SQLModel):
    access_token: str
    token_type: str


class TokenData(SQLModel):
    username: Optional[str] = None

# database setup ---->

DATABASE_URL = "sqlite:///./notes.db"
engine = create_engine(DATABASE_URL, echo=False)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

app = FastAPI()
create_db_and_tables()


# ---------- Auth helpers ----------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user_by_username(session: Session, username: str) -> Optional[User]:
    statement = select(User).where(User.username == username)
    return session.exec(statement).first()


def authenticate_user(session: Session, username: str, password: str) -> Optional[User]:
    user = get_user_by_username(session, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
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

    with Session(engine) as session:
        user = get_user_by_username(session, token_data.username)
        if user is None:
            raise credentials_exception
        return user

# Routes ---->

notes : List[Note] = []  #this will hold the notes 
next_id : int = 1

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

@app.get("/notes", response_model=List[NoteRead])
def list_notes(
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    with Session(engine) as session:
        statement = select(Note).where(Note.user_id == current_user.id)
        notes = session.exec(statement).all()

        if not search or search.strip() == "":
            return notes

        q = search.lower()
        return [
            note
            for note in notes
            if q in note.title.lower() or q in note.content.lower()
        ]

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

@app.post("/notes", response_model=NoteRead)
async def create_note(
    note_in: NoteCreate,
    current_user: User = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    note = Note(
      title=note_in.title,
      content=note_in.content,
      created_at=now,
      updated_at=now,
      user_id=current_user.id,
    )

    with Session(engine) as session:
        session.add(note)
        session.commit()
        session.refresh(note)
        return note

# get and edit a specific note by id 

# @app.get("/notes/{note_id}", response_model=Note)
# async def get_note(note_id: int):
#     for note in notes:
#         if note.id == note_id:
#             return note
#     raise HTTPException(status_code=404, detail="Note not found")   

@app.get("/notes/{note_id}", response_model=NoteRead)
async def get_note(
    note_id: int,
    current_user: User = Depends(get_current_user),
):
    with Session(engine) as session:
        note = session.get(Note, note_id)
        if not note or note.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")
        return note


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

@app.put("/notes/{note_id}", response_model=NoteRead)
async def update_note(
    note_id: int,
    note_in: NoteUpdate,
    current_user: User = Depends(get_current_user),
):
    with Session(engine) as session:
        note = session.get(Note, note_id)
        if not note or note.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")

        if note_in.title is not None:
            note.title = note_in.title
        if note_in.content is not None:
            note.content = note_in.content

        note.updated_at = datetime.now(timezone.utc)

        session.add(note)
        session.commit()
        session.refresh(note)
        return note

# delete a specific note by id

# @app.delete("/notes/{note_id}")
# async def delete_note(note_id: int):
#     for index, note in enumerate(notes):
#         if note.id == note_id:
#             notes.pop(index)
#             return {"detail": "Note deleted"}
        
#     raise HTTPException(status_code=404, detail="Note not found")

@app.delete("/notes/{note_id}")
async def delete_note(
    note_id: int,
    current_user: User = Depends(get_current_user),
):
    with Session(engine) as session:
        note = session.get(Note, note_id)
        if not note or note.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")

        session.delete(note)
        session.commit()
        return {"detail": "Note deleted"}
    
    
# ---------- Auth routes ----------

@app.post("/register", response_model=UserRead)
def register_user(user_in: UserCreate):
    with Session(engine) as session:
        existing = get_user_by_username(session, user_in.username)
        if existing:
            raise HTTPException(status_code=400, detail="Username already registered")

        user = User(
            username=user_in.username,
            hashed_password=get_password_hash(user_in.password),
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        user = authenticate_user(session, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token = create_access_token(data={"sub": user.username})
        return {"access_token": access_token, "token_type": "bearer"}