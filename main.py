from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, select, insert, update, delete
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from models.models import roles, users, artists, albums, songs  
from datetime import datetime
from config import DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME 
from typing import Optional, Dict

from fastapi_users import fastapi_users, FastAPIUsers
from pydantic import BaseModel, Field

from auth.auth import auth_backend
from auth.database import User
from auth.manager import get_user_manager
from auth.schemas import UserRead, UserCreate, UserUpdate
from bcrypt import hashpw, gensalt


DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)



app = FastAPI()

fastapi_users = FastAPIUsers[User, int](
    get_user_manager,
    [auth_backend],
)

app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/jwt",
    tags=["auth"],
)

app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RoleCreate(BaseModel):
    name: str
    permissions: dict = {}

class UserCreate(BaseModel):
    email: str
    username: str
    role_id: int
    hashed_password: str
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False

class ArtistCreate(BaseModel):
    name: str
    genre: str = None
    country: str = None

class AlbumCreate(BaseModel):
    title: str
    release_date: datetime
    artist_id: int

class SongCreate(BaseModel):
    title: str
    duration: int
    album_id: int
    artist_id: int

class Role(BaseModel):
    id: int
    name: str
    permissions: dict

    class Config:
        orm_mode = True

class User(BaseModel):
    id: int
    email: str
    username: str
    role_id: int
    registered_at: datetime
    is_active: bool
    is_superuser: bool
    is_verified: bool

    class Config:
        orm_mode = True

class Artist(BaseModel):
    id: int
    name: str
    genre: str = None
    country: str = None

    class Config:
        orm_mode = True

class Album(BaseModel):
    id: int
    title: str
    release_date: datetime
    artist_id: int

    class Config:
        orm_mode = True

class Song(BaseModel):
    id: int
    title: str
    duration: int
    album_id: int
    artist_id: int

    class Config:
        orm_mode = True

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    permissions: Optional[Dict] = None

class UserUpdate(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    role_id: Optional[int] = None
    hashed_password: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    is_verified: Optional[bool] = None

class ArtistUpdate(BaseModel):
    name: Optional[str] = None
    genre: Optional[str] = None
    country: Optional[str] = None

class AlbumUpdate(BaseModel):
    title: Optional[str] = None
    release_date: Optional[datetime] = None
    artist_id: Optional[int] = None

class SongUpdate(BaseModel):
    title: Optional[str] = None
    duration: Optional[int] = None
    album_id: Optional[int] = None
    artist_id: Optional[int] = None


@app.post("/roles/", response_model=Role)
def create_role(role: RoleCreate, db: Session = Depends(get_db)):
    stmt = insert(roles).values(
        name=role.name,
        permissions=role.permissions
    ).returning(roles.c.id, roles.c.name, roles.c.permissions)
    result = db.execute(stmt).fetchone()
    db.commit()
    return result


@app.get("/roles/", response_model=list[Role])
def get_roles(db: Session = Depends(get_db)):
    result = db.execute(select(roles)).fetchall()
    return result


@app.get("/roles/{role_id}", response_model=Role)
def get_role(role_id: int, db: Session = Depends(get_db)):
    result = db.execute(select(roles).where(roles.c.id == role_id)).fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return result


@app.put("/roles/{role_id}", response_model=Role)
def update_role(role_id: int, role: RoleCreate, db: Session = Depends(get_db)):
    stmt = update(roles).where(roles.c.id == role_id).values(
        name=role.name,
        permissions=role.permissions
    ).returning(roles.c.id, roles.c.name, roles.c.permissions)
    result = db.execute(stmt).fetchone()
    db.commit()
    if result is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return result


@app.post("/users/", response_model=User)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    # Hash the password using bcrypt
    hashed_password = hashpw(user.password.encode('utf-8'), gensalt()).decode('utf-8')
    
    stmt = insert(users).values(
        email=user.email,
        username=user.username,
        role_id=user.role_id,
        hashed_password=hashed_password,  # Use hashed password
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        is_verified=user.is_verified
    ).returning(
        users.c.id, users.c.email, users.c.username, users.c.role_id, users.c.registered_at,
        users.c.is_active, users.c.is_superuser, users.c.is_verified
    )
    result = db.execute(stmt).fetchone()
    db.commit()
    return result


@app.get("/users/", response_model=list[User])
def get_users(
    db: Session = Depends(get_db), 
    limit: int = 10,   
    offset: int = 0    
):
    query = select(users).limit(limit).offset(offset)
    result = db.execute(query).fetchall()
    return result



@app.get("/users/{user_id}", response_model=User)
def get_user(user_id: int, db: Session = Depends(get_db)):
    result = db.execute(select(users).where(users.c.id == user_id)).fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@app.put("/users/{user_id}", response_model=User)
def update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    stmt = update(users).where(users.c.id == user_id).values(
        {k: v for k, v in user.dict().items() if v is not None}

    ).returning(
        users.c.id, users.c.email, users.c.username, users.c.role_id, users.c.registered_at,
        users.c.is_active, users.c.is_superuser, users.c.is_verified
    )
    result = db.execute(stmt).fetchone()
    db.commit()
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@app.post("/artists/", response_model=Artist)
def create_artist(artist: ArtistCreate, db: Session = Depends(get_db)):
    stmt = insert(artists).values(
        name=artist.name,
        genre=artist.genre,
        country=artist.country
    ).returning(artists.c.id, artists.c.name, artists.c.genre, artists.c.country)
    result = db.execute(stmt).fetchone()
    db.commit()
    return result


@app.get("/artists/", response_model=list[Artist])
def get_artists(
    db: Session = Depends(get_db), 
    limit: int = 10, 
    offset: int = 0
):
    query = select(artists).limit(limit).offset(offset)
    result = db.execute(query).fetchall()
    return result

@app.get("/artists/{artist_id}", response_model=Artist)
def get_artist(artist_id: int, db: Session = Depends(get_db)):
    result = db.execute(select(artists).where(artists.c.id == artist_id)).fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="Artist not found")
    return result


@app.delete("/artists/{artist_id}")
def delete_artist(artist_id: int, db: Session = Depends(get_db)):
    stmt = delete(artists).where(artists.c.id == artist_id)
    result = db.execute(stmt)
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Artist not found")
    return {"message": "Artist deleted successfully"}

'''
@app.put("/artists/{artist_id}", response_model=ArtistUpdate)
def update_artist(artist_id: int, artist: ArtistCreate, db: Session = Depends(get_db)):
    stmt = update(artists).where(artists.c.id == artist_id).values(
        name=artist.name,
        genre=artist.genre,
        country=artist.country
    ).returning(artists.c.id, artists.c.name, artists.c.genre, artists.c.country)
    result = db.execute(stmt).fetchone()
    db.commit()
    if result is None:
        raise HTTPException(status_code=404, detail="Artist not found")
    return result
'''

@app.put("/artists/{artist_id}", response_model=Artist)
def update_artist(artist_id: int, artist: ArtistUpdate, db: Session = Depends(get_db)):
    stmt = update(artists).where(artists.c.id == artist_id).values(
        {k: v for k, v in artist.dict().items() if v is not None}
    ).returning(artists.c.id, artists.c.name, artists.c.genre, artists.c.country)
    result = db.execute(stmt).fetchone()
    db.commit()
    if result is None:
        raise HTTPException(status_code=404, detail="Artist not found")
    return result


@app.post("/albums/", response_model=Album)
def create_album(album: AlbumCreate, db: Session = Depends(get_db)):
    stmt = insert(albums).values(
        title=album.title,
        release_date=album.release_date,
        artist_id=album.artist_id
    ).returning(albums.c.id, albums.c.title, albums.c.release_date, albums.c.artist_id)
    result = db.execute(stmt).fetchone()
    db.commit()
    return result


@app.get("/albums/{album_id}", response_model=Album)
def get_album(album_id: int, db: Session = Depends(get_db)):
    result = db.execute(select(albums).where(albums.c.id == album_id)).fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="Album not found")
    return result


@app.put("/artists/{artist_id}", response_model=Artist)
def update_artist(artist_id: int, artist: ArtistCreate, db: Session = Depends(get_db)):
    stmt = update(artists).where(artists.c.id == artist_id).values(
        name=artist.name,
        genre=artist.genre,
        country=artist.country
    ).returning(artists.c.id, artists.c.name, artists.c.genre, artists.c.country)
    result = db.execute(stmt).fetchone()
    db.commit()
    if result is None:
        raise HTTPException(status_code=404, detail="Artist not found")
    return result


@app.post("/songs/", response_model=Song)
def create_song(song: SongCreate, db: Session = Depends(get_db)):
    stmt = insert(songs).values(
        title=song.title,
        duration=song.duration,
        album_id=song.album_id,
        artist_id=song.artist_id
    ).returning(songs.c.id, songs.c.title, songs.c.duration, songs.c.album_id, songs.c.artist_id)
    result = db.execute(stmt).fetchone()
    db.commit()
    return result


@app.get("/songs/{song_id}", response_model=Song)
def get_song(song_id: int, db: Session = Depends(get_db)):
    result = db.execute(select(songs).where(songs.c.id == song_id)).fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="Song not found")
    return result

