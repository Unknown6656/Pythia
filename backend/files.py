from typing import Any, Iterator
import datetime
import hashlib
import uuid


class PythiaFileInfo:
    def __init__(self : 'PythiaFileInfo',
                 name : str,
                 data : bytes,
                 mime : str = 'application/octet-stream',
                 comment : str | None = None,
                 created : datetime.datetime = datetime.datetime.now(),
                 id : uuid.UUID = uuid.uuid4()
    ) -> None:
        self.id = id
        self.name = name
        self.mime = mime
        self.comment = comment
        self.data = data
        self.size = len(data)
        self.sha1 = hashlib.sha1(data).hexdigest()
        self.md5 = hashlib.md5(data).hexdigest()
        self.created = created

    def __hash__(self) -> int:
        return self.id.__hash__()

    def __eq__(self, other : Any) -> bool:
        if isinstance(other, PythiaFileInfo):
            return self.id == other.id
        elif isinstance(other, uuid.UUID):
            return self.id == other
        else:
            return False

    def __repr__(self : 'PythiaFileInfo') -> str:
        return f'("{self.name}", {self.mime}, {self.size}B, {self.created}, {self.sha1})'


class PythiaFiles:
    def __init__(self : 'PythiaFiles') -> None:
        self.files: dict[uuid.UUID, PythiaFileInfo] = { }

    def __contains__(self : 'PythiaFiles', id_or_name: uuid.UUID | str) -> bool:
        return len(self.get(id_or_name)) == 1

    def __getitem__(self : 'PythiaFiles', id_or_name: uuid.UUID | str) -> PythiaFileInfo | None:
        results: list[PythiaFileInfo] = self.get(id_or_name)

        if len(results) == 1:
            return results[0]
        elif len(results) > 1:
            raise ValueError(f'Multiple files found for {id_or_name}')
        else:
            return None

    def __iter__(self : 'PythiaFiles') -> Iterator[PythiaFileInfo]:
        return iter(self.files.values())

    def __len__(self : 'PythiaFiles') -> int:
        return len(self.files)

    def __repr__(self : 'PythiaFiles') -> str:
        return f'PythiaFiles({len(self.files)} files)'

    def __delitem__(self : 'PythiaFiles', id_or_name: uuid.UUID | str) -> None:
        for match in self.get(id_or_name):
            self.remove(match.id)


    def add(self : 'PythiaFiles', file: PythiaFileInfo) -> None:
        self.files[file.id] = file

    def get(self : 'PythiaFiles', id_or_name: uuid.UUID | str) -> list[PythiaFileInfo]:
        id_or_name = str(id_or_name).strip().lower()

        return [f for f in self if str(f.id).lower() == id_or_name or f.name.lower() == id_or_name]

    def create(self : 'PythiaFiles', name: str, data: bytes, mime: str = 'application/octet-stream', comment: str | None = None) -> PythiaFileInfo:
        file_info = PythiaFileInfo(name, data, mime, comment, datetime.datetime.now(), uuid.uuid4())
        self.add(file_info)

        return file_info

    def remove(self : 'PythiaFiles', id_or_name: uuid.UUID | str) -> None:
        del self[id_or_name]
