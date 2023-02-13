import requests
import uuid
import sys
import math
import random
import base64
import threading
import io

from getpass import getpass
from multiprocessing import pool
from typing import Tuple, Mapping, Final, Optional, List

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class Buffer(bytearray):
    def __init__(self, size: int):
        self._size = size

        super().__init__(self._size)

    def __getitem__(self, value):
        if isinstance(value, slice):
            return Buffer(super().__getitem__(value))

        return super().__getitem__(value)

    def _fill_left(self, start: int, fill: bytes):
        if self._size > start:
            self[start:] = fill * (self._size - start)

    def _rtrim(self, idx: int) -> bytes:
        return self if idx >= self._size else self[:idx]

    def _fit_bytes(self, bytes_: bytes):
        pieces = math.ceil(len(bytes_) / self._size)
        return [bytes_[self._size*i:self._size*(i+1)] for i in range(pieces)]

    def fill_left(self, start: int, fill: bytes = b'\0'):
        assert from_idx >= 0, 'Starting index must be greater than zero'
        assert len(fill) == 1, 'Remaining fill must be a single byte'

        return self._fill_left(start, fill)

    def rtrim(self, until: int):
        return Buffer(self._rtrim(until))

    def fit_bytes(self, bytes_: bytes):
        return [Buffer(b) for b in self._fit_bytes(bytes_)]

    @property
    def size(self) -> int:
        return self._size

# utils
def try_pop(_list: List[any], index=-1, *, default: any) -> any:
    return _list.pop(index) if (ll := len(_list)) and ll > index else default
# ----------

from functools import singledispatchmethod

class File:
    def __init__(self, file: str | io.IOBase, mode: str = 'rb+'):
        self._name, self._stream = self._open(file, mode)

        self._last_read_bytes = 0
        self._backtrack_bytes = 0

    @classmethod
    def temporary(cls, *args, **kwargs):
        return cls(tempfile.TemporaryFile(*args, **kwargs))
        
    def __enter__(self, *args, **kwargs):
        return self._stream.__enter__(*args, **kwargs)

    def __exit__(self, *args, **kwargs):
        return self._stream.__exit__(*args, **kwargs)

    def _open(self, file: str | io.IOBase, mode: str) -> Tuple[str, io.IOBase]:
        if isinstance(file, io.IOBase):
            return None, file
        elif isinstance(file, str):
            return os.path.basename(file), open(file, mode)

        raise Exception('Input file must be a name of file-like object')

    def _backtrack(self):
        self._stream.seek(-self._backtrack_bytes, io.SEEK_CUR)
        self._backtrack_bytes = 0 # reset inplace positioning

    def rewind(self):
        self._stream.seek(0)

    def readinto(self, buffer: Buffer) -> int:
        self._backtrack_bytes = self._last_read_bytes = \
                self._stream.readinto(buffer)

        return self._last_read_bytes

    def buffered_read(self, buffer: Buffer) -> int:
        while bytes_written := self.readinto(buffer):
            yield buffer.rtrim(bytes_written) # remove unused bytes, if any

    def write(self, _bytes: bytes, *, inplace=False) -> int:
        if inplace:
            self._backtrack()

        return self._stream.write(_bytes)

    def close(self):
        self._stream.close()

    @property
    def last_read_bytes(self):
        return self._last_read_bytes

    @property
    def name(self) -> str:
        return self._name

    @property
    def stream(self) -> io.IOBase:
        return self._stream

class EncryptedFileHandler:
    BASE64_ALIGNMENT = 3

    def __init__(self, file_list: List[str], parallel: int, buf_len: int):
        self._buffer_alignment = self.BASE64_ALIGNMENT
        
        self._files = len(file_list)
        self._file_list = self._open_files(file_list)

        self._parallel = self._parallel_instances(parallel)

        self._buf_len = self._align(buf_len)
        self._buffers = self._build_buffers()


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if traceback:
            print(f'An error occurred: {exc_value}', file=sys.stderr)

        for file in self._file_list:
            file.close()

    def _align(self, num: int) -> int:
        return (num
                if (rem := num % self._buffer_alignment) == 0 
                else num + (self._buffer_alignment - rem))

    def _open_files(self, file_list: List[str]) -> List[io.BufferedRandom]:
        return [File(f) for f in file_list]

    def _parallel_instances(self, parallel: int) -> int:
        return parallel if self._files > parallel else self._files

    def _build_buffers(self) -> List[bytearray]:
        return [Buffer(self._buf_len) for _ in range(self._parallel)]

    def _handle_file(self, file: File) -> str:
        buf = self._buffers.pop() # get a buffer
        chunks: List[Buffer] = []

        for data in file.buffered_read(buf):
            encoded_bytes = base64.encodebytes(data)

            to_write = try_pop(chunks, default=b'') + encoded_bytes
            chunks += buf.fit_bytes(to_write) # fit bytes into a Buffer array
            
            file.write(chunks.pop(0), inplace=True)

        self._buffers.append(buf) # release buffer

        while remaining := try_pop(chunks, 0, default=b''):
            file.write(remaining)

        return file.name

    def process_files(self):
        with pool.ThreadPool(processes=self._parallel) as instances_pool:
            print(f'Starting process!')
            for file in instances_pool.imap_unordered(self._handle_file,
                                                      self._file_list):
                print(f'Successfully processed file: {file}')
            print(f'Finished processing')

    @property
    def buf_len(self) -> int:
        return self._buf_len

    @property
    def files(self) -> int:
        return self._files

class HTTPStream:
    def __init__(self, stream: io.IOBase):
        self._stream = stream

    def buffered_read(self, buffer: Buffer):
        while bytes_written := self._stream.readinto(buffer):
            yield buffer.rtrim(bytes_written)

class Ubook:
    LOGIN_URL: Final[str] = "https://www.ubook.com/login/index/target/default"
    DECODE_URL: Final[str] = "https://www.ubook.com/playerExternal/decryptEpub"
    EBOOK_PATH_URL: Final[str] = "https://www.ubook.com/reader/EbookPathDetail"

    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

        self._cookies = self._create_cookies()
        self._headers = self._create_headers()

        self._stub_key = self._generate_stub_pk()

    def __enter__(self):
        self._sess = requests.Session()

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._sess.close()

        if traceback:
            print(f'An error occurred: {exc_value}', file=sys.stderr)

    def perform_login(self) -> bool:
        payload = self._create_login_payload()
        response = self._sess.post(url=self.LOGIN_URL,
                                   cookies=self._cookies,
                                   headers=self._headers,
                                   data=payload)

        return response.ok

    def fetch_ebook_url(self, ebook_code: str) -> Optional[str]:
        payload = self._create_ebook_path_payload(ebook_code)
        response = self._sess.post(url=self.EBOOK_PATH_URL,
                                   cookies=self._cookies,
                                   headers=self._headers,
                                   data=payload)

        if response.ok:
            content_raw = response.json()['data']['url_content'].encode()
            decoded_url = base64.decodebytes(content_raw)

            return "http://" + decoded_url.replace(b'//', b'', 1).decode()

    def decode_ebook_file(self, ebook_code: str, file_name: str) -> HTTPStream:
        payload = self._create_ebook_file_decode_payload(ebook_code=ebook_code, 
                                                         file_name=file_name)
        response = self._sess.post(url=self.DECODE_URL,
                                   cookies=self._cookies,
                                   headers=self._headers,
                                   data=payload,
                                   stream=True)

        response.raw.decode_content = True

        return HTTPStream(response.raw)


    def _create_ebook_file_decode_payload(self,
                                          ebook_code: str,
                                          file_name: str) -> Mapping[str, str]:
        with open(file_name, 'r') as enc_file:
            data = enc_file.buffer.raw.readall()

            return {
                'buffer': data,#base64.encodebytes(data),
                'catalog_item_id': ebook_code,
            }


    def _coin_toss(self) -> bool: return math.floor(random.random() * 11) > 5
    def _generate_sess_id(self,
                          size: int = 26,
                          alphabet_range: Tuple[int, int] = (97, 123),
                          integer_range: Tuple[int, int] = (0, 10)) -> str:
        return ''.join([
            chr(random.randrange(*alphabet_range)) if self._coin_toss()
            else str(random.randrange(*integer_range))
            for _ in range(size)
        ])

    def _create_cookies(self) -> Mapping[str, str]:
        device = str(uuid.uuid4()).capitalize()
        user_session = str(uuid.uuid4())
        sess_id = self._generate_sess_id()

        return {
            'device': device,
            'user_session': user_session,
            'PHPSESSID': sess_id,
            'accept-cookies': '1',
        }

    def _create_headers(self) -> Mapping[str, str]:
        return {
            'authority': 'www.ubook.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-GB,en;q=0.9',
            'cache-control': 'max-age=0',
            'origin': 'https://www.ubook.com',
            'referer': 'https://www.ubook.com/login',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Brave";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'sec-gpc': '1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
        }

    def _create_login_payload(self) -> Mapping[str, str]:
        return {
            'store': '',
            'is_action_amais': '',
            'callback': '',
            'CustomerLoginForm[username]': f'{self._username}',
            'CustomerLoginForm[password]': f'{self._password}',
            'CustomerLoginForm[remember_me]': '0',
            'yt0': 'Entrar',
        }

    def _create_ebook_path_payload(self, id: str) -> Mapping[str, str]:
        return {
            'id': id,
            #'public_key': 'pk'
            'public_key': self._stub_key,
        }

    def _generate_stub_pk(self):
        prk = rsa.generate_private_key(3, 512)
        puk = prk.public_key().public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return puk.rstrip(b'\n').decode()



import re
from zipfile import ZipFile, ZIP_DEFLATED

class Downloader:
    def __init__(
        self,
        url: str,
        output: Optional[str] = None,
        *,
        buf_size: int = 512,
    ):
        self._url = url

        self._buffer = self._build_buffer(buf_size)

        self._file = self._create_byte_file(output)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if traceback:
            print(f'[{type(self).__name__}] An error occurred: {exc_value}',
                  file=sys.stderr)
    
        if self._temp_file is not None:
            self._temp_file.cleanup()
        else:
            self._file.close()

    @property
    def name(self):
        return self._file.name

    def _build_buffer(self, size: int) -> Buffer:
        return Buffer(size * (2**10))

    def _create_byte_file(self, output: str) -> File:
        if output is None:
            return File.temporary('xb+')

        return File(output, 'xb+')

    def download(self) -> File:
        with requests.get(self._url, stream=True) as response:
            stream = HTTPStream(response.raw)

            for data in stream.buffered_read(self._buffer):
                self._file.write(data)
                print(f'Wrote to file: {self._file}')

        self._file.rewind()

        return self._file

import tempfile
from dataclasses import dataclass

@dataclass
class Extracted:
    path: str
    name: str

    @property
    def full_path(self) -> str:
        return os.path.join(self.path, self.name)

class Epub:
    def __init__(self, input_: File, output: str):
        self._input = ZipFile(input_.stream)
        self._output = self._output_as_zip(output)

        self._extracted_files = []

        self._tmp_ext_dir = tempfile.TemporaryDirectory(dir='/tmp')

        self._not_essential_meta_file_regex = (
                self._build_not_essential_meta_file_regex())
        self._is_content_file_regex = self._build_is_content_file_regex()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if traceback:
            print(f'An error occurred: {exc_value}', file=sys.stderr)

        self._tmp_ext_dir.cleanup()

    @property
    def path(self):
        return self._tmp_ext_dir.name

    def _build_not_essential_meta_file_regex(self) -> re.Pattern:
        essentials = ['container.xml', 'manifest.xml', 'metadata.xml']
        return re.compile('META-INF/.+'
                          f"{''.join([f'(?<!{e})' for e in essentials])}"
                          '$')

    def _build_is_content_file_regex(self) -> re.Pattern:
        return re.compile(f'OEBPS/.*\.(x?)html')

    def _path_data(self, fullpath: str) -> Tuple[str, str]:
        path, name = os.path.split(fullpath)
        name_only, ext = os.path.splitext(name)

        return os.path.normpath(path), name, name_only, ext[1:]

    def _valid_output_name(self, output: str) -> str:
        path, full_name, name, ext = self._path_data(output)

        curr_path = os.getcwd()
        os.chdir(path)

        idx = 1
        while os.path.exists(full_name):
            full_name = f'{name} ({idx}).{ext}'
            idx += 1

        os.chdir(curr_path)

        return full_name

    def _output_as_zip(self, output: str) -> ZipFile:
        valid_output = self._valid_output_name(output)

        return ZipFile(file=valid_output,
                       mode='x',
                       compression=ZIP_DEFLATED,
                       compresslevel=9)

    def _is_content_file(self, path: str) -> bool:
        return self._is_content_file_regex.match(path) is not None

    def _is_not_essential_meta_file(self, path: str) -> bool:
        return self._not_essential_meta_file_regex.match(path) is not None

    def extract(self) -> List[Extracted]:
        self._input.extractall(self._tmp_ext_dir.name)

        self._extracted_files = [
            Extracted(path=self._tmp_ext_dir.name, name=name)
            for name in self._input.namelist()
        ]

        return self._extracted_files

    def content_files(self) -> List[Extracted]:
        return [xf
                for xf in self._extracted_files
                if self._is_content_file(xf.name)]

    def remove(self, to_remove: List[Extracted] = []) -> None:
        for xf in to_remove:
            self._extracted_files.remove(xf)

    def compact(self) -> None:
        print(f"Output: {self._output}")
        for xf in self._extracted_files:
            print(f"{xf.full_path} -> {xf.name}")
            self._output.write(xf.full_path, xf.name)

    def drm_files(self) -> List[Extracted]:
        return [xf
                for xf in self._extracted_files
                if self._is_not_essential_meta_file(xf.name)]



        #epub_as_zip = _download_file()
        #
        #tmp = tmpfile.TemporaryDirectory(dir='/tmp')
        #
        #epub_as_zip.extractall(tmp.name)
        #
        #extracted = [(os.path.join(tmp.name, f), f) for f in epub_as_zip.namelist()]
        #
        #to_be_decrypted = [f for f in extracted if re.match(f'{tmp.name}/OEBPS/.*\.(x?)html', f) is not None]
        #...
        # output = ZipFile('output_final.epub', mode='x', compression=ZIP_DEFLATED, compresslevel=9)
        # [output.write(f[0], f[1]) for f in extracted]
        #
        # tmp.cleanup()
        #
        # remover output temporário!!!








#if __name__ == '__main__':
#    with EncryptedFileHandler(file_list=sys.argv[1:], parallel=15, buf_len=2**20) as handler:
#        handler.process_files()


import os
import time
if __name__ == '__main__':
    username = input("email: ")
    password = getpass("password: ")

    download_buffer = 512 # 512KiB

    code = '1100066'
    output = '/tmp/ebooks_ubook/testing.epub'

    with Ubook(username=username, password=password) as ubook:
        if not ubook.perform_login():
            print(f'Unable to login for {username=}', file=sys.stderr)
            sys.exit(1)

        url = ubook.fetch_ebook_url(code)
        print(f'url: {url}\n')
        downloader = Downloader(url=url, buf_size=download_buffer)

        ebook_file = downloader.download()
        print(f'ebook: {ebook_file}')

        epub = Epub(ebook_file, output)
        print(f'epub: {epub}')

        epub.extract()

        content = epub.content_files()
        drm = epub.drm_files()

        print(f'len: {len(epub._extracted_files)}')
        print(f'Content: {content}')
        print(f'DRM: {drm}')

        print(f'type: {type(epub)}')
        epub.remove(drm)
        print(f'len: {len(epub._extracted_files)}')

        print("Starting to decrypt!")
        file_list = [c.full_path for c in content]
        with EncryptedFileHandler(
            file_list=file_list,
            parallel=15,
            buf_len=2**20
        ) as handler:
            handler.process_files()
            buf = Buffer(512 * 2**10)
            for co in content:
                f = co.name
                print(f'Full path: {co.full_path}')
                decoded = ubook.decode_ebook_file(code, co.full_path)
                print(f'Decoded: {decoded}')
                print(f'Writing: {f}')
                #outter = open('/tmp/_ebooks' + f.split('/')[-1], 'xb')
                outter = open(co.full_path, "wb")
                print(outter)
                #print(decoded.read())
                #print(ubook.decode_ebook_file(code, './_more_test/OEBPS/Text/advertencia.xhtml').read())
                for data in decoded.buffered_read(buf):
                    outter.write(data)
                #while bytes_written := decoded.readinto(buf):
                #    outter.write(buf.rtrim(bytes_written))
                outter.close()


        print("Decrypted!")

        epub.compact()
        print("Compacted decrypted data!")

        # clean up
        ebook_file.close()
            
            #print(ubook.decode_ebook_file(code, './_more_test/OEBPS/Text/advertencia.xhtml'))


