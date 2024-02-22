# 导入必要的库
import os
import sys
import base64
import hashlib
import time
from Crypto.Cipher import AES
from Crypto import Random


# 定义加密和解密的函数
def encrypt_file(key, in_filename, out_filename=None):
    # 如果没有指定输出文件名，则在输入文件名后加上".enc"后缀
    if not out_filename:
        out_filename = in_filename + '.enc'
    time_stamp = int(time.time())
    # 16 字节的时间戳字符串用作散列盐
    time_salt = str(time_stamp).zfill(16)
    # 用密码生成一个32字节的密钥
    key = hashlib.sha256((key + time_salt).encode()).digest()
    # 生成16字节的随机初始向量
    iv = Random.new().read(AES.block_size)
    # 创建AES加密器
    encryptor = AES.new(key, AES.MODE_GCM, iv)
    h = hashlib.sha256()
    # 以二进制模式打开输入文件
    with open(in_filename, 'rb') as infile:
        for chunk in iter(lambda: infile.read(4096), b''):
            # 向哈希对象输入数据
            h.update(chunk)
        file_hash = h.digest()
        # 以二进制模式打开输出文件
        with open(out_filename, 'wb') as outfile:
            # 写入初始向量
            outfile.write(iv)
            # 写入时间戳盐
            outfile.write(time_salt.encode())
            # 写入哈希值
            outfile.write(file_hash)
            # 将输入文件指针指向起始位置
            infile.seek(0)
            # 读取输入文件的内容，每次读取一个块（16字节）
            while True:
                chunk = infile.read(16)
                # 如果到达文件末尾，跳出循环
                if len(chunk) == 0:
                    break
                # 如果块的长度不足16字节，补齐
                elif len(chunk) % 16 != 0:
                    pad_len = (16 - len(chunk) % 16)
                    # 填充 pad_len 个二进制数字 pad_len, pad_len 为填充字节数，
                    chunk += pad_len.to_bytes(1, byteorder='big') * (pad_len)
                # 写入加密后的块
                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None):
    # 如果没有指定输出文件名，则去掉输入文件名的".enc"后缀
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
    # 以二进制模式打开输入文件
    with open(in_filename, 'rb') as infile:
        # 读取初始向量
        iv = infile.read(16)
        time_salt = infile.read(16).decode()
        file_hash = infile.read(32)
        h = hashlib.sha256()
        # 用密码生成一个32字节的密钥
        key = hashlib.sha256((key + time_salt).encode()).digest()
        # 创建AES解密器
        decryptor = AES.new(key, AES.MODE_GCM, iv)
        # 以二进制模式打开输出文件
        with open(out_filename, 'wb') as outfile:
            # 读取输入文件的内容，每次读取一个块（16字节）
            while True:
                pad_len = 0
                chunk = infile.read(16)
                # 如果到达文件末尾，跳出循环
                if len(chunk) == 0:
                    break
                d_chunk = decryptor.decrypt(chunk)
                # 如果文件最后为二进制数字 1~16, 则去除填充的数字
                if int.from_bytes(d_chunk[-1:], byteorder='big') >= 1 and int.from_bytes(d_chunk[-1:], byteorder='big') < 16:
                    pad_len = int.from_bytes(d_chunk[-1:], byteorder='big')
                    # 判断是否为 pad_len 个连续的 pad_len
                    for i in range(-pad_len, -2):
                        if int.from_bytes(d_chunk[i:i+1], byteorder='big') != pad_len:
                            pad_len = 0
                            break
                if pad_len != 0:
                    d_chunk = d_chunk[:-pad_len]
                # 写入解密后的块
                outfile.write(d_chunk)
                h.update(d_chunk)
        print('-- Decrypted finished. --')
        print('-- Integrity: --')
        print(h.digest() == file_hash)


def print_help():
    print(
        "Usage: python encrypt-file.py [-p password] [-e/-d] [-f filename]")
    sys.exit(0)


def main():
    filename = 'FILE_DEFAULT'
    password = '0000'
    # 获取命令行参数
    args = sys.argv
    if len(args) < 2:
        print_help()
    # 获取密码，模式和文件名
    if '-e' in args:
        mode = 'encrypt'
    elif '-d' in args:
        mode = 'decrypt'
    else:
        print_help()
    if '-p' not in args or '-f' not in args:
        print_help()
    else:
        p_index = args.index("-p")
        password = args[p_index + 1]
        f_index = args.index("-f")
        filename = args[f_index + 1]
    # 根据模式调用相应的函数
    if mode == 'encrypt':
        encrypt_file(password, filename)
    elif mode == 'decrypt':
        decrypt_file(password, filename)
    else:
        print("Invalid mode: must be encrypt or decrypt")
        sys.exit(0)


main()
