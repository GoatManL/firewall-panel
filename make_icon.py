import os
from PIL import Image, ImageDraw

size = 256
img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)
draw.rounded_rectangle([10, 10, size - 10, size - 10], radius=40, fill=(120, 120, 120, 255))
draw.text((size // 2, size // 2), "W", fill=(255, 255, 255, 255), anchor="mm")
os.makedirs("assets", exist_ok=True)
img.save("assets/icon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
print("Icon generated.")
