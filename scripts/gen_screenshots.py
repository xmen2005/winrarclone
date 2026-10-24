from PIL import Image, ImageDraw, ImageFont
import os

out_dir = r"D:\winrarsetup\docs\screenshots"
os.makedirs(out_dir, exist_ok=True)

names = ["main"]
for name in names:
    im = Image.new("RGB", (800, 500), (240, 240, 240))
    d = ImageDraw.Draw(im)
    d.rectangle((0,0,799,499), outline=(180,180,180), width=2)
    d.text((20,20), f"Screenshot placeholder: {name}", fill=(80,80,80))
    d.text((20,60), "Replace with a real screenshot.", fill=(120,120,120))
    im.save(os.path.join(out_dir, name + ".png"))
    print("saved", name)