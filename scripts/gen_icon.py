from PIL import Image, ImageDraw, ImageFont
import os

out = r"D:\winrarsetup\src\resources\app.ico"
sizes = [16,32,48,64,128,256]
imgs = []
for sz in sizes:
    im = Image.new("RGBA", (sz, sz), (0,0,0,0))
    d = ImageDraw.Draw(im)
    pad = max(1, sz//16)
    d.rounded_rectangle((pad, pad, sz-pad-1, sz-pad-1), radius=sz//6, fill=(30,90,180,255), outline=(20,60,140,255), width=max(1,sz//16))
    try:
        font = ImageFont.truetype("arial.ttf", int(sz*0.55))
    except Exception:
        font = ImageFont.load_default()
    txt = "W"
    bbox = d.textbbox((0,0), txt, font=font)
    tw = bbox[2]-bbox[0]
    th = bbox[3]-bbox[1]
    x = (sz - tw)//2 - bbox[0]
    y = (sz - th)//2 - bbox[1]
    d.text((x,y), txt, fill=(255,255,255,255), font=font)
    imgs.append(im)

imgs[0].save(out, format="ICO", sizes=[(im.width, im.height) for im in imgs], append_images=imgs[1:])
print("saved", out, os.path.getsize(out))