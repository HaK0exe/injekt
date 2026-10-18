#!/usr/bin/env python3
"""Convert an image into textmode ASCII art for INJEKT. Requires Pillow."""
import argparse
from PIL import Image, ImageOps, ImageEnhance, ImageFilter

# Ordered from darkest character (empty) to most visually dense.
RAMPS = {
    'detailed': ' .`^",:;Il!i><~+_-?][}{1)(|\\/tfjrxnuvczXYUJCLQ0OZmwqpdbkhao*#MW&8%B@$',
    'medium': ' .,:-~=+*#%@',
    'technical': ' .:-=+*#%@',
}

def convert(path, width=104, ratio=0.48, contrast=1.75, gamma=0.85,
            invert=False, ramp='detailed', threshold=7):
    img = Image.open(path).convert('RGBA')
    # Put transparent assets on solid black canvas for white-on-black terminal art.
    bg = Image.new('RGBA', img.size, (0,0,0,255))
    bg.alpha_composite(img)
    img = bg.convert('L')
    if invert:
        img = ImageOps.invert(img)
    height = max(1, round(width * img.height / img.width * ratio))
    img = img.resize((width, height), Image.Resampling.LANCZOS)
    img = ImageEnhance.Contrast(img).enhance(contrast)
    lut = [round(255 * (v / 255) ** gamma) for v in range(256)]
    img = img.point(lut)
    chars = RAMPS[ramp]
    pixels = list(img.get_flattened_data())
    lines=[]
    for y in range(height):
        row=''.join(' ' if p < threshold else chars[round((len(chars)-1)*p/255)] for p in pixels[y*width:(y+1)*width])
        lines.append(row.rstrip())
    while lines and not lines[0].strip(): lines.pop(0)
    while lines and not lines[-1].strip(): lines.pop()
    return '\n'.join(lines)

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image')
    ap.add_argument('-w','--width',type=int,default=104)
    ap.add_argument('--cell-ratio',type=float,default=0.48)
    ap.add_argument('--contrast',type=float,default=1.75)
    ap.add_argument('--gamma',type=float,default=0.85)
    ap.add_argument('--invert',action='store_true')
    ap.add_argument('--ramp',choices=RAMPS,default='detailed')
    args=ap.parse_args()
    print(convert(args.image,args.width,args.cell_ratio,args.contrast,args.gamma,args.invert,args.ramp))
