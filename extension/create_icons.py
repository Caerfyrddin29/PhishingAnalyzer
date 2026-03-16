# Simple icon creation script
# This creates basic placeholder icons for the extension

import os
from PIL import Image, ImageDraw, ImageFont

def create_icon(size, output_path):
    """Create a simple shield icon"""
    # Create image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw shield shape
    margin = size // 8
    shield_points = [
        (size // 2, margin),  # Top point
        (size - margin, size // 3),  # Right upper
        (size - margin, size - margin),  # Right lower
        (size // 2, size - margin // 2),  # Bottom point
        (margin, size - margin),  # Left lower
        (margin, size // 3),  # Left upper
    ]
    
    # Draw shield
    draw.polygon(shield_points, fill=(68, 136, 255, 255), outline=(255, 255, 255, 255), width=2)
    
    # Draw checkmark
    check_size = size // 4
    check_margin = size // 3
    draw.line([
        (check_margin, size // 2),
        (size // 2 - check_size // 4, size - check_margin),
        (size - check_margin, check_margin + check_size // 2)
    ], fill=(255, 255, 255, 255), width=size // 16, joint='round')
    
    img.save(output_path)
    print(f"Created {output_path}")

def create_icons():
    """Create all required icon sizes"""
    icons_dir = os.path.join(os.path.dirname(__file__), 'icons')
    os.makedirs(icons_dir, exist_ok=True)
    
    sizes = [16, 48, 128]
    for size in sizes:
        output_path = os.path.join(icons_dir, f'icon{size}.png')
        create_icon(size, output_path)

if __name__ == "__main__":
    create_icons()
    print("Extension icons created successfully!")
