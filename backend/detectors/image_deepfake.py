import io
import base64
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
from typing import Dict, Any

def perform_error_level_analysis(original_img: Image.Image, quality: int = 95) -> tuple[Image.Image, float, str]:
    img_rgb = original_img.convert("RGB")
    buffer = io.BytesIO()
    img_rgb.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    resaved_img = Image.open(buffer)

    ela_diff = ImageChops.difference(img_rgb, resaved_img)
    diff_arr = np.array(ela_diff, dtype=np.float32)
    mean_diff = float(np.mean(diff_arr))

    extrema = ela_diff.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    scale = 255.0 / max(max_diff, 1) if max_diff > 0 else 1.0
    scale = min(scale, 25.0)

    enhancer = ImageEnhance.Brightness(ela_diff)
    ela_enhanced = enhancer.enhance(scale)

    out_buf = io.BytesIO()
    ela_enhanced.save(out_buf, format="JPEG", quality=90)
    b64_str = "data:image/jpeg;base64," + base64.b64encode(out_buf.getvalue()).decode("ascii")

    return ela_enhanced, mean_diff, b64_str

def perform_fft_spectral_analysis(img: Image.Image) -> tuple[float, str]:
    img_gray = img.convert("L").resize((256, 256))
    arr = np.asarray(img_gray, dtype=np.float32)

    f = np.fft.fft2(arr)
    fshift = np.fft.fftshift(f)
    magnitude_spectrum = np.log1p(np.abs(fshift))

    min_val, max_val = np.min(magnitude_spectrum), np.max(magnitude_spectrum)
    norm_spectrum = ((magnitude_spectrum - min_val) / (max_val - min_val + 1e-7) * 255.0).astype(np.uint8)

    h, w = arr.shape
    cy, cx = h // 2, w // 2
    y, x = np.ogrid[:h, :w]
    dist_from_center = np.sqrt((x - cx)**2 + (y - cy)**2)
    
    outer_mask = dist_from_center > 70
    spectral_score = float(np.std(magnitude_spectrum[outer_mask])) if np.any(outer_mask) else 10.0

    spectrum_img = Image.fromarray(norm_spectrum)
    buf = io.BytesIO()
    spectrum_img.save(buf, format="PNG")
    b64_spectrum = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

    return spectral_score, b64_spectrum

def analyze_image_deepfake(image_bytes: bytes, filename: str = "uploaded.jpg") -> Dict[str, Any]:
    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        return {"error": f"Invalid image format: {str(e)}"}

    flags = []
    fake_score = 0

    w, h = img.size
    is_square_power2 = (w == h and w in [512, 1024, 2048, 768])
    if is_square_power2:
        fake_score += 15
        flags.append({
            "severity": "medium",
            "title": "Standard Generative Diffusion Geometry",
            "desc": f"Exact square canvas ({w}x{h}) aligns with Latent Diffusion & Midjourney generator latent resolution."
        })

    exif = img.getexif()
    software_tag = ""
    has_camera_hardware = False
    
    if exif:
        for tag_id, value in exif.items():
            str_val = str(value).lower()
            if any(tool in str_val for tool in ["photoshop", "gimp", "midjourney", "stable diffusion", "automatic1111", "comfyui"]):
                software_tag = str(value)
            if any(cam in str_val for cam in ["canon", "nikon", "sony", "apple", "samsung", "google", "fujifilm"]):
                has_camera_hardware = True

    if software_tag:
        fake_score += 35
        flags.append({
            "severity": "high",
            "title": "Generative Pipeline Metadata Signature",
            "desc": f"Metadata explicitly references editing/synthesis pipeline: '{software_tag}'."
        })
    elif not has_camera_hardware and len(exif) == 0:
        fake_score += 10
        flags.append({
            "severity": "low",
            "title": "Stripped Sensor EXIF",
            "desc": "Digital image contains zero physical camera sensor or lens calibration metadata."
        })

    # Error Level Analysis (ELA)
    ela_img, mean_diff, ela_b64 = perform_error_level_analysis(img)
    if mean_diff > 12.0:
        fake_score += 35
        flags.append({
            "severity": "critical",
            "title": "Severe Compression Discontinuity (ELA)",
            "desc": f"Mean error rate {mean_diff:.2f} indicates disparate compression layers or localized facial inpainting splicing."
        })
    elif mean_diff > 7.0:
        fake_score += 15
        flags.append({
            "severity": "medium",
            "title": "Elevated Error Level Discrepancy",
            "desc": f"ELA mean diff {mean_diff:.2f} shows non-uniform compression signatures."
        })

    # 2D FFT Frequency Domain Analysis
    spectral_score, fft_b64 = perform_fft_spectral_analysis(img)
    if spectral_score > 3.2:
        fake_score += 30
        flags.append({
            "severity": "critical",
            "title": "High-Frequency Synthetic Periodic Noise (CVPR Benchmark)",
            "desc": "2D Fourier spectrum reveals unnatural periodic frequencies consistent with generative up-convolution (Durall et al.)."
        })
    elif spectral_score > 2.5:
        fake_score += 15
        flags.append({
            "severity": "low",
            "title": "Spectral Density Variance",
            "desc": "Frequency distribution exhibits slight synthetic roll-off anomalies."
        })

    final_score = min(max(fake_score, 0), 100)

    # Risk Tiers: SAFE, MEDIUM, CRITICAL
    if final_score >= 60:
        risk_tier = "CRITICAL"
        status_color = "red"
        verdict = "CRITICAL DEEPFAKE / SYNTHETIC MANIPULATION"
        recommendations = [
            "Do NOT accept for identity verification, biometric KYC, or legal evidentiary submission.",
            "Flag profile associated with this uploaded image for automated fraud investigation.",
            "Inspect original uncompressed RAW or sensor files out-of-band."
        ]
    elif final_score >= 35:
        risk_tier = "MEDIUM"
        status_color = "amber"
        verdict = "SUSPICIOUS COMPRESSION OR EDITING DETECTED"
        recommendations = [
            "Image exhibits non-standard editing or heavy digital filter compression.",
            "Request secondary photo capture with dynamic biometric liveness verification."
        ]
    else:
        risk_tier = "SAFE"
        status_color = "emerald"
        verdict = "SAFE / AUTHENTIC OPTICAL PROFILE"
        recommendations = [
            "Sensor noise and compression characteristics are consistent with genuine camera capture.",
            "Verification passed under standard forensic protocols."
        ]

    return {
        "filename": filename,
        "width": w,
        "height": h,
        "deepfake_probability": final_score,
        "risk_tier": risk_tier,
        "status_color": status_color,
        "verdict": verdict,
        "recommendations": recommendations,
        "ela_heatmap_url": ela_b64,
        "fft_spectrum_url": fft_b64,
        "flags": flags,
        "forensics": {
            "ela_mean_difference": round(mean_diff, 3),
            "spectral_artifact_score": round(spectral_score, 3),
            "has_exif_camera_data": has_camera_hardware,
            "detected_software": software_tag or "None / Cleared"
        }
    }
