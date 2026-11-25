use anyhow::{bail, Context, Result};
use image::codecs::ico::{IcoEncoder, IcoFrame};
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::codecs::webp::WebPEncoder;
use image::metadata::Orientation;
use image::{
    DynamicImage, ExtendedColorType, ImageDecoder, ImageEncoder, ImageFormat, ImageReader,
    RgbaImage,
};
use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::fsutil;

pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_IMAGE_PIXELS: u64 = 256_000_000;
pub const MAX_IMAGE_SIDE: u32 = 16_384;
const JPEG_QUALITY: u8 = 90;
const ICON_SIZES: [u32; 7] = [16, 24, 32, 48, 64, 128, 256];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceFormat {
    Png,
    Jpeg,
    WebP,
    Ico,
    Avif,
}

pub struct ProcessedImage {
    pub package_name: String,
    pub bytes: Vec<u8>,
    pub source: PathBuf,
}

pub fn process_icon(source: &Path) -> Result<ProcessedImage> {
    let bytes = fsutil::read_limited(source, MAX_IMAGE_BYTES, "icon image")?;
    let format = detect_format(&bytes)?;
    let image = decode(&bytes, format)?;
    let rgba = image.to_rgba8();

    let mut frames = Vec::with_capacity(ICON_SIZES.len());
    for size in ICON_SIZES {
        let square = fit_square(&rgba, size);
        let frame = IcoFrame::as_png(
            square.as_raw(),
            square.width(),
            square.height(),
            ExtendedColorType::Rgba8,
        )
        .context("failed to encode icon frame")?;
        frames.push(frame);
    }
    let mut output = Vec::new();
    IcoEncoder::new(&mut output)
        .encode_images(&frames)
        .context("failed to re-encode icon as ICO")?;
    check_output_size("icon", output.len())?;

    Ok(ProcessedImage {
        package_name: "assets/icon.ico".into(),
        bytes: output,
        source: source.to_path_buf(),
    })
}

fn fit_square(source: &RgbaImage, size: u32) -> RgbaImage {
    let width = source.width().max(1);
    let height = source.height().max(1);
    let scale = (size as f64 / width as f64).min(size as f64 / height as f64);
    let target_width = ((width as f64 * scale).round() as u32).clamp(1, size);
    let target_height = ((height as f64 * scale).round() as u32).clamp(1, size);
    let resized = if target_width == width && target_height == height {
        source.clone()
    } else {
        image::imageops::resize(
            source,
            target_width,
            target_height,
            image::imageops::FilterType::Lanczos3,
        )
    };
    let mut canvas = RgbaImage::new(size, size);
    let x = i64::from((size - target_width) / 2);
    let y = i64::from((size - target_height) / 2);
    image::imageops::overlay(&mut canvas, &resized, x, y);
    canvas
}

pub fn process_background(source: &Path) -> Result<ProcessedImage> {
    let bytes = fsutil::read_limited(source, MAX_IMAGE_BYTES, "background image")?;
    let format = detect_format(&bytes)?;
    if format == SourceFormat::Ico {
        bail!("ICO is not a supported background format");
    }
    let image = decode(&bytes, format)?;
    let rgba = image.to_rgba8();

    let (extension, output) = match format {
        SourceFormat::Png => {
            let mut output = Vec::new();
            PngEncoder::new(&mut output)
                .write_image(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    ExtendedColorType::Rgba8,
                )
                .context("failed to re-encode background as PNG")?;
            ("png", output)
        }
        SourceFormat::Jpeg => {
            let rgb = image.to_rgb8();
            let mut output = Vec::new();
            JpegEncoder::new_with_quality(&mut output, JPEG_QUALITY)
                .write_image(
                    rgb.as_raw(),
                    rgb.width(),
                    rgb.height(),
                    ExtendedColorType::Rgb8,
                )
                .context("failed to re-encode background as JPEG")?;
            ("jpg", output)
        }
        SourceFormat::WebP => {
            let mut output = Vec::new();
            WebPEncoder::new_lossless(&mut output)
                .encode(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    ExtendedColorType::Rgba8,
                )
                .context("failed to re-encode background as WebP")?;
            ("webp", output)
        }
        SourceFormat::Avif => {
            // AVIF is decoded to pixels and stored as lossless WebP, which the
            // runtime supports. This strips AVIF container metadata as well.
            let mut output = Vec::new();
            WebPEncoder::new_lossless(&mut output)
                .encode(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    ExtendedColorType::Rgba8,
                )
                .context("failed to re-encode AVIF background as WebP")?;
            ("webp", output)
        }
        SourceFormat::Ico => unreachable!(),
    };
    check_output_size("background", output.len())?;

    Ok(ProcessedImage {
        package_name: format!("assets/background.{extension}"),
        bytes: output,
        source: source.to_path_buf(),
    })
}

fn detect_format(bytes: &[u8]) -> Result<SourceFormat> {
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" && oxideav_avif::probe(bytes) {
        return Ok(SourceFormat::Avif);
    }
    let format = image::guess_format(bytes).context("unrecognized image format")?;
    match format {
        ImageFormat::Png => Ok(SourceFormat::Png),
        ImageFormat::Jpeg => Ok(SourceFormat::Jpeg),
        ImageFormat::WebP => Ok(SourceFormat::WebP),
        ImageFormat::Ico => Ok(SourceFormat::Ico),
        other => bail!("unsupported image format: {other:?}"),
    }
}

fn decode(bytes: &[u8], format: SourceFormat) -> Result<DynamicImage> {
    match format {
        SourceFormat::Avif => {
            let info = oxideav_avif::info(bytes).context("failed to parse AVIF header")?;
            check_dimensions(info.width, info.height)?;
            let image = oxideav_avif::decode_rgba8(bytes).context("failed to decode AVIF image")?;
            check_dimensions(image.width, image.height)?;
            let image = RgbaImage::from_raw(image.width, image.height, image.data)
                .context("AVIF decoder returned an invalid pixel buffer")?;
            Ok(DynamicImage::ImageRgba8(image))
        }
        _ => {
            let mut decoder = ImageReader::new(Cursor::new(bytes))
                .with_guessed_format()
                .context("failed to inspect image")?
                .into_decoder()
                .context("failed to create image decoder")?;
            let (width, height) = decoder.dimensions();
            check_dimensions(width, height)?;
            let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
            let mut image =
                DynamicImage::from_decoder(decoder).context("failed to decode image")?;
            check_dimensions(image.width(), image.height())?;
            image.apply_orientation(orientation);
            Ok(image)
        }
    }
}

fn check_dimensions(width: u32, height: u32) -> Result<()> {
    if width == 0 || height == 0 {
        bail!("image has zero width or height");
    }
    if width > MAX_IMAGE_SIDE || height > MAX_IMAGE_SIDE {
        bail!("image side exceeds {MAX_IMAGE_SIDE} pixels: {width}x{height}");
    }
    let pixels = u64::from(width) * u64::from(height);
    if pixels > MAX_IMAGE_PIXELS {
        bail!("image exceeds {MAX_IMAGE_PIXELS} pixels: {width}x{height}");
    }
    Ok(())
}

fn check_output_size(kind: &str, size: usize) -> Result<()> {
    if size as u64 > MAX_IMAGE_BYTES {
        bail!("re-encoded {kind} is larger than 64 MiB");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgba, RgbaImage};

    fn png_bytes() -> Vec<u8> {
        let image = RgbaImage::from_pixel(4, 4, Rgba([30, 60, 90, 255]));
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(image.as_raw(), 4, 4, ExtendedColorType::Rgba8)
            .unwrap();
        bytes
    }

    #[test]
    fn reencodes_png_background() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("background.png");
        std::fs::write(&path, png_bytes()).unwrap();
        let processed = process_background(&path).unwrap();
        assert_eq!(processed.package_name, "assets/background.png");
        assert!(processed.bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    }

    #[test]
    fn converts_png_icon_to_ico() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("icon.png");
        std::fs::write(&path, png_bytes()).unwrap();
        let processed = process_icon(&path).unwrap();
        assert_eq!(processed.package_name, "assets/icon.ico");
        assert!(processed.bytes.starts_with(&[0, 0, 1, 0]));
    }

    #[test]
    fn converts_avif_background_to_webp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("background.avif");
        let rgba = [
            30u8, 60, 90, 255, 10, 20, 30, 255, 40, 50, 60, 255, 70, 80, 90, 255,
        ];
        let bytes = oxideav_avif::encode_rgba8(
            2,
            2,
            &rgba,
            &oxideav_avif::EncodeOptions::default().with_lossless(true),
        )
        .unwrap();
        std::fs::write(&path, bytes).unwrap();
        let processed = process_background(&path).unwrap();
        assert_eq!(processed.package_name, "assets/background.webp");
        assert!(processed.bytes.starts_with(b"RIFF"));
        assert_eq!(&processed.bytes[8..12], b"WEBP");
    }

    #[test]
    fn rejects_disguised_html() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("background.png");
        std::fs::write(&path, b"<html>not an image</html>").unwrap();
        assert!(process_background(&path).is_err());
    }
}
