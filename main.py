#!/usr/bin/env python3
"""
Forensic Metadata Analyzer

A comprehensive tool for extracting and analyzing metadata from various file types
for forensic investigation purposes.

Author: Hans Bricks
License: MIT
"""

import argparse
import os
import sys
import json
import logging
import datetime
import subprocess
import re
from typing import Dict, Any, List, Union, Tuple, Optional

# External tool check for exiftool
def is_exiftool_available():
    """Check if exiftool is available on the system."""
    try:
        subprocess.run(["exiftool", "-ver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return True
    except FileNotFoundError:
        return False

EXIFTOOL_AVAILABLE = is_exiftool_available()

# File type detection
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    import mimetypes

# Image metadata
try:
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# PDF metadata
try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:
    try:
        import pikepdf
        PIKEPDF_AVAILABLE = True 
    except ImportError:
        PYPDF2_AVAILABLE = False
        PIKEPDF_AVAILABLE = False

# More advanced PDF parsing
try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

# Audio metadata
try:
    import mutagen
    from mutagen.id3 import ID3
    from mutagen.mp4 import MP4
    from mutagen.wave import WAVE
    from mutagen.flac import FLAC
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False

# FFmpeg for deeper audio analysis (via ffprobe)
def is_ffprobe_available():
    """Check if ffprobe is available on the system."""
    try:
        subprocess.run(["ffprobe", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return True
    except FileNotFoundError:
        return False

FFPROBE_AVAILABLE = is_ffprobe_available()

# Office documents
try:
    from docx import Document
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

# Output formatting
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

# Colored output
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# Setup logger
logging.basicConfig(format='%(levelname)s: %(message)s')
logger = logging.getLogger('forensic-metadata')

# Global variable for args (will be set in main)
args = None

# Colors for different elements
COLORS = {
    'TITLE': Fore.CYAN + Style.BRIGHT,
    'HEADER': Fore.GREEN + Style.BRIGHT,
    'ERROR': Fore.RED + Style.BRIGHT,
    'WARNING': Fore.YELLOW,
    'INFO': Fore.BLUE,
    'SUCCESS': Fore.GREEN,
    'RESET': Style.RESET_ALL,
    'HIGHLIGHT': Fore.MAGENTA,
}

def print_colored(text: str, color_key: str = 'RESET', bold: bool = False) -> None:
    """Print colored text if colorama is available."""
    if not COLORAMA_AVAILABLE or not args.color:
        print(text)
        return

    color = COLORS.get(color_key, '')
    if bold and not color_key in ['TITLE', 'HEADER', 'ERROR']:
        text = f"{Style.BRIGHT}{color}{text}{COLORS['RESET']}"
    else:
        text = f"{color}{text}{COLORS['RESET']}"
    
    print(text)

def determine_file_type(file_path: str) -> Tuple[str, str]:
    """
    Determine the file type and MIME type of a given file.
    Returns a tuple of (file_type, mime_type)
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    file_ext = os.path.splitext(file_path)[1].lower()[1:]
    
    if MAGIC_AVAILABLE:
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(file_path)
        
        # Get a more human-readable file type
        magic_desc = magic.Magic()
        file_type = magic_desc.from_file(file_path)
    else:
        # Fallback to mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            file_type = mime_type.split('/')[0].capitalize()
            if file_type == "Application":
                file_type = f"{file_type}/{mime_type.split('/')[1]}"
        else:
            file_type = f"Unknown ({file_ext})"
    
    return file_type, mime_type

def extract_exiftool_metadata(file_path: str) -> Dict[str, Any]:
    """Extract comprehensive metadata using exiftool if available."""
    if not EXIFTOOL_AVAILABLE:
        return {"error": "ExifTool not available on the system"}
    
    try:
        # Run exiftool with JSON output for easier parsing
        result = subprocess.run(
            ["exiftool", "-j", "-a", "-u", "-G1", file_path], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        
        # Parse the JSON output
        try:
            exif_data = json.loads(result.stdout)
            if exif_data and isinstance(exif_data, list) and len(exif_data) > 0:
                # ExifTool returns a list with one item per file
                metadata = exif_data[0]
                
                # Remove some less useful technical fields to clean up output
                for key in list(metadata.keys()):
                    if key in ['SourceFile', 'ExifToolVersion', 'Directory']:
                        del metadata[key]
                
                # Organize metadata by groups
                organized_metadata = {}
                
                for key, value in metadata.items():
                    # ExifTool's group feature adds group names in format "Group:Tag"
                    if ':' in key:
                        group, tag = key.split(':', 1)
                        if group not in organized_metadata:
                            organized_metadata[group] = {}
                        organized_metadata[group][tag] = value
                    else:
                        # Handle keys without groups
                        if 'General' not in organized_metadata:
                            organized_metadata['General'] = {}
                        organized_metadata['General'][key] = value
                
                return organized_metadata
            return {}
        except json.JSONDecodeError:
            # If JSON parsing fails, use the raw output
            lines = result.stdout.splitlines()
            metadata = {}
            
            current_group = 'General'
            metadata[current_group] = {}
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Check if this is a group header
                if line.startswith('--') and line.endswith('--'):
                    current_group = line.strip('-').strip()
                    if current_group not in metadata:
                        metadata[current_group] = {}
                    continue
                
                # Parse key-value pairs
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[current_group][key.strip()] = value.strip()
            
            return metadata
    
    except subprocess.CalledProcessError as e:
        if args.verbose:
            logger.error(f"Error running ExifTool: {e}")
        return {"error": f"ExifTool error: {e.stderr.strip() if e.stderr else str(e)}"}
    except Exception as e:
        if args.verbose:
            logger.error(f"Error extracting metadata with ExifTool: {str(e)}")
        return {"error": f"Failed to extract metadata with ExifTool: {str(e)}"}

def extract_image_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from image files."""
    # If exiftool is available, use it for more comprehensive extraction
    if EXIFTOOL_AVAILABLE and args.use_exiftool:
        return extract_exiftool_metadata(file_path)
    
    if not PIL_AVAILABLE:
        return {"error": "PIL/Pillow library not available"}
    
    try:
        with Image.open(file_path) as img:
            metadata = {
                "format": img.format,
                "mode": img.mode,
                "size": f"{img.width}x{img.height}",
                "width": img.width,
                "height": img.height,
                "bit_depth": getattr(img, "bit_depth", None),
            }
            
            # Extract EXIF data if available
            if hasattr(img, '_getexif') and img._getexif():
                exif = img._getexif()
                if exif:
                    exif_data = {}
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        
                        # Handle GPS data specially
                        if tag == 'GPSInfo':
                            gps_data = {}
                            for gps_tag_id, gps_value in value.items():
                                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                                gps_data[gps_tag] = gps_value
                            exif_data[tag] = gps_data
                        elif isinstance(value, bytes):
                            # Try to decode bytes to string, if fails, show as hex
                            try:
                                exif_data[tag] = value.decode('utf-8').strip('\x00')
                            except UnicodeDecodeError:
                                exif_data[tag] = f"<binary data: {len(value)} bytes>"
                        else:
                            exif_data[tag] = value
                    
                    metadata["EXIF"] = exif_data
            
            return metadata
    except Exception as e:
        if args.verbose:
            logger.error(f"Error extracting image metadata: {str(e)}")
        return {"error": f"Failed to extract image metadata: {str(e)}"}

def extract_pdf_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from PDF files."""
    # If exiftool is available, use it for more comprehensive extraction
    if EXIFTOOL_AVAILABLE and args.use_exiftool:
        return extract_exiftool_metadata(file_path)
    metadata = {}
    
    if PYPDF2_AVAILABLE:
        try:
            with open(file_path, 'rb') as file:
                reader = PyPDF2.PdfReader(file)
                info = reader.metadata
                
                metadata.update({
                    "pages": len(reader.pages),
                    "encrypted": reader.is_encrypted,
                })
                
                if info:
                    # Convert PDF metadata to dict
                    for key, value in info.items():
                        # Remove the leading slash in keys if present
                        clean_key = key[1:] if key.startswith('/') else key
                        
                        if isinstance(value, (bytes, bytearray)):
                            try:
                                metadata[clean_key] = value.decode('utf-8').strip('\x00')
                            except UnicodeDecodeError:
                                metadata[clean_key] = f"<binary data: {len(value)} bytes>"
                        else:
                            metadata[clean_key] = str(value)
                
                # Extract text from first page for preview if requested
                if args.extract_text and len(reader.pages) > 0:
                    try:
                        first_page_text = reader.pages[0].extract_text()
                        preview = first_page_text[:200] + "..." if len(first_page_text) > 200 else first_page_text
                        metadata["text_preview"] = preview
                    except Exception as e:
                        metadata["text_preview_error"] = str(e)
                
                return metadata
        except Exception as e:
            if args.verbose:
                logger.error(f"Error extracting PDF metadata with PyPDF2: {str(e)}")
            # Fall through to try pikepdf if available
    
    if PIKEPDF_AVAILABLE:
        try:
            with pikepdf.open(file_path) as pdf:
                metadata.update({
                    "pages": len(pdf.pages),
                    "version": str(pdf.pdf_version),
                })
                
                if pdf.docinfo:
                    for key, value in pdf.docinfo.items():
                        clean_key = key[1:] if key.startswith('/') else key
                        
                        if isinstance(value, (bytes, bytearray)):
                            try:
                                metadata[clean_key] = value.decode('utf-8').strip('\x00')
                            except UnicodeDecodeError:
                                metadata[clean_key] = f"<binary data: {len(value)} bytes>"
                        else:
                            metadata[clean_key] = str(value)
                
                return metadata
        except Exception as e:
            if args.verbose:
                logger.error(f"Error extracting PDF metadata with pikepdf: {str(e)}")
    
    # If we got here, both failed or aren't available
    if not (PYPDF2_AVAILABLE or PIKEPDF_AVAILABLE):
        return {"error": "No PDF processing libraries available"}
    else:
        return {"error": f"Failed to extract PDF metadata"}

def extract_audio_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from audio files (MP3, M4A, WAV, FLAC, etc.)."""
    # If exiftool is available, use it for more comprehensive extraction
    if EXIFTOOL_AVAILABLE and args.use_exiftool:
        return extract_exiftool_metadata(file_path)
        
    if not MUTAGEN_AVAILABLE:
        return {"error": "Mutagen library not available"}
    
    try:
        metadata = {}
        audio = mutagen.File(file_path)
        
        if audio is None:
            return {"error": "Unsupported audio format or corrupted file"}
        
        # Basic info
        metadata["length"] = f"{int(audio.info.length // 60)}:{int(audio.info.length % 60):02d}"
        metadata["seconds"] = round(audio.info.length, 2)
        
        if hasattr(audio.info, "bitrate"):
            metadata["bitrate"] = f"{audio.info.bitrate / 1000:.1f} kbps"
        
        if hasattr(audio.info, "channels"):
            metadata["channels"] = audio.info.channels
        
        if hasattr(audio.info, "sample_rate"):
            metadata["sample_rate"] = f"{audio.info.sample_rate / 1000:.1f} kHz"
        
        # Get format-specific tags
        if isinstance(audio, MP4):
            for key, value in audio.items():
                if isinstance(value, list) and len(value) == 1:
                    metadata[key] = str(value[0])
                else:
                    metadata[key] = str(value)
        
        elif isinstance(audio, ID3):
            for key, value in audio.items():
                # Clean up ID3 tag names
                clean_key = key
                if key.startswith("TXXX:"):
                    clean_key = key[5:]
                elif key.startswith("T"):
                    clean_key = key[1:]
                metadata[clean_key] = str(value)
        
        # For all formats, add any available tags
        if hasattr(audio, "tags") and audio.tags:
            for key, value in audio.tags.items():
                if isinstance(value, list) and len(value) == 1:
                    metadata[key] = str(value[0])
                else:
                    metadata[key] = str(value)
        
        # Smartphone recording specific info (look for device info, geolocation)
        smartphone_indicators = []
        
        # Common smartphone recording indicators in metadata
        keys_to_check = ["device", "model", "make", "recorder", "location", "gps", "geolocation"]
        
        for key in metadata:
            key_lower = key.lower()
            if any(indicator in key_lower for indicator in keys_to_check):
                smartphone_indicators.append(f"{key}: {metadata[key]}")
        
        if smartphone_indicators:
            metadata["smartphone_indicators"] = smartphone_indicators
        
        return metadata
    except Exception as e:
        if args.verbose:
            logger.error(f"Error extracting audio metadata: {str(e)}")
        return {"error": f"Failed to extract audio metadata: {str(e)}"}

def extract_office_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from Office documents (DOCX, etc.)."""
    # If exiftool is available, use it for more comprehensive extraction
    if EXIFTOOL_AVAILABLE and args.use_exiftool:
        return extract_exiftool_metadata(file_path)
    if not DOCX_AVAILABLE:
        return {"error": "python-docx library not available"}
    
    try:
        metadata = {}
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext == ".docx":
            doc = Document(file_path)
            core_props = doc.core_properties
            
            # Extract core properties
            metadata.update({
                "author": core_props.author,
                "created": str(core_props.created) if core_props.created else None,
                "modified": str(core_props.modified) if core_props.modified else None,
                "last_modified_by": core_props.last_modified_by,
                "title": core_props.title,
                "subject": core_props.subject,
                "keywords": core_props.keywords,
                "comments": core_props.comments,
                "category": core_props.category,
                "revision": core_props.revision,
                "paragraphs": len(doc.paragraphs),
                "sections": len(doc.sections),
            })
            
            # Remove None values
            metadata = {k: v for k, v in metadata.items() if v is not None}
        
        return metadata
    except Exception as e:
        if args.verbose:
            logger.error(f"Error extracting Office document metadata: {str(e)}")
        return {"error": f"Failed to extract Office document metadata: {str(e)}"}

def extract_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from a file based on its type."""
    try:
        # If exiftool is available and forced, use it for all files
        if EXIFTOOL_AVAILABLE and args.force_exiftool:
            if args.verbose:
                print_colored(f"Using ExifTool for metadata extraction from {file_path}...", 'INFO')
            exif_metadata = extract_exiftool_metadata(file_path)
            
            # Add basic file stats
            stat = os.stat(file_path)
            basic_metadata = {
                "file_name": os.path.basename(file_path),
                "file_path": os.path.abspath(file_path),
                "file_size": stat.st_size,
                "human_size": humanize_size(stat.st_size),
            }
            
            # Only add these if they're not in the exiftool data
            if not any(key in exif_metadata.get('File', {}) for key in ['FileSize', 'FileModifyDate', 'FileAccessDate']):
                basic_metadata.update({
                    "created": datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                    "modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    "accessed": datetime.datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                })
            
            # Get file type if it wasn't detected
            if 'FileType' not in exif_metadata.get('File', {}):
                file_type, mime_type = determine_file_type(file_path)
                basic_metadata.update({
                    "file_type": file_type,
                    "mime_type": mime_type,
                })
                
            # Merge the metadata
            if 'General' not in exif_metadata:
                exif_metadata['General'] = {}
            exif_metadata['General'].update(basic_metadata)
            
            return exif_metadata
                
        # Get file type
        file_type, mime_type = determine_file_type(file_path)
        
        # Get file stats
        stat = os.stat(file_path)
        
        # Base metadata (available for all files)
        metadata = {
            "file_name": os.path.basename(file_path),
            "file_path": os.path.abspath(file_path),
            "file_size": stat.st_size,
            "human_size": humanize_size(stat.st_size),
            "created": datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            "modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            "accessed": datetime.datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
            "file_type": file_type,
            "mime_type": mime_type,
        }
        
        # Extract specific metadata based on file type
        if mime_type:
            main_type = mime_type.split('/')[0]
            sub_type = mime_type.split('/')[1] if '/' in mime_type else ''
            
            # Extract image metadata
            if main_type == 'image':
                if args.verbose:
                    print_colored(f"Extracting image metadata from {file_path}...", 'INFO')
                image_metadata = extract_image_metadata(file_path)
                if not "error" in image_metadata:
                    metadata["image_metadata"] = image_metadata
                elif args.verbose:
                    print_colored(f"Warning: {image_metadata['error']}", 'WARNING')
            
            # Extract PDF metadata
            elif mime_type == 'application/pdf':
                if args.verbose:
                    print_colored(f"Extracting PDF metadata from {file_path}...", 'INFO')
                pdf_metadata = extract_pdf_metadata(file_path)
                if not "error" in pdf_metadata:
                    metadata["pdf_metadata"] = pdf_metadata
                elif args.verbose:
                    print_colored(f"Warning: {pdf_metadata['error']}", 'WARNING')
            
            # Extract audio metadata
            elif main_type == 'audio':
                if args.verbose:
                    print_colored(f"Extracting audio metadata from {file_path}...", 'INFO')
                audio_metadata = extract_audio_metadata(file_path)
                if not "error" in audio_metadata:
                    metadata["audio_metadata"] = audio_metadata
                elif args.verbose:
                    print_colored(f"Warning: {audio_metadata['error']}", 'WARNING')
            
            # Extract Office document metadata
            elif mime_type in [
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/msword'
            ]:
                if args.verbose:
                    print_colored(f"Extracting document metadata from {file_path}...", 'INFO')
                doc_metadata = extract_office_metadata(file_path)
                if not "error" in doc_metadata:
                    metadata["document_metadata"] = doc_metadata
                elif args.verbose:
                    print_colored(f"Warning: {doc_metadata['error']}", 'WARNING')
            
            # For all other types, try exiftool if available and enabled
            elif EXIFTOOL_AVAILABLE and args.use_exiftool:
                if args.verbose:
                    print_colored(f"Using ExifTool for metadata extraction from {file_path}...", 'INFO')
                exif_metadata = extract_exiftool_metadata(file_path)
                if not "error" in exif_metadata:
                    metadata["exiftool_metadata"] = exif_metadata
                elif args.verbose:
                    print_colored(f"Warning: {exif_metadata['error']}", 'WARNING')
            
            # Handle other types
            else:
                if args.verbose:
                    print_colored(f"No specific metadata extractor for MIME type: {mime_type}", 'WARNING')
        
        return metadata
    except Exception as e:
        if args.verbose:
            logger.error(f"Error extracting metadata: {str(e)}")
        return {
            "file_name": os.path.basename(file_path),
            "file_path": os.path.abspath(file_path),
            "error": f"Failed to extract metadata: {str(e)}"
        }

def process_file(file_path: str) -> Dict[str, Any]:
    """Process a single file and extract its metadata."""
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}
    
    if not os.path.isfile(file_path):
        return {"error": f"Not a file: {file_path}"}
    
    if args.verbose:
        print_colored(f"Processing file: {file_path}", 'HEADER')
    
    return extract_metadata(file_path)

def process_directory(dir_path: str, recursive: bool = False) -> List[Dict[str, Any]]:
    """Process all files in a directory and extract their metadata."""
    if not os.path.exists(dir_path):
        print_colored(f"Directory not found: {dir_path}", 'ERROR')
        return []
    
    if not os.path.isdir(dir_path):
        print_colored(f"Not a directory: {dir_path}", 'ERROR')
        return []
    
    results = []
    
    if args.verbose:
        print_colored(f"Processing directory: {dir_path}", 'HEADER')
    
    for item in os.listdir(dir_path):
        item_path = os.path.join(dir_path, item)
        
        if os.path.isfile(item_path):
            # Skip hidden files unless explicitly requested
            if not args.include_hidden and item.startswith('.'):
                if args.verbose:
                    print_colored(f"Skipping hidden file: {item_path}", 'WARNING')
                continue
            
            # Apply extension filter if specified
            if args.extensions and not any(item.lower().endswith(ext.lower()) for ext in args.extensions):
                if args.verbose:
                    print_colored(f"Skipping file with non-matching extension: {item_path}", 'WARNING')
                continue
            
            result = process_file(item_path)
            results.append(result)
        
        elif recursive and os.path.isdir(item_path):
            # Skip hidden directories unless explicitly requested
            if not args.include_hidden and item.startswith('.'):
                if args.verbose:
                    print_colored(f"Skipping hidden directory: {item_path}", 'WARNING')
                continue
            
            subdir_results = process_directory(item_path, recursive)
            results.extend(subdir_results)
    
    return results

def format_metadata_as_table(metadata: Dict[str, Any], prefix: str = "") -> List[List[str]]:
    """Format metadata as a table for nice display."""
    rows = []
    
    # Check if this is ExifTool format (has groups)
    is_exiftool_format = any(isinstance(v, dict) for k, v in metadata.items())
    
    if is_exiftool_format:
        # For ExifTool format, organize by groups
        for group_name, group_data in sorted(metadata.items()):
            if isinstance(group_data, dict) and group_data:
                # Add a header row for each group
                rows.append([f"--- {group_name} ---", ""])
                
                # Add rows for each item in the group
                for key, value in sorted(group_data.items()):
                    if isinstance(value, dict):
                        # Handle nested dictionaries (like GPS data)
                        for sub_key, sub_value in sorted(value.items()):
                            rows.append([f"{key}.{sub_key}", str(sub_value)])
                    elif isinstance(value, list):
                        # Format list as comma-separated values
                        rows.append([key, ", ".join(map(str, value))])
                    else:
                        rows.append([key, str(value)])
    else:
        # Standard format
        for key, value in sorted(metadata.items()):
            if isinstance(value, dict) and not key == "error":
                # Add a header row for nested dictionaries
                if prefix:
                    header_key = f"{prefix}.{key}"
                else:
                    header_key = key
                rows.append([f"--- {header_key} ---", ""])
                
                # Recursively format nested dictionaries
                nested_rows = format_metadata_as_table(value, header_key)
                rows.extend(nested_rows)
            elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
                # Handle lists of dictionaries
                for i, item in enumerate(value):
                    if prefix:
                        header_key = f"{prefix}.{key}[{i}]"
                    else:
                        header_key = f"{key}[{i}]"
                    
                    rows.append([f"--- {header_key} ---", ""])
                    nested_rows = format_metadata_as_table(item, header_key)
                    rows.extend(nested_rows)
            elif isinstance(value, list):
                # Format list as comma-separated values
                if prefix:
                    full_key = f"{prefix}.{key}"
                else:
                    full_key = key
                rows.append([full_key, ", ".join(map(str, value))])
            else:
                # Simple key-value pair
                if prefix:
                    full_key = f"{prefix}.{key}"
                else:
                    full_key = key
                rows.append([full_key, str(value)])
    
    return rows

def highlight_important_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Highlight forensically interesting metadata."""
    interesting = {}
    
    # Check if this is ExifTool format
    if any(isinstance(v, dict) for k, v in metadata.items()) and 'General' in metadata:
        # ExifTool format with groups
        
        # GPS data
        if 'GPS' in metadata:
            gps_data = {}
            for key, value in metadata['GPS'].items():
                if any(term in key.lower() for term in ['latitude', 'longitude', 'altitude', 'position']):
                    gps_data[key] = value
            if gps_data:
                interesting['GPS_LOCATION'] = gps_data
        
        # Creation dates, timestamps
        for group in ['EXIF', 'File', 'XMP', 'ICC_Profile']:
            if group in metadata:
                for key, value in metadata[group].items():
                    if any(term in key.lower() for term in ['date', 'time', 'created', 'modified']):
                        interesting[f"{group}:{key}"] = value
        
        # Camera/device info
        for group in ['EXIF', 'MakerNotes', 'QuickTime']:
            if group in metadata:
                for key, value in metadata[group].items():
                    if any(term in key.lower() for term in ['make', 'model', 'software', 'device', 'camera', 'phone']):
                        interesting[f"{group}:{key}"] = value
        
        # Author, creator info
        for group in ['XMP', 'PDF', 'File']:
            if group in metadata:
                for key, value in metadata[group].items():
                    if any(term in key.lower() for term in ['author', 'creator', 'producer', 'owner', 'artist']):
                        interesting[f"{group}:{key}"] = value
    else:
        # Standard format
        
        # Highlight EXIF data with GPS information
        if "image_metadata" in metadata and "EXIF" in metadata["image_metadata"]:
            exif = metadata["image_metadata"]["EXIF"]
            if "GPSInfo" in exif:
                interesting["GPS_LOCATION"] = exif["GPSInfo"]
            
            # Look for creation dates, camera info
            for key in ["DateTimeOriginal", "DateTime", "Make", "Model", "Software"]:
                if key in exif:
                    interesting[key] = exif[key]
        
        # Highlight PDF author and creation information
        if "pdf_metadata" in metadata:
            pdf = metadata["pdf_metadata"]
            for key in ["Author", "Creator", "Producer", "CreationDate", "ModDate"]:
                if key in pdf:
                    interesting[key] = pdf[key]
        
        # Highlight audio recording information
        if "audio_metadata" in metadata:
            audio = metadata["audio_metadata"]
            if "smartphone_indicators" in audio:
                interesting["SMARTPHONE_DATA"] = audio["smartphone_indicators"]
        
        # Highlight document creation information
        if "document_metadata" in metadata:
            doc = metadata["document_metadata"]
            for key in ["author", "created", "modified", "last_modified_by"]:
                if key in doc and doc[key]:
                    interesting[key] = doc[key]
    
    return interesting

def display_metadata(metadata: Dict[str, Any]) -> None:
    """Display metadata in the selected format."""
    if "error" in metadata and not isinstance(metadata["error"], dict):
        print_colored(f"Error: {metadata['error']}", 'ERROR')
        return
    
    # Extract interesting forensic metadata
    interesting = highlight_important_metadata(metadata)
    
    if args.output_format == "json":
        # Pretty print JSON
        formatted_json = json.dumps(metadata, indent=4, default=str)
        if args.color and COLORAMA_AVAILABLE:
            # Highlight some parts of the JSON (primitive coloring)
            formatted_json = (
                formatted_json
                .replace('"', f'{Fore.GREEN}"')
                .replace('": ', f'"{Style.RESET_ALL}: ')
                .replace('true', f'{Fore.BLUE}true{Style.RESET_ALL}')
                .replace('false', f'{Fore.BLUE}false{Style.RESET_ALL}')
                .replace('null', f'{Fore.BLUE}null{Style.RESET_ALL}')
            )
            for num in range(10):
                formatted_json = formatted_json.replace(
                    f": {num}", f": {Fore.MAGENTA}{num}{Style.RESET_ALL}"
                )
            print(formatted_json)
        else:
            print(formatted_json)
    
    elif args.output_format == "table":
        # Display as table with forensic highlights
        if TABULATE_AVAILABLE:
            # Print the file header
            file_name = metadata.get("file_name", "Unknown")
            file_type = metadata.get("file_type", "Unknown")
            file_size = metadata.get("human_size", "Unknown")
            
            print_colored(f"\n=== Metadata for {file_name} ({file_type}, {file_size}) ===", 'TITLE')
            
            # Show forensically interesting data first if available
            if interesting:
                print_colored("\n🔍 FORENSIC POINTS OF INTEREST:", 'HIGHLIGHT', bold=True)
                interesting_table = []
                for key, value in interesting.items():
                    if isinstance(value, dict):
                        interesting_table.append([key, json.dumps(value, default=str)])
                    elif isinstance(value, list):
                        interesting_table.append([key, "\n".join(value)])
                    else:
                        interesting_table.append([key, str(value)])
                
                print(tabulate(interesting_table, headers=["Property", "Value"], tablefmt="pretty"))
                print()
            
            # Format the data as a table
            table_data = format_metadata_as_table(metadata)
            
            # Group by category if the table is large
            if len(table_data) > 20:
                current_category = ""
                grouped_data = {}
                
                for row in table_data:
                    key = row[0]
                    if key.startswith("---"):
                        # This is a header row
                        current_category = key.strip("- ")
                        if current_category not in grouped_data:
                            grouped_data[current_category] = []
                    else:
                        category = key.split(".")[0] if "." in key else "General"
                        if category not in grouped_data:
                            grouped_data[category] = []
                        grouped_data[category].append(row)
                
                # Display each category
                for category, rows in grouped_data.items():
                    if rows:
                        print_colored(f"\n--- {category} ---", 'HEADER')
                        print(tabulate(rows, headers=["Property", "Value"], tablefmt="pretty"))
            else:
                # Display as a single table
                print(tabulate(table_data, headers=["Property", "Value"], tablefmt="pretty"))
        else:
            # Fallback if tabulate is not available
            print_colored(f"\n=== Metadata for {metadata.get('file_name', 'Unknown')} ===", 'TITLE')
            
            # Show forensically interesting data first if available
            if interesting:
                print_colored("\n🔍 FORENSIC POINTS OF INTEREST:", 'HIGHLIGHT', bold=True)
                for key, value in interesting.items():
                    print(f"{key}: {value}")
                print()
            
            for key, value in metadata.items():
                if isinstance(value, dict):
                    print_colored(f"\n--- {key} ---", 'HEADER')
                    for sub_key, sub_value in value.items():
                        print(f"{sub_key}: {sub_value}")
                else:
                    print(f"{key}: {value}")
    
    elif args.output_format == "compact":
        # Simplified output format
        file_info = []
        if "file_name" in metadata:
            file_info.append(metadata["file_name"])
        if "file_type" in metadata:
            file_info.append(metadata["file_type"])
        if "human_size" in metadata:
            file_info.append(metadata["human_size"])
        
        print_colored(" | ".join(file_info), 'TITLE')
        
        # Show forensically interesting data
        if interesting:
            print_colored("\n🔍 FORENSIC POINTS OF INTEREST:", 'HIGHLIGHT', bold=True)
            for key, value in interesting.items():
                if isinstance(value, (dict, list)):
                    print_colored(f"{key}:", 'HEADER')
                    if isinstance(value, dict):
                        for k, v in value.items():
                            print(f"  {k}: {v}")
                    else:  # list
                        for item in value:
                            print(f"  {item}")
                else:
                    print(f"{key}: {value}")
    
    else:
        print_colored("Unknown output format", 'ERROR')

def humanize_size(size_bytes: int) -> str:
    """Convert bytes to a human-readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

def is_installed(library: str) -> bool:
    """Check if a Python library is installed."""
    try:
        __import__(library)
        return True
    except ImportError:
        return False

def check_dependencies() -> None:
    """Check required dependencies and warn if any are missing."""
    dependencies = {
        "colorama": ("Colorama", "pip install colorama", "Colored output"),
        "tabulate": ("Tabulate", "pip install tabulate", "Nice table formatting"),
        "magic": ("Python-magic", "pip install python-magic", "File type detection"),
        "PIL": ("Pillow", "pip install Pillow", "Image metadata extraction"),
        "PyPDF2": ("PyPDF2", "pip install PyPDF2", "PDF metadata extraction"),
        "pikepdf": ("pikepdf", "pip install pikepdf", "Alternative PDF metadata extraction"),
        "mutagen": ("Mutagen", "pip install mutagen", "Audio metadata extraction"),
        "docx": ("python-docx", "pip install python-docx", "DOCX metadata extraction"),
    }
    
    missing = []
    installed = []
    
    for module, (name, install_cmd, purpose) in dependencies.items():
        if is_installed(module):
            installed.append((name, purpose))
        else:
            missing.append((name, install_cmd, purpose))
    
    if args.verbose:
        if installed:
            print_colored("Installed dependencies:", 'SUCCESS')
            for name, purpose in installed:
                print(f"  ✓ {name}: {purpose}")
        
        if missing:
            print_colored("\nMissing optional dependencies:", 'WARNING', bold=True)
            for name, install_cmd, purpose in missing:
                print(f"  ✗ {name}: {purpose}")
                print(f"    Install with: {install_cmd}")
        print()

def save_to_file(results: Union[Dict[str, Any], List[Dict[str, Any]]], output_file: str) -> None:
    """Save results to a file."""
    try:
        file_ext = os.path.splitext(output_file)[1].lower()
        
        if file_ext == ".json":
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, default=str)
        elif file_ext in [".txt", ".csv", ".md"]:
            with open(output_file, 'w', encoding='utf-8') as f:
                if isinstance(results, list):
                    for result in results:
                        f.write(f"=== {result.get('file_name', 'Unknown')} ===\n")
                        for key, value in result.items():
                            if isinstance(value, dict):
                                f.write(f"\n--- {key} ---\n")
                                for sub_key, sub_value in value.items():
                                    f.write(f"{sub_key}: {sub_value}\n")
                            else:
                                f.write(f"{key}: {value}\n")
                        f.write("\n")
                else:
                    for key, value in results.items():
                        if isinstance(value, dict):
                            f.write(f"\n--- {key} ---\n")
                            for sub_key, sub_value in value.items():
                                f.write(f"{sub_key}: {sub_value}\n")
                        else:
                            f.write(f"{key}: {value}\n")
        else:
            # Default to JSON for other extensions
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, default=str)
        
        if args.verbose:
            print_colored(f"Results saved to {output_file}", 'SUCCESS')
    
    except Exception as e:
        print_colored(f"Error saving to file: {str(e)}", 'ERROR')

def main() -> None:
    """Main function to run the metadata extractor."""
    global args  # Make args available to all functions
    
    parser = argparse.ArgumentParser(
        description="Forensic Metadata Analyzer - Extract and analyze metadata from various file types",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s image.jpg                     # Extract metadata from a single image file
  %(prog)s -r /path/to/dir               # Recursively process files in a directory
  %(prog)s -f json -o results.json file  # Save JSON metadata to results.json
  %(prog)s -v -e jpg,png,pdf /evidence   # Process only JPG, PNG and PDF files
  %(prog)s -c -s /path/to/files          # Show a compact summary of metadata
  %(prog)s --exiftool image.jpg          # Use ExifTool for comprehensive metadata extraction

Supported file types:
  - Images (JPG, PNG, GIF, TIFF, etc.) - EXIF data extraction
  - Documents (PDF, DOCX) - Author, creation dates, etc.
  - Audio (MP3, WAV, FLAC, M4A, etc.) - ID3 tags, recording info
  - And more (automatic detection)
"""
    )
    
    parser.add_argument("input", help="File or directory to analyze")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Save results to file")
    output_group.add_argument("-f", "--output-format", choices=["json", "table", "compact"], 
                              default="table", help="Output format (default: table)")
    output_group.add_argument("-q", "--quiet", action="store_true", 
                              help="Suppress output to screen")
    output_group.add_argument("--no-color", dest="color", action="store_false", 
                              help="Disable colored output")
    output_group.add_argument("-s", "--summary", action="store_true", 
                              help="Show only summary information for each file")
    
    # Processing options
    processing_group = parser.add_argument_group("Processing Options")
    processing_group.add_argument("-r", "--recursive", action="store_true", 
                              help="Recursively process directories")
    processing_group.add_argument("-e", "--extensions", 
                              help="Comma-separated list of file extensions to process (e.g. jpg,pdf,mp3)")
    processing_group.add_argument("--include-hidden", action="store_true", 
                              help="Include hidden files and directories (starting with .)")
    processing_group.add_argument("--extract-text", action="store_true", 
                              help="Extract text preview from documents (PDF, DOCX)")
    
    # External tool options
    external_group = parser.add_argument_group("External Tool Options")
    external_group.add_argument("--exiftool", action="store_true", dest="use_exiftool",
                            help="Use ExifTool if available for specific file types")
    external_group.add_argument("--force-exiftool", action="store_true",
                            help="Force use of ExifTool for all file types if available")
    external_group.add_argument("--ffprobe", action="store_true", dest="use_ffprobe",
                            help="Use ffprobe if available for detailed audio/video analysis")
    
    # Misc options
    misc_group = parser.add_argument_group("Miscellaneous Options")
    misc_group.add_argument("-v", "--verbose", action="store_true", 
                              help="Enable verbose output")
    misc_group.add_argument("--debug", action="store_true", 
                              help="Enable debug mode")
    
    args = parser.parse_args()
    
    # Set up logger based on verbosity
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    
    # Process extensions if provided
    if args.extensions:
        args.extensions = args.extensions.split(',')
    
    # Print header
    if not args.quiet:
        print_colored("🔍 Forensic Metadata Analyzer 🔍", 'TITLE', bold=True)
        print_colored(f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", 'INFO')
    
    # Check dependencies if verbose
    if args.verbose:
        check_dependencies()
        
        # Check external tools
        if EXIFTOOL_AVAILABLE:
            print_colored("ExifTool detected! Comprehensive metadata extraction available.", 'SUCCESS')
        elif args.use_exiftool or args.force_exiftool:
            print_colored("Warning: ExifTool requested but not found on system. Install ExifTool for better results.", 'WARNING')
        
        if FFPROBE_AVAILABLE:
            print_colored("ffprobe detected! Enhanced audio/video analysis available.", 'SUCCESS')
        elif args.use_ffprobe:
            print_colored("Warning: ffprobe requested but not found on system. Install ffprobe for better audio/video analysis.", 'WARNING')
            
        # Check advanced libraries
        if PYMUPDF_AVAILABLE:
            print_colored("PyMuPDF detected! Enhanced PDF analysis available.", 'SUCCESS')
    
    try:
        # Process the input path
        if os.path.isfile(args.input):
            results = process_file(args.input)
            
            if not args.quiet:
                display_metadata(results)
            
            if args.output:
                save_to_file(results, args.output)
        
        elif os.path.isdir(args.input):
            results = process_directory(args.input, args.recursive)
            
            if not args.quiet:
                if results:
                    print_colored(f"\nProcessed {len(results)} files:", 'SUCCESS', bold=True)
                    
                    for result in results:
                        if args.summary:
                            # Display a summary for each file
                            file_name = result.get("file_name", "Unknown")
                            file_type = result.get("file_type", "Unknown")
                            file_size = result.get("human_size", "Unknown")
                            
                            # Check for highlighted forensic data
                            interesting = highlight_important_metadata(result)
                            if interesting:
                                print_colored(f"{file_name} ({file_type}, {file_size}) - 🔍 FORENSIC INTEREST", 'HIGHLIGHT')
                            else:
                                print(f"{file_name} ({file_type}, {file_size})")
                        else:
                            # Display detailed metadata for each file
                            display_metadata(result)
                            print()
                else:
                    print_colored("No files processed", 'WARNING')
            
            if args.output:
                save_to_file(results, args.output)
        
        else:
            print_colored(f"Input path not found: {args.input}", 'ERROR')
            sys.exit(1)
    
    except KeyboardInterrupt:
        print_colored("\nOperation cancelled by user", 'WARNING')
        sys.exit(130)
    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            print_colored(f"Error: {str(e)}", 'ERROR')
        sys.exit(1)

if __name__ == "__main__":
    main()
