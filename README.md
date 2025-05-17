# pyforensics

### A Swiss Army knife for metadata extraction, OSINT, and digital forensics

**NOTE**: This code might be rough around the edges, but gets the damn job done. It's v0.0.1 

Hey there! 👋 This little Python tool was born out of frustration with remembering a bunch of different commands for metadata extraction. I had enough of jumping between exiftool, ffprobe, binwalk, strings, and whatever else just to see what's hiding in a file. So I built this.

## WTF is this? or *QUICKSTART*

`pyforensics` extracts ALL THE METADATA from pretty much any file you throw at it. Images, PDFs, audio files, office docs, whatever. It's the tool you wish you had when someone sends you a "totally safe" attachment or when you need to figure out who really created that document.

Some cool shit it can do:

- 🔍 Extract EXIF data from images (including those GPS coordinates people forget about)
- 📄 Dig into PDF files for hidden content, JavaScript, XMP data, etc.
- 🎵 Analyze audio files for recording device info, embedded data
- 🚨 Automatically highlight forensically interesting stuff (think: creation dates, device info)
- 💻 Works with ExifTool if you have it (and you should), but runs without it too
- 🔊 Uses ffprobe for advanced audio analysis (again, if you have it)
- 🌈 Colorful output because black and white terminal is for people with no joy

## Getting it running

```bash
# Clone this shit
git clone https://github.com/yourusername/pyforensics.git
cd pyforensics

# Install dependencies (or don't, and watch it complain)
pip install -r requirements.txt

# For the full experience, get these on your system:
# ExifTool - seriously, install it: https://exiftool.org/
# ffmpeg/ffprobe - for audio nerds: https://ffmpeg.org/
```

## How to use this thing

Basic usage is dead simple:

```bash
# Just point it at a file
python main.py suspicious_file.jpg

# Or go nuts on a directory
python main.py -r /path/to/evidence/

# Use the good stuff if you have it installed
python main.py --exiftool --ffprobe sketch_audio.mp3

# Save the output for your reports
python main.py -o evidence.json evil.pdf
```

## Examples of cool things you can find

- That image your target posted? Probably has their GPS coordinates, device model, and timestamp
- PDF document from a "anonymous" source? Author metadata, creation software, embedded scripts
- Audio recording? Recording device, sometimes even geolocation metadata
- Every file? Creation dates, modification timestamps, etc.

## Why I made this

I got sick of having to remember 50 different commands to do basic forensics work. Also, digital forensics tools shouldn't require a PhD to use or cost thousands in licenses. The tools we already have (exiftool, ffprobe, etc.) are amazing but sometimes you just want ONE command that does it all.

This is for those moments when you need to quickly figure out WTF is in a file without opening 5 different tools.

## Contributing

This is absolutely a work in progress. Found a bug? Got a feature idea? Want to add support for another file type? PRs welcome!

## Get in touch

Got questions, ideas, or just want to chat about forensics and OSINT? Reach out:

- Email: hans@dialout.net
- Twitter: @gyrusdentatus
- GitHub: @gyrusdentatus

Always down to collaborate on anything related to privacy, infosec, OSINT, or just cool hacking projects.

Remember: metadata is where all the juicy secrets hide. Happy hunting! 🕵️‍♂️
## DISCLAIMER 
I HAVE ABSOLUTELY NO RESPONSIBILITY FOR ANY MISUSE OF THIS CODE. IT IS INTENDED FOR RESEARCH PURPOSES AND IS RELEASED UNDER MIT LICENSE. 
## License

MIT, because sharing is caring.
