# Introduction to Secret Scanning

<img src="https://octodex.github.com/images/Professortocat_v2.png" align="right" height="200px" />

Hey Syko12345!

Mona here. I'm done preparing your exercise. Hope you enjoy! 💚

Remember, it's self-paced so feel free to take a break! ☕️

[![](https://img.shields.io/badge/Go%20to%20Exercise-%E2%86%92-1f883d?style=for-the-badge&logo=github&labelColor=197935)](https://github.com/Syko12345/SecretScanTool/issues/2)

---

&copy; 2025 GitHub &bull; [Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/code_of_conduct.md) &bull; [MIT License](https://gh.io/mit)

## Owner login scan tool

This repository now includes a minimal owner verification tool in `owner_scan_auth.py`.

It stores a hashed owner scan signature and denies login when the new scan does not match the enrolled owner signature.

### Quick start

```bash
python owner_scan_auth.py --database owner_scans.json enroll alice "FaceVector:12345"
python owner_scan_auth.py --database owner_scans.json login alice "FaceVector:12345"   # Access granted
python owner_scan_auth.py --database owner_scans.json login alice "FaceVector:wrong"  # Access denied
```
