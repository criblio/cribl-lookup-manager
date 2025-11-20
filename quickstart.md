# Quick Start Guide

## Setup (First Time Only)

1. **Copy configuration template:**
   ```bash
   cp config.ini.template config.ini
   ```

2. **Edit config.ini with your Cribl Cloud credentials:**
   ```bash
   # Open config.ini and replace:
   # - your_client_id_here
   # - your_client_secret_here
   # - your_organization_id_here
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

```bash
python app.py
```

The server will start and show you the URL (default: http://localhost:42001)

## What's New in This Version

### Issue #6 Fixed: Pack Lookup Names
- Pack lookups (e.g., `cribl-search-examples-searches.operators.csv`) now show the shortened name (`operators.csv`) in:
  - Ready status
  - Commit messages
  
### Repository Ready
- ✅ `.gitignore` protects your credentials
- ✅ `config.ini.template` for safe sharing
- ✅ Complete `README.md` documentation
- ✅ All 6 issues fixed and tested

## Files You'll Use

- **app.py** - The server (don't modify unless developing)
- **index.html** - The web interface (don't modify unless developing)
- **config.ini** - Your credentials (NEVER commit to Git!)
- **config.ini.template** - Example configuration to get you started
- **requirements.txt** - Python packages needed

## Files for Reference

- **README.md** - Complete documentation
- **QUICKSTART.md** - This quick start guide
- **.gitignore** - Protects sensitive files from Git

## Need Help?

See README.md for:
- How to get Cribl Cloud API credentials
- Complete usage workflow
- Troubleshooting guide
- Feature descriptions
