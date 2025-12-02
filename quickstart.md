# Quick Start Guide

Get up and running with the Cribl Lookup Manager in 5 minutes.

## Setup (First Time Only)

### 1. Copy Configuration Template

```bash
cp config.ini.template config.ini
```

### 2. Edit config.ini with Your Cribl Cloud Credentials

Open `config.ini` and replace the placeholder values:

```ini
[cribl]
client_id = your_client_id_here
client_secret = your_client_secret_here
organization_id = your_organization_id_here
```

**Getting credentials:**
1. Log in to Cribl Cloud
2. Go to Organization Settings > API Credentials
3. Create a new API credential
4. Copy the Client ID and Client Secret

**Organization ID formats accepted:**
- Direct tenant URL: `main-amazing-varahamihira.cribl.cloud`
- Just the subdomain: `main-amazing-varahamihira`
- Full URL: `https://main-amazing-varahamihira.cribl.cloud/`

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Or let the app install them automatically on first run.

## Running the Application

```bash
python app.py
```

The server will:
1. Check dependencies
2. Find an available port (default: 42001)
3. Optionally open your browser
4. Start the web server

## Basic Workflow

### Transfer a Single Lookup

1. **Source Panel (left side):**
   - Select API Type (Stream, Search, or Edge)
   - Select worker group or fleet
   - Click the edit icon on a lookup to preview/edit it

2. **Destination Panel (right side):**
   - Select destination API Type
   - Check the destination worker group(s) or fleet(s)
   - Choose lookup type (Memory or Disk)

3. **Click Transfer** - File is uploaded and committed automatically

4. **Click Deploy** - Push changes live to workers

### Transfer Multiple Lookups

1. Use checkboxes to select multiple lookups in the Source panel
2. Check multiple destinations in the Destination panel
3. Optionally change lookup type per file using the Mem/Disk badge
4. Click Transfer - watch the progress indicator
5. Click Deploy when all transfers complete

## Key Features

### Lookup Editor
- **Table View** (default): Edit CSV files like a spreadsheet
- **Text View**: Edit raw file content
- **Filter**: Search for specific rows in table view
- **Rename**: Change filename before transfer

### Panels
- Click panel headers to expand/collapse
- **Console**: Shows API activity logs
- **curl Commands**: Shows equivalent curl commands for learning/debugging
- **Activity Log**: Shows last operation result

### Tips
- Pack lookups automatically have their prefix stripped
- Files over 10MB open in rename-only mode
- Binary files (.mmdb, .gz) can only be renamed

## Files You'll Use

| File | Purpose |
|------|---------|
| `app.py` | Backend server (don't modify unless developing) |
| `index.html` | Frontend UI (don't modify unless developing) |
| `config.ini` | Your credentials (**NEVER** commit to Git!) |
| `config.ini.template` | Example config for new users |
| `requirements.txt` | Python dependencies |

## Troubleshooting

### "Not authenticated" error
- Check your credentials in `config.ini`
- Verify the organization_id format
- Try logging out and back in

### Port in use
- The app will find another port automatically
- Or kill the existing process using the port

### Transfer fails
- Check Console panel for detailed error messages
- Verify you have write permissions to the destination
- Check if lookup type conflicts need resolution

## Need More Help?

See `README.md` for:
- Complete feature documentation
- API credential setup details
- Troubleshooting guide
- Development instructions
