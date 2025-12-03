# Cribl Lookup Manager

A web-based tool for managing and transferring lookup tables between Cribl Cloud worker groups across Stream, Search, and Edge deployments.

**Version: 2.0.1** | December 2025

## Features

### Core Functionality
- **Multi-API Support**: Transfer lookups between Cribl Stream, Search, and Edge worker groups/fleets
- **Lookup Type Management**: Support for both memory-based and disk-based lookups
- **Built-in Editor**: Edit lookup content with text or table view, rename files before transfer
- **Safe Deployments**: Selective commit and deploy to avoid deploying unrelated changes
- **Pack Support**: Automatically handles Cribl Pack lookup naming conventions
- **Type Conversion**: Handle conflicts when changing lookup types (disk to memory)
- **Auto-Commit**: Automatically commits lookups to prevent hanging changes
- **Real-time Status**: View pending changes, current versions, and deployment status

### Bulk Transfer
- **Multi-Lookup Selection**: Select multiple lookup files to transfer at once using checkboxes
- **Multi-Destination Selection**: Transfer to multiple worker groups or fleets simultaneously
- **Per-Lookup Type Override**: Set disk-based or memory-based type individually for each lookup
- **Bulk Transfer Progress**: Real-time progress indicator showing current operation count and destination
- **Select All / Deselect All**: Quick selection controls for both lookups and destination groups

### Pack Lookup Discovery
- **Stream/Edge Pack Lookups**: Discover lookups from installed Cribl Packs in Stream and Edge
- **Selective Pack Loading**: Choose which packs to load lookups from (no need to export all packs)
- **Progress Tracking**: Horizontal progress bar shows which pack is being exported
- **Pack Indicator**: Visual badge showing which lookups come from packs
- **Fast Initial Load**: System lookups load instantly; pack lookups load on-demand

### Lookup Editor
- **Text Mode**: Edit raw CSV/text content directly
- **Table Mode**: Edit CSV files in a spreadsheet-like interface (default)
- **Search Filter**: Filter table rows by content to find specific entries
- **Add/Delete Rows and Columns**: Modify table structure directly
- **Binary File Support**: Handles `.mmdb` and `.gz` files (rename-only mode)
- **Large File Protection**: Files over 10MB open in rename-only mode to prevent browser issues

### User Interface
- **Dark/Light Mode**: Toggle between dark and light themes
- **Collapsible Panels**: Minimize the Lookup Editor, Console, and curl Commands sections
- **Activity Log**: Shows last operation results (transfer, deploy status)
- **In-App Documentation**: Quick access to docs via Help button
- **Clickable Headers**: Click panel headers to expand/collapse

## Prerequisites

- Python 3.7 or higher
- Cribl Cloud account with API access
- OAuth credentials (Client ID and Client Secret)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/criblio/cribl-lookup-manager
cd cribl-lookup-manager
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Configure credentials (choose one option):

**Option A: Environment Variables (Recommended - More Secure)**
```bash
export CRIBL_CLIENT_ID=your_client_id_here
export CRIBL_CLIENT_SECRET=your_client_secret_here
export CRIBL_ORG_ID=your_organization_id_here
```

**Option B: Config File**
```bash
cp config.ini.template config.ini
```

Edit `config.ini` and add your Cribl Cloud credentials:
```ini
[cribl]
client_id = your_client_id_here
client_secret = your_client_secret_here
organization_id = your_organization_id_here
```

> **Security Note:** The application automatically sets restrictive file permissions (600) on config.ini to protect your credentials. Environment variables are preferred as they don't persist secrets to disk.

## Getting Cribl Cloud API Credentials

1. Log in to [Cribl Cloud](https://cloud.cribl.io)
2. Click your organization name in the top left
3. Select **"Organization Settings"**
4. Click **"API Credentials"** in the left sidebar
5. Click **"Create API Credential"**
6. Enter a descriptive name (e.g., "Lookup Manager")
7. Set appropriate permissions (minimum: Read/Write access to Worker Groups)
8. Click **"Create"** and copy the credentials immediately (you won't see them again!)

## Usage

1. Start the server:
```bash
python app.py
```

2. The server will:
   - Check for available ports (default: 42001)
   - Detect if you have a config file for auto-login
   - Ask if you want to open the browser automatically
   - Start the Flask web server

3. Open your browser to the displayed URL (e.g., `http://localhost:42001`)

4. If you have a config file, you'll be automatically logged in. Otherwise, enter your credentials manually.

## Workflow

### Transferring a Single Lookup

1. **Select Source**:
   - Choose API type (Stream, Search, or Edge)
   - Select worker group or fleet
   - Click on a lookup file from the list

2. **Select Destination**:
   - Choose destination API type
   - Select destination worker group or fleet
   - Choose lookup type (disk-based or memory-based)

3. **Optional: Edit Content**:
   - Click the edit icon on a lookup to load it into the editor
   - Modify content or rename the file
   - Click "Save" when done

4. **Transfer**:
   - Click "Transfer" button
   - Changes are automatically committed
   - For pack lookups, the pack prefix is automatically stripped

5. **Deploy** (for Stream/Edge only):
   - Click "Deploy" to push changes to workers
   - Deployment is selective - only deploys the transferred lookup

### Bulk Transfer (Multiple Lookups to Multiple Destinations)

1. **Select Source**:
   - Choose API type and worker group
   - Use checkboxes to select multiple lookup files
   - Use "All" / "None" for quick selection

2. **Select Destinations**:
   - Choose destination API type
   - Use checkboxes to select multiple destination worker groups or fleets
   - Use "All" / "None" for quick selection

3. **Configure Lookup Types** (Optional):
   - Click the Mem/Disk badge next to each selected lookup to change its type
   - Each lookup can have its own type setting

4. **Transfer**:
   - Click "Transfer" button
   - Watch the progress indicator showing current operation
   - The commit message automatically reflects the bulk operation details

5. **Deploy**:
   - After bulk transfer completes, click "Deploy" to push all changes
   - All transferred lookups are deployed to their respective destinations

### Handling Type Conflicts

If you transfer a lookup with a different type than the existing one:

1. The tool will automatically:
   - Delete the existing lookup
   - Create a new one with the new type
2. You'll see a log message indicating the mode change

## Features in Detail

### Automatic Pack Name Handling

When transferring lookups from Cribl Packs (e.g., `cribl-search-examples.operators.csv`), the tool:
- Automatically strips the pack prefix
- Transfers as the shortened name (e.g., `operators.csv`)
- Updates the status and commit message with the shortened name

### Auto-Commit for Lookups

All lookups (disk-based and memory-based) are automatically committed after transfer. The tool:
- Commits only the specific lookup files you transferred
- Avoids accidentally committing other team members' changes
- Logs warnings if auto-commit fails (manual commit needed)

### Selective Deployment

The deploy function is designed to:
- Only deploy the specific lookup files you transferred
- Avoid accidentally deploying other uncommitted changes
- Show deployment status in the activity log

### Large File Handling

For files over 10MB:
- The editor opens in "rename-only" mode
- Content cannot be edited (to prevent browser memory issues)
- You can still rename the file before transfer

## File Structure

```
cribl-lookup-manager/
├── app.py                  # Flask backend server
├── index.html              # React frontend application
├── config.ini.template     # Example configuration file
├── config.ini              # Your actual config (gitignored)
├── requirements.txt        # Python dependencies
├── cribl-logo.svg          # Logo file
├── quickstart.md           # Quick start guide
├── .gitignore              # Git ignore rules
└── README.md               # This file
```

## Troubleshooting

### Port Already in Use

If port 42001 is in use, the application will:
1. Automatically search for an available port nearby
2. Ask if you want to use the found port
3. Allow you to specify a custom port

### Connection Issues

1. Expand the Console panel to see detailed API logs
2. Check the curl Commands panel to see the actual API calls being made
3. Test API connectivity using the "Test API Paths..." option

### Authentication Failures

- Verify your credentials in `config.ini`
- Check that your API token hasn't expired
- Ensure you have appropriate permissions
- Try logging out and back in

### Uncommitted Changes

- Auto-commit should handle most cases
- If auto-commit fails, check the console logs
- Manually commit via Cribl UI if needed

## Development

The application consists of:
- **Backend**: Flask server (`app.py`) that proxies Cribl API requests
- **Frontend**: React SPA (`index.html`) with Tailwind CSS for styling

To modify:
1. Backend changes: Edit `app.py`
2. Frontend changes: Edit `index.html` (React code is in `<script type="text/babel">`)
3. Restart the server to see changes

### Debug Mode

To enable verbose logging in the backend, edit `app.py` and set:
```python
DEBUG_MODE = True
```

## Security Notes

- Never commit `config.ini` to version control
- Keep your API credentials secure
- Use appropriate API token expiration dates
- Rotate tokens periodically
- Delete unused tokens from Cribl Cloud

## License

[Your License Here]

## Support

For issues, questions, or contributions, please [open an issue](your-repo-url/issues).

## Changelog

### Version 2.0.1 (December 2025)
- **Large File Protection**: Files over 10MB open in rename-only mode
- **Table View Default**: Lookup Editor now defaults to table view for CSV files
- **Search Filter**: Added filter to table view for finding specific rows
- **Clickable Headers**: Panel headers (Lookup Editor, Console, curl Commands) are now clickable to expand/collapse
- **Improved Binary File Handling**: Better UI for MMDB and GZ files with clear messaging
- **Terminology Update**: "Target" renamed to "Destination" throughout the UI
- **Smart Pluralization**: Messages correctly use singular/plural (1 destination vs 2 destinations)
- **Reduced Logging**: Production logging is now minimal; enable DEBUG_MODE for verbose output
- **UI Polish**: Reduced spacing in lists, matching fonts across panels, improved Clear buttons

### Version 1.3.0 (December 2025)
- **Pack Lookup Discovery**: Discover lookups from Cribl Packs in Stream/Edge by exporting and parsing `.crbl` files
- **Bulk Transfer Support**: Transfer multiple lookups to multiple worker groups/fleets simultaneously
- **Multi-Selection UI**: Checkbox-based selection for lookups and destination groups with Select All/Deselect All
- **Per-Lookup Type Override**: Set disk-based or memory-based type individually for each lookup in bulk transfers
- **Bulk Transfer Progress**: Real-time progress indicator with current operation count and destination display
- **Collapsible Panels**: Minimize/expand Lookup Editor, Console, and curl Commands sections
- **Binary File Support**: Handle `.mmdb` and `.gz` files with rename-only mode (no content editing)
- **In-App Documentation**: Quick access to README via Help button in the UI
- **UI Improvements**: Streamlined layout, better button sizing, and cleaner visual hierarchy
- **Bug Fixes**: Fixed race conditions and issues with deleting lookup tables and partial deployments

### Version 1.0.0
- Initial release
- Support for Stream, Search, and Edge APIs
- Lookup editor with rename capability
- Dark/Light mode toggle
- Selective commit and deploy
