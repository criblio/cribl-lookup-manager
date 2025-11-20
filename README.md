# Cribl Lookup Manager

A web-based tool for managing and transferring lookup tables between Cribl Cloud worker groups across Stream, Search, and Edge deployments.

## Features

- **Multi-API Support**: Transfer lookups between Cribl Stream, Search, and Edge worker groups
- **Lookup Type Management**: Support for both memory-based and disk-based lookups
- **Built-in Editor**: Edit lookup content and rename files before transfer
- **Safe Deployments**: Selective commit and deploy to avoid deploying unrelated changes
- **Pack Support**: Automatically handles Cribl Pack lookup naming conventions
- **Type Conversion**: Handle conflicts when changing lookup types (disk ↔ memory)
- **Dark/Light Mode**: Toggle between dark and light themes
- **Auto-Commit**: Automatically commits disk-based lookups to prevent hanging changes
- **Real-time Status**: View pending changes, current versions, and deployment status

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

3. Create your configuration file:
```bash
cp config.ini.template config.ini
```

4. Edit `config.ini` and add your Cribl Cloud credentials:
```ini
[cribl]
client_id = your_client_id_here
client_secret = your_client_secret_here
organization_id = your_organization_id_here
```

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

### Transferring a Lookup

1. **Select Source**:
   - Choose API type (Stream, Search, or Edge)
   - Select worker group (or use default_search for Search)
   - Select lookup file from the list

2. **Select Target**:
   - Choose target API type
   - Select target worker group
   - Choose lookup type (disk-based or memory-based)

3. **Optional: Edit Content**:
   - Click "Load from Source" to edit the lookup
   - Modify content or rename the file
   - Click "Save" when done

4. **Transfer**:
   - Click "Transfer" button
   - For disk-based lookups, changes are automatically committed
   - For pack lookups, the pack prefix is automatically stripped

5. **Deploy** (for Stream/Edge only):
   - Click "Deploy" to push changes to workers
   - Deployment is selective - only deploys the transferred lookup

### Handling Type Conflicts

If you transfer a lookup with a different type than the existing one:

1. You'll see a conflict resolution dialog
2. Choose one of:
   - **Replace**: Delete the old one and transfer with new type (auto-commits deletion)
   - **Rename**: Transfer with a different name
   - **Cancel**: Abort the transfer

## Features in Detail

### Automatic Pack Name Handling

When transferring lookups from Cribl Packs (e.g., `cribl-search-examples-searches.operators.csv`), the tool:
- Automatically strips the pack prefix
- Transfers as the shortened name (e.g., `operators.csv`)
- Updates the "Ready" status and commit message with the shortened name

### Auto-Commit for Disk-Based Lookups

Disk-based lookups write files to the filesystem and create Git changes. The tool:
- Detects when a disk-based lookup is transferred
- Automatically commits the changes with an appropriate message
- Updates version information
- Logs warnings if auto-commit fails (manual commit needed)

### Selective Deployment

The commit and deploy functions are designed to:
- Only commit/deploy the specific lookup files you transferred
- Avoid accidentally deploying other team members' uncommitted changes
- Show pending changes count before deployment

## File Structure

```
cribl-lookup-manager/
├── app.py                  # Flask backend server
├── index.html              # React frontend application
├── config.ini.template     # Example configuration file
├── config.ini              # Your actual config (gitignored)
├── requirements.txt        # Python dependencies
├── cribl-logo.svg          # Logo file
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## Troubleshooting

### Port Already in Use

If port 42001 is in use, the application will:
1. Automatically search for an available port nearby
2. Ask if you want to use the found port
3. Allow you to specify a custom port

### Connection Issues

1. Click "Test API Paths..." dropdown in the interface
2. Select your API type (Stream, Search, or Edge)
3. The tool will test various API endpoints and show results
4. Use the successful endpoint pattern for your queries

### Authentication Failures

- Verify your credentials in `config.ini`
- Check that your API token hasn't expired
- Ensure you have appropriate permissions
- Try logging out and back in

### Uncommitted Changes

- For disk-based lookups: Auto-commit should handle this
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

### Version 1.0.0
- Initial release
- Support for Stream, Search, and Edge APIs
- Lookup editor with rename capability
- Dark/Light mode toggle
- Selective commit and deploy
