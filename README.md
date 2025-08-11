# SOPS.nvim

A Neovim plugin for seamless integration with [Mozilla SOPS](https://github.com/mozilla/sops) (Secrets OPerationS). Automatically decrypt SOPS-encrypted files when opening them in Neovim and re-encrypt them when saving.

## Features

- **Automatic Detection**: Detects SOPS-encrypted files and decrypts them automatically
- **Multi-Backend Support**: Works with AWS KMS, GCP KMS, Azure Key Vault, PGP, Age, and HashiCorp Vault
- **Authentication Validation**: Checks authentication status for each backend before attempting operations
- **Metadata Preservation**: Preserves original SOPS metadata and encryption keys during edit sessions
- **Format Support**: Supports YAML, JSON, dotenv, INI, and other formats supported by SOPS
- **User Commands**: Provides convenient commands for manual operations
- **Buffer Management**: Automatically cleans up stored metadata when buffers are deleted

> **Note**: This plugin works with existing SOPS-encrypted files only. It does not create new SOPS-encrypted files or initialize SOPS configuration. To create new encrypted files, use the `sops` command directly.

## Requirements

- Neovim 0.7+
- [SOPS](https://github.com/mozilla/sops) installed and available in PATH
- Appropriate CLI tools for your encryption backends:
  - **AWS KMS**: `aws` CLI configured
  - **GCP KMS**: `gcloud` CLI authenticated
  - **Azure Key Vault**: `az` CLI logged in
  - **PGP**: `gpg` with secret keys available
  - **Age**: Age keys configured via environment variables or default locations
  - **HashiCorp Vault**: `vault` CLI with valid token

## Installation

### Using [lazy.nvim](https://github.com/folke/lazy.nvim)

```lua
{
  "your-username/sops.nvim",
  config = function()
    require("sops").setup({
      -- Configuration options
    })
  end,
}
```

### Using [packer.nvim](https://github.com/wbthomason/packer.nvim)

```lua
use {
  "your-username/sops.nvim",
  config = function()
    require("sops").setup()
  end
}
```

### Using [vim-plug](https://github.com/junegunn/vim-plug)

```vim
Plug 'your-username/sops.nvim'
```

Then add to your `init.lua`:

```lua
require("sops").setup()
```

## Configuration

The plugin can be configured with the following options:

```lua
require("sops").setup({
  -- Skip authentication checks if they fail (default: false)
  -- When true, attempts decryption even if some backends fail authentication
  skip_failed_auth = false,
})
```

## Usage

### Automatic Operation

The plugin works automatically once installed and configured:

1. **Opening Files**: When you open a SOPS-encrypted file, it will be automatically detected and decrypted
2. **Saving Files**: When you save a file that was originally SOPS-encrypted, it will be automatically re-encrypted using the original keys and configuration

### Manual Commands

The plugin provides several user commands for manual control:

- `:SopsDecrypt` - Manually decrypt the current buffer
- `:SopsEncrypt` - Manually encrypt the current buffer
- `:SopsReload` - Reload and decrypt the current SOPS file
- `:SopsCleanup` - Clean up stored SOPS metadata for the current buffer

### Backend Authentication

The plugin automatically detects which encryption backends are used in your SOPS files and validates authentication:

**AWS KMS**: Checks `aws sts get-caller-identity`
**GCP KMS**: Verifies active gcloud authentication
**Azure Key Vault**: Confirms az CLI login status
**PGP**: Ensures GPG secret keys are available
**Age**: Looks for keys in `SOPS_AGE_KEY_FILE`, `SOPS_AGE_KEY`, or `~/.config/sops/age/keys.txt`
**HashiCorp Vault**: Validates vault token for the configured address

### Environment Variables

The plugin respects standard SOPS environment variables:

- `SOPS_AGE_KEY_FILE` - Path to Age private key file
- `SOPS_AGE_KEY` - Age private key as string
- `VAULT_ADDR` - HashiCorp Vault address (can also be read from file metadata)
- `VAULT_TOKEN` - HashiCorp Vault token (managed automatically when possible)

## File Format Support

SOPS.nvim automatically detects file formats based on extension and configures SOPS accordingly:

- **YAML**: `.yaml`, `.yml`
- **JSON**: `.json`
- **Dotenv**: `.env`, `.dotenv`
- **INI**: `.ini`
- **Others**: Auto-detected by SOPS

## Troubleshooting

### Authentication Issues

If you see authentication failures:

1. Verify your CLI tools are installed and configured
2. Check that you're authenticated to the required services
3. For development/testing, you can set `skip_failed_auth = true` to bypass auth checks

### Large Files

The plugin efficiently handles large files by checking the most likely locations for SOPS metadata (end of file first, then beginning).

### Debug Information

The plugin provides informative notifications about its operations. Check `:messages` for detailed logs.

## How It Works

1. **Detection**: When a buffer is read, the plugin scans for SOPS metadata blocks
2. **Metadata Extraction**: Original SOPS configuration and encryption keys are extracted and stored
3. **Decryption**: File is decrypted using the `sops -d` command with appropriate environment variables
4. **Editing**: You edit the decrypted content normally in Neovim
5. **Re-encryption**: On save, the plugin re-encrypts using the original keys and configuration via `sops -e`

## Security Considerations

- Decrypted content exists only in Neovim's memory and temporary files during operations
- Original SOPS metadata and encryption configuration is preserved exactly
- Authentication tokens are managed securely through existing CLI tool configurations
- Temporary files are cleaned up automatically after encryption operations

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

[MIT License](LICENSE)

## Acknowledgments

This plugin was created with assistance from ChatGPT and Claude.ai to provide seamless SOPS integration for Neovim users.

---

**Note**: This plugin handles sensitive encrypted data. Please ensure you understand the security implications and have proper backups before using it with production secrets.