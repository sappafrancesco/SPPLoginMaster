# NoClaude

A CLI tool to remove Claude Code attribution from git history and set a custom author. In the ironic tradition of using code to erase traces of code generators, **NoClaude** rewrites your Git history to strip Claude Code attributions and replace them with your own author details.

Built with TypeScript and Bun.

## Features

- **Remove Claude Code attribution** from commit messages
- **Rewrite commit author and committer** information
- **Flexible configuration** via CLI args, environment variables, .env file, or git config
- **Dry-run mode** to preview changes before execution
- **Auto-push option** to automatically push after cleaning
- **Interactive confirmation** before making changes

## Requirements

- **[Bun](https://bun.sh/)** - Runtime (≥1.0.0)
- **Git** - Version control system
- **Node.js and npm** - For installation

## Installation

```bash
npm install -g noclaude
```

## Usage

Navigate to your repository and run:

```bash
noclaude --name "Your Name" --email "your@email.com"
```

### Options

- `-n, --name <name>` - Author name (optional, defaults to env/git config)
- `-e, --email <email>` - Author email (optional, defaults to env/git config)
- `-d, --dry-run` - Show what would be done without executing
- `-p, --auto-push` - Automatically push to remote after cleaning
- `-h, --help` - Show help message

### Configuration Priority

The tool looks for author information in this order:

1. Command-line arguments (`--name`, `--email`)
2. Environment variables (`GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`)
3. `.env` file in current directory
4. Git config (`user.name`, `user.email`)

### Examples

```bash
# Using CLI arguments
noclaude --name "rickhallett" --email "rick@example.com"

# Using environment variables
GIT_AUTHOR_NAME="rickhallett" GIT_AUTHOR_EMAIL="rick@example.com" noclaude

# Dry-run mode
noclaude --dry-run

# Auto-push after cleaning
noclaude --auto-push
```

### Warning

History rewrites are destructive and irreversible. This is the developer equivalent of deleting production data without backups. Always create a backup before running. Force-pushing will rewrite remote history and can affect collaborators. Use with caution.

## How It Works

Uses `git filter-branch` with two filters:

- **env-filter** - Sets `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, and `GIT_COMMITTER_EMAIL`
- **msg-filter** - Uses `sed` to remove Claude Code attribution lines from commit messages

The tool executes these filters across all commits in your repository history.

## Development

### Build

```bash
bun run build
```

Bundles `src/noclaude.ts` to `dist/noclaude.js` as an ESM executable.

### Architecture

Single-file CLI in `src/noclaude.ts`:

1. **Argument parsing** - Handles CLI flags and help text
2. **Configuration resolution** - Checks CLI args, env vars, .env file, then git config
3. **Interactive prompt** - Confirms before execution
4. **Git execution** - Runs `git filter-branch` with `execSync`
5. **Auto-push** - Optionally pushes to remote after completion

### Testing Locally

```bash
bun link
noclaude --dry-run
```

Test on a disposable repository first.

### Publishing

The `prepublishOnly` script automatically builds before publishing. Only the `dist` folder is included in the npm package.

## Contributing

Fork, hack, PR. Ensure it builds and passes any tests.

## License

MIT License. Free as in beer, but with the hangover of potential repo destruction.
