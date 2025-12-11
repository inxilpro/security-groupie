# Security Groupie

A macOS menubar application that automatically updates AWS security group rules when the user's IP address changes.

## Project Goals

- Provide a simple menubar app for managing dynamic IP access to AWS security groups
- Automatically detect IP address changes and update security group rules
- Support multiple AWS profiles and security groups

## Core Functionality

1. **IP Detection**: Fetch current public IP from `https://checkip.amazonaws.com` (or perhaps a pool of known IP services)
2. **Security Group Management**:
   - Find existing rules by device description/nickname
   - Update existing rules when IP changes
   - Create new rules if none exist for the device
3. **Settings Panel**:
   - AWS Security Group ID (e.g., `sg-xxxxxxxx`)
   - AWS Region (default: `us-east-1`)
   - Either a) AWS Profile name (for credentials), or b) AWS access key and secret
   - Device nickname/description (defaults to hostname)
   - Port number (default: 22)

## Technical Details

- **Platform**: macOS (SwiftUI, menubar app)
- **AWS SDK**: Use AWS SDK for Swift
- **Minimum macOS**: Mac OS 15

## Architecture

- Menubar icon with dropdown menu
- Settings window (SwiftUI)
- Background IP monitoring (listen for network changes)
- Secure credential handling via AWS profiles (~/.aws/credentials)

## Future Considerations

- Multiple security group configurations
- IP change notifications
- Manual refresh option
- Connection status indicator in menubar
