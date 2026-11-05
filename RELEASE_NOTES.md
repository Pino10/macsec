## MacSec 0.9.0

### Updates you can see
A new **Updates** page, like Laramac's: MacSec's newest version with its notes inside the app, a progress bar while it downloads, the scanners that have a newer version (update them all at once), a refresh for the vulnerability databases, and every past release with its notes. The sidebar shows when a new version is ready.

MacSec never offered updates before, because every release was published as a pre-release and MacSec skipped those. It now reads them, and new releases are published as normal ones.

### Counts you can trust
A full audit runs its own code review and web scan and holds their findings, and the Overview counted those findings twice. Each finding now counts once, in the Overview and in "Test everything again".

### Special audits, put where they belong
- **Cloud and servers** is its own page: your Azure or AWS account, and the open ports of a server you own.
- **Code review** offers "Just my changes" (Claude Code's /security-review of your branch) and "Code and its live site" (a code review and a web scan joined in one report).
- **Projects** has "Check every project" (keys and vulnerable packages across your www folder).
- Mobile apps already had its own page.

### Your own editor
"Open in editor" uses the editor or IDE you choose in Settings (VS Code, Cursor, Zed, Sublime Text, the JetBrains IDEs, Nova, Xcode and more, or any app), at the line of the finding.

### Also
- The default reviewer in Settings now saves every reviewer, not only some.
- Each release carries only its own notes.

