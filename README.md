# Discord Archive Viewer

A Python tool that converts your Discord data package into a beautiful, fully offline HTML file you can open in any browser — with your full chat history, statistics, charts, and more.

### 📥 [Download Latest Windows .exe](https://github.com/thomasthanos/discord_package_viewer/releases/latest)

![Python](https://img.shields.io/badge/Python-3.13.12-blue)
![License](https://img.shields.io/badge/License-Proprietary-red)

---

## What it does

When you request your data from Discord, you receive a ZIP file containing all your account information — messages, servers, activity, and more. This tool takes that ZIP and generates a single `discord_viewer.html` file that works completely offline, with no server, no installation, and no internet connection required after generation.

### What's inside the viewer

- **Full message history** — every DM and server channel you've ever written in, with proper Discord markdown, spoilers, @mentions, custom emoji, and attachments
- **Smart message grouping** — consecutive messages from the same author are grouped together with mini profile pictures, exactly like Discord
- **Media playback** — image previews, a custom video player, audio player for voice messages, and Tenor GIFs
- **Statistics & Interactive Charts** — dynamic graphs for hourly, daily, and all-time messaging activity, plus top emoji usage and active servers
- **Word cloud** — a visual map of your most-used words
- **Live search & Filtering** — search through all your messages instantly with keyword highlighting, and quick date range filters
- **Rich Account info** — view your account creation date, badges (HypeSquad, Active Developer, etc.), device info, Nitro history, linked accounts, and payment history
- **Fast Navigation** — floating jump-to-top/bottom buttons, instant "Load More" header controls, and a smooth loading progress bar

---

## Requirements

- **Python 3.13.12** — that's it, no other dependencies required

Optional (for better avatar rendering — extracts a static frame from animated GIFs):
```
pip install Pillow
```

---

## How to use

### Step 1 — Request your Discord data

1. Open Discord → **Settings** → **Privacy & Safety**
2. Scroll down and click **"Request all of my Data"**
3. Wait a few days — Discord will email you a download link
4. Download the ZIP file (do **not** extract it)

> ⚠️ **Important:** Your Discord interface language must be set to **English** when you request the data package. If Discord is set to another language (Greek, French, German, Spanish, etc.), the folder names inside the ZIP will be translated and the tool will not work correctly.
>
> To change language: **Discord Settings → Language → English**, then request your data again.

---

### Step 2 — Run the tool

**GUI mode** (recommended — double-click friendly):
```bash
python generate_discord_viewer.py
```
A window opens. Click **Browse ZIP**, select your Discord data ZIP file, then click **⚡ Generate HTML**. When it finishes, click **🌐 Open in Browser**.

**CLI mode** (for power users):
```bash
python generate_discord_viewer.py E:\package.zip
```

---

### Step 3 — Open the viewer

The tool saves a `discord_viewer.html` file next to your ZIP. Open it in any modern browser (Chrome, Firefox, Edge). No internet connection needed.

---

## Expected ZIP structure

The tool expects the standard English Discord data package structure:

<details>
<summary><strong>Expected ZIP structure</strong> — click to expand</summary>

```
package.zip
└── package/
    ├── Account/
    │   ├── user.json                    ← REQUIRED
    │   ├── avatar.gif / .png
    │   ├── applications/
    │   ├── recent_avatars/
    │   └── user_data_exports/           ← Nitro/payments history
    ├── Messages/
    │   ├── index.json                   ← REQUIRED
    │   └── c<channel_id>/
    │       ├── channel.json
    │       └── messages.json
    ├── Servers/
    │   ├── index.json
    │   └── <server_id>/
    │       ├── guild.json
    │       ├── audit-log.json
    │       ├── channels.json
    │       ├── emoji.json
    │       ├── icon.jpeg / icon.gif
    │       └── …
    ├── Activity/
    │   └── reporting/                   ← activity events (NDJSON)
    ├── Activities/
    ├── Ads/
    └── Support_Tickets/
```

> Only `Account/user.json` and `Messages/index.json` are required — everything else is optional and gracefully skipped if absent.

</details>

---

## Privacy

Everything runs locally on your machine. The script never sends any data anywhere. The generated HTML file only makes external requests for:
- **Google Fonts** — to render the UI fonts
- **Discord CDN** — to load custom server emoji by ID
- **Tenor** — thumbnail previews for GIF links (pre-fetched during generation)

Your messages, account info, and personal data never leave your computer.

---

## Troubleshooting

**"Non-English Package Detected" warning**
Your ZIP was created while Discord was set to a non-English language. Change Discord's language to English, request a new data package, and use that ZIP instead.

**Avatar not showing**
Place your `avatar.gif` or `avatar.png` inside the `Account/` folder of the extracted package, or make sure it's present inside the ZIP.

**Generation fails or shows missing data**
Make sure you selected the correct ZIP — the original Discord data package, not a re-zipped or renamed version. The internal folder structure must match the expected layout above.

**`customtkinter` not found**
The tool will attempt to install it automatically. If that fails, run:
```bash
pip install customtkinter
```

---

## License

Proprietary — see [LICENSE](LICENSE).
