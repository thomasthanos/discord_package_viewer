# Discord Data Package Viewer

Ένα Python script που μετατρέπει το Discord data export σου σε ένα standalone HTML αρχείο — με chat history, στατιστικά, γραφήματα, και πολλά άλλα. Δουλεύει εξ ολοκλήρου offline, δε χρειάζεται server, εγκατάσταση, ή dependencies.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-Proprietary-red)

---

## Τι κάνει

Παίρνει τον φάκελο που κατεβάζεις από το Discord (το data package) και φτιάχνει ένα `discord_viewer.html` που ανοίγεις απλά στον browser σου.

Μέσα στο HTML έχεις:

- Όλα τα μηνύματα σου ανά κανάλι / DM, με σωστό Discord markdown, spoilers, mentions, custom emoji, attachments
- Image previews, custom video player, audio player για voice messages, Tenor GIFs
- Στατιστικά: πόσα μηνύματα έχεις στείλει, σε ποιους servers, με ποιους DM, τι emoji χρησιμοποιείς
- Word cloud, ωριαία/ημερήσια/μηνιαία γραφήματα δραστηριότητας
- Live search μέσα στα μηνύματα με highlight
- Custom date range picker για να φιλτράρεις
- Πληροφορίες λογαριασμού, Nitro history, linked accounts, payment history, quests
- UI στα Ελληνικά και Αγγλικά

---

## Χρήση

**Απαιτήσεις:** Python 3.9+, τίποτα άλλο.

Προαιρετικά, αν θες καλύτερο avatar rendering (static frame από animated GIF):
```bash
pip install Pillow
```

### GUI mode
```bash
python generate_discord_viewer.py
```
Ανοίγει παράθυρο, διαλέγεις τον φάκελο, πατάς Generate.

### CLI mode
```bash
python generate_discord_viewer.py C:\path\to\your\package
```

Το output (`discord_viewer.html`) δημιουργείται στον **parent φάκελο** του package.

---

## Πώς να κατεβάσεις το Discord package σου

1. Discord → Settings → Privacy & Safety
2. "Request all of my Data"
3. Μετά από λίγες μέρες σου έρχεται email με download link
4. Κατεβάζεις και κάνεις extract το ZIP

---

## Δομή package

```
package/
├── Account/
│   ├── user.json        ← απαραίτητο
│   └── avatar.gif/.png  ← προαιρετικό
├── Messages/
│   ├── index.json       ← απαραίτητο
│   └── c<id>/messages.json
├── Servers/index.json
├── Activity/reporting/
└── Ads/quests_user_status.json
```

---

## Privacy

Όλα τρέχουν τοπικά. Το script δε στέλνει τίποτα πουθενά. Το HTML που παράγεται κάνει requests μόνο για Google Fonts, Discord CDN (για custom emoji), και Tenor thumbnails (pre-fetched κατά τη δημιουργία).

---

## License

Proprietary — δες το [LICENSE](LICENSE).
