# Bond — logo assets

The mark is the **O of BOND**, cut open with a single dot resting in the opening: the one
person let in. It is a letter first and a symbol second, so the logotype and the app icon are
the same drawing at two sizes — there is no separate icon to keep in sync.

Everything here is generated from one geometry spec and real font outlines. The letters are
**outlined paths**, so nothing depends on Archivo being installed anywhere.

---

## Colour

| | Hex | Use |
|---|---|---|
| **Ink** | `#0B0B0C` | the mark and the letters on light backgrounds |
| **Flare** | `#FF4D2E` | the dot — only ever the dot |
| **Paper** | `#F6F7F9` | the light background |
| White | `#FFFFFF` | the mark and the letters on dark backgrounds |

The dot is the only place the red appears. It does not get used for text, buttons, or anything
else in the logo.

---

## Which file to use

### Logotype — the default
The full name. Use this wherever there is room for a word.

- `svg/bond-logotype.svg` — on light
- `svg/bond-logotype-on-dark.svg` — on dark
- `png/bond-logotype-2048w.png`, `-1024w`, `-512w` (+ `-on-dark-` versions), transparent

### Lockup — logotype plus "INVITE ONLY"
For splash screens, covers, and anywhere the product needs introducing.

- `svg/bond-lockup.svg`, `svg/bond-lockup-on-dark.svg`
- `png/bond-lockup-2048w.png`, `-1024w` (+ `-on-dark-`), transparent

### Mark alone
Only where the name is already established or obviously nearby — avatars, favicons, a nav bar
that already says Bond.

- `svg/bond-mark.svg` — ink ring, red dot
- `svg/bond-mark-on-dark.svg` — white ring, red dot
- `png/bond-mark-1024.png` … `-64` (+ `-on-dark-`), transparent

### App icon
- `svg/bond-app-icon.svg` — rounded square, dark. The general-purpose icon.
- `svg/bond-app-icon-square.svg` — full bleed, no corner radius. For Android adaptive icons and
  any store that applies its own mask.
- `svg/bond-app-icon-light.svg` — paper background, for light-only contexts.
- `png/bond-app-icon-{1024,512,256,192,180,152,128,96,64,48,32,16}.png`
- `png/bond-app-icon-square-{1024,512,432,216,108}.png`
- `favicon.ico` — 16/32/48/64/128/256 in one file

### One colour
For embossing, etching, single-colour print, a stamp, or anywhere the red cannot go.

- `svg/bond-mark-mono.svg`, `svg/bond-mark-mono-white.svg`
- `svg/bond-logotype-mono.svg`, `svg/bond-logotype-mono-white.svg`

These are a **separate cut**, not a recolour. In the two-colour version the dot touches the ring
and the colour difference keeps them apart; make them one colour and the O closes up into a
solid blob. So the mono cut widens the opening to 62° and drops the dot to r 4.8, which keeps
real daylight on both sides. Do not make your own mono version by recolouring the standard one.

- `svg/bond-mark-ring.svg` — the extreme reduction: open ring, no dot. For sizes below where the
  mono cut survives, and for debossing into a single material.

---

## Clear space and minimum sizes

**Clear space** on every side is one stroke width of the ring — the same as the dot's diameter.
Nothing else sits inside that margin.

| Asset | Minimum |
|---|---|
| Logotype | 96 px wide on screen · 25 mm in print |
| Lockup | 160 px wide (below this the tagline stops being readable) |
| Mark, two colour | 24 px |
| Mark, one colour | 32 px |
| Ring only | no floor |

At 16 px the red dot is a single pixel. That is fine for a favicon — it still reads as a ring
with a warm speck — but do not use the mark at 16 px anywhere it has to carry meaning on its own.

---

## Construction

The mark is drawn on a 64-unit grid. Every asset here is this shape scaled.

```
grid            64 × 64
ring centre     (32, 32)
ring radius     21            (centreline)
stroke          10.8          round caps
opening         54°, centred at −35°      (clockwise from 3 o'clock, SVG y-down)
dot             centre (49.20, 19.96), r 5.40     — exactly half the stroke width
ink box         52.8 × 52.8   →  x and y run 5.6 … 58.4

  path  M52.80 29.08 A21 21 0 1 1 41.86 13.46
  dot   cx 49.20  cy 19.96  r 5.40
```

**Fitting the mark into type.** The logotype is Archivo 700 with −0.05em tracking. The ring is a
monoline standing in for a modulated letter, so it is cut to 0.1455em — the midpoint between
Archivo's O side stroke (0.1535em) and its top stroke (0.1220em). Matching the side stroke makes
it read heavy and chokes the counter. Beside Archivo 700 at font-size `S`:

```
box         0.8606 S square           (gives a 0.710 S ring — the height of Archivo's own O)
baseline    vertical-align −0.0871 S  (puts the ring centre 0.3432 S above the baseline)
margins     left −0.0338 S            (restores the O's 0.0415 S sidebearings)
            right −0.0838 S           (sidebearing, plus the −0.05 tracking an element misses)
```

Logotype proportions: **3.8554 : 1**. Lockup: **2.5062 : 1**.

---

## Don't

- Don't recolour the dot, or add the red to anything else in the logo.
- Don't close the gap, rotate the mark, or move the dot.
- Don't rebuild the mono version by recolouring the two-colour one — use the mono files.
- Don't set BOND in Archivo and leave the real O in place. The O is the logo.
- Don't put the mark on a busy photo without the dark or paper plate behind it.
- Don't stretch. Logotype is 3.8554:1 and the mark is square.

---

## Type

| | |
|---|---|
| Logotype | Archivo 700, −0.05em tracking |
| Tagline | IBM Plex Sans 500, 0.20em tracking, uppercase |

Both are SIL Open Font License 1.1, which permits using the outlines in a logo and shipping the
fonts with an application. Keep the OFL text alongside if you bundle the font files themselves.
The logotype and lockup SVGs contain outlines, not text, so they need no font at runtime.

---

## Wiring it up

**Web** — `favicon.ico` at the site root, plus:
```html
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/bond-app-icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/bond-app-icon-180.png">
```

**Android adaptive icon** — foreground must sit inside the middle 66% of the canvas, so use
`bond-app-icon-square-*.png` as a full-bleed layer rather than the rounded file; the launcher
applies its own mask.

**iOS** — `bond-app-icon-1024.png` for App Store Connect. iOS applies the squircle itself, so the
rounded corners in the file are harmless but the square version is the safer source.

**Flutter** — put the SVGs under `client/assets/brand/` and the icon PNGs wherever
`flutter_launcher_icons` is configured to read them.

---

*Regenerate from source:* the geometry above plus `Archivo[wdth,wght].ttf` at wght 700 and
`IBMPlexSans[wdth,wght].ttf` at wght 500, both from the google/fonts repository.
