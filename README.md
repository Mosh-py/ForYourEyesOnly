# ForYourEyesOnly
# F.Y.E.O (For Your Eyes Only) 👁️🔒

> **Status:** Live & Deployed  
> **Demo:** [https://foryoureyesonly.rumptycloud.app/](https://foryoureyesonly.rumptycloud.app/)

## 📡 Overview
**F.Y.E.O** is a visual cryptography engine designed to explore the relationship between **Image Entropy**, **Compression Algorithms**, and **Data Privacy**.

Unlike standard steganography (which hides data inside an image), FYEO transforms the image itself into high-entropy visual noise based on a user-provided seed. The project challenges the standard behavior of lossy compression protocols (like WhatsApp's JPEG algorithm) by forcing a confrontation between **Pixel Permutation** and **Quantization**.



## 🛠️ Engineering Highlights

### 1. The "Entropy Expansion" Problem
One of the core challenges in building this system was handling the explosion of raw data size.
* **The Issue:** A 3MB JPEG file on a user's phone is highly compressed. When loaded into RAM as a `BufferedImage`, it expands to its raw bitmap size (often >50MB), imagine users uploading a 3MB pictures and downloading over 50mb size of the same pic.
* **The Constraint:** Encrypting this data creates a file with maximum entropy (pure noise), which renders standard PNG compression useless.
* **The Solution:** Implemented a server-side **Resizing Algorithm**. This forces incoming streams to conform to a strict pixel budget (maintaining aspect ratio) *before* encryption, ensuring the output file remains transmissible (<5MB) without crashing the JVM Heap.

### 2. Fault Tolerance in Lossy Channels
The encryption algorithm was designed to be robust against "Macroblocking"—a common artifact of JPEG compression.
* While standard encryption is "all-or-nothing" (one bit flip breaks everything), FYEO's pixel permutation logic allows the image to survive transmission through aggressive channels (like WhatsApp) as long as the file is treated as a binary stream (Document mode).

### 3. Architecture
Built with a focus on **Clean Code** principles:
* **Strict MVC Pattern:** Separation of `ImageEncryptorService` / `ImageDecryptorService` (Logic),
  `WelcomeController` (Web Routing), `WelcomeAppController` (Mobile API Routing), and Thymeleaf
  Templates (View). Controllers depend only on the service layer via constructor injection.
* **DTO Pattern:** `CryptoDto` strictly binds the multipart file and hashing key, keeping
  parameters out of the controller signatures. `AppResponse` wraps the outbound payload.
* **Stateless Crypto Core:** `VisualAeadEngine` is a pure, static utility (no Spring beans, no
  injected state), so the same engine backs both the server-side path and the browser Web Worker.
* **Java 21 & Spring Boot:** Leveraging modern memory management and strict typing.

### 4. Cryptography — Visual AEAD (v2.0)
The engine in `crypto/VisualAeadEngine` is **not** plain pixel permutation; it is an
authenticate construction in the AES-GCM spirit, adapted to image data:
* **Key derivation:** PBKDF2-HMAC-SHA256 with **100,000 iterations**.
* **Key separation:** HKDF expands the derived master key into purpose-bound subkeys (e.g.
  `FYEO-v2-Auth-HMAC`) so no key is ever reused across purposes.
* **Integrity:** An HMAC-SHA256 authentication tag is computed over the Additional Authenticated
  Data **and** the pixel payload.
* **Verification:** Tags are compared in **constant time**, so a wrong password cannot be
  brute-forced by timing the response.
* **Randomness:** A `SecureRandom` CSPRNG seeds the permutation, so two encryptions of the same
  image under the same password produce different output.

This is what lets the project claim **tamper detection**: an altered, recompressed or cropped
image fails authentication instead of silently producing garbage pixels.

---

## 💻 Tech Stack
* **Backend:** Java 21, Spring Boot (Web, DevTools).
* **Frontend:** Thymeleaf, Vanilla JavaScript (FormData API), CSS (Dark Mode/Terminal UI).
* **Deployment:** Docker, RumptyCloud Platform.
* **Cryptography:** Custom **Visual AEAD** — PBKDF2-HMAC-SHA256 (100k rounds), HKDF subkey expansion, HMAC-SHA256 authentication tag with constant-time verification.

---

## 🚀 How to Run

### Option A: The Fast Way (Docker) 🐳
You don't need to install Java or Maven. Just pull the image from Docker Hub and run it.

```bash
# 1. Pull the image
docker pull moshpy/fyeo:v1.2

# 2. Run the container
docker run -p 8080:8080 moshpy/fyeo:v1.2
```

Then open [http://localhost:8080](http://localhost:8080).

> Pin an explicit tag. There is deliberately **no `latest`** tag, so `docker pull moshpy/fyeo`
> will fail — which is intentional, because an unpinned crypto image can silently change
> under you.

### Option B: Build the Image Yourself 🔨

```bash
# 1. Package the application (REQUIRED before building the image)
./mvnw clean package

# 2. Build the image
docker build -t fyeo:v1.2 .
```

⚠️ **The `Dockerfile` copies a pre-built jar** (`COPY target/*.jar app.jar`), so
`./mvnw package` **must** run first. On a clean checkout with no `target/` directory the
build fails with an unhelpful "no source files were specified" error. If you change the
source and rebuild without re-packaging, you will silently get the *previous* jar.

To pin a different tag, change it in both the `docker build` and any `docker run` command.

---

## 🖥️ Running Locally (No Docker)

Requires **JDK 21** (the build targets Java 21 and will **not** compile on 17 or earlier —
you will get `release version 21 not supported`).

```bash
# 1. Run the app (uses the bundled Maven wrapper)
./mvnw spring-boot:run

# 2. Override the port if 8080 is taken
./mvnw spring-boot:run -Dspring-boot.run.arguments=--server.port=8089
```

Then open [http://localhost:8080](http://localhost:8080) (or your chosen port).
The port can also be set via the `PORT` environment variable.

### Running the Tests

```bash
./mvnw test
```

18 tests covering the PNG metadata helper, the Visual AEAD engine, the application
context, and a full end-to-end pixel-parity integration round-trip.

---

## 🔐 Two Engines, One UI

The UI defaults to **Zero-Knowledge (`zk`)**: the image is encrypted entirely in the
browser via a Web Worker, and the password never leaves the device. Switch to
**`cloud`** in the engine bar to fall back to server-side processing — useful if your
browser lacks Web Worker support.

| Endpoint | Purpose |
|---|---|
| `GET /` | Web UI |
| `POST /encrypt` | Server-side encrypt (Cloud engine) |
| `POST /decrypt` | Server-side decrypt (Cloud engine) |
| `POST /api/v1/app/encrypt` | Mobile app API |
| `POST /api/v1/app/decrypt` | Mobile app API |
| `POST /api/v1/app/compress` | Mobile app API |

---

## 🔑 Handling of the Private Password

* The password is held in a `type="password"` field and is **cleared automatically after
  a successful encrypt or decrypt**, along with any in-memory copy and the key in the URL
  fragment (`#...&key=`). Nothing lingers in the DOM or the address bar once consumed.
* On a **failed** operation the password is intentionally **retained**, so a typo does not
  force a full retype.
* The 1-click WhatsApp share link embeds the password in the URL **fragment**. Fragments
  are not sent to the server by the browser, so it never reaches the server in a request —
  but it *is* part of the link. Anyone you send that link to has the password.
