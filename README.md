# ForYourEyesOnly
# F.Y.E.O (For Your Eyes Only) 👁️🔒

> **Status:** Live & Deployed  
> **Demo:** [https://foryoureyesonly-m4th.onrender.com/](https://foryoureyesonly-m4th.onrender.com/)

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
* **Strict MVC Pattern:** Separation of `ChaosService` (Logic), `ChaosController` (Routing), and Thymeleaf Templates (View).
* **DTO Pattern:** Usage of `CryptoDto` to strictly bind multipart files and hashing keys, preventing parameter clutter in the controller.
* **Java 17 & Spring Boot:** Leveraging modern memory management and strict typing.

---

## 💻 Tech Stack
* **Backend:** Java 17, Spring Boot (Web, DevTools).
* **Frontend:** Thymeleaf, Vanilla JavaScript (FormData API), CSS (Dark Mode/Terminal UI).
* **Deployment:** Docker, Render Cloud Platform.
* **Cryptography:** Custom Seed-Based Pixel Permutation Logic.

---

## 🚀 How to Run

### Option A: The Fast Way (Docker) 🐳
You don't need to install Java or Maven. Just pull the image from Docker Hub and run it.

```bash
# 1. Pull the image
docker pull moshpy/fyeo:v1.0.0

# 2. Run the container
docker run -p 8080:8080 moshPy/fyeo:v1.0.0
