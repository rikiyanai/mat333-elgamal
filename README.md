# ElGamal Encryption: Interactive 3D Demo

Python companion to my MAT331 number theory project on ElGamal public key encryption.

The Maple implementation and full writeup are in the main project directory. This repo provides an interactive demo with 3D visualizations demonstrating ElGamal encryption and the computational hardness of the Discrete Logarithm Problem.

## Files

`elgamal.py` contains the core library (keygen, encrypt, decrypt, text message handling, baby step giant step DLP solver). `elgamal_demo.py` is the interactive demo with 5 modes including 3 interactive 3D visualizations.

## Requirements

```
pip3 install matplotlib numpy colorama
```

## Usage

```
python3 elgamal_demo.py
```

The interactive menu offers five modes:

1. **Encrypt / Decrypt** generates keys, encrypts a message, decrypts it, and shows the probabilistic property.
2. **Crack a key (BSGS)** generates a key and breaks it with baby step giant step.
3. **3D: DLP One-Way Landscape** renders g^x mod p as a 3D surface across multiple primes, with a 2D slice showing the inverse problem.
4. **3D: Ciphertext Cloud** plots (c1, c2, plaintext) in 3D, showing same-message encryptions form distinct z-layers that overlap in projection.
5. **3D: BSGS Collision Grid** visualizes the sqrt(p) x sqrt(p) search structure as a 3D surface, with the collision valley where baby and giant steps match.

All 3D plots feature interactive rotation, hover annotations, and toggle buttons.

## Sample Visualizations

![DLP One-Way Landscape](dlp_landscape_3d.png)

![Ciphertext Cloud](ciphertext_cloud_3d.png)

![BSGS Collision Grid](bsgs_collision_3d.png)
