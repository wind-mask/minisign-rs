# Changelog

All notable changes to this project will be documented in this file.

## [0.1.5] - 2026-04-24

### 🐛 Bug Fixes

- Address security audit findings

## [0.1.4] - 2026-04-23

### 🐛 Bug Fixes

- Harden minisign parsing and key compatibility

### 🧪 Testing

- Add official minisign compatibility coverage
## [0.1.3] - 2026-02-21

### 💼 Other

- Potential fix for code scanning alert no. 1: Workflow does not contain permissions

Co-authored-by: Copilot Autofix powered by AI <62310815+github-advanced-security[bot]@users.noreply.github.com>
- 🔒️ security(zeroize-buf): zeroize some sec buf

### 📚 Documentation

- 📝 docs(README): fix doc test

### ⚙️ Miscellaneous Tasks

- Release v0.1.3
## [0.1.2] - 2026-02-20

### 🚀 Features

- ✨ feat(mini_sign::PublicKeyBox-mini_sign::SecretKeyBox): Added items to the public API
=============================
+pub fn mini_sign::PublicKeyBox<'s>::key_id(&self) -> &[u8; 8]
+pub fn mini_sign::PublicKeyBox<'s>::sig_alg(&self) -> &[u8; 2]
+pub fn mini_sign::PublicKeyBox<'s>::verify<R>(&self, signature_box: &mini_sign::SignatureBox<'_>, data_reader: R) -> mini_sign::Result<bool> where R: std::io::Read
+pub fn mini_sign::SecretKeyBox<'s>::public_key(&self, password: core::option::Option<&[u8]>) -> mini_sign::Result<mini_sign::PublicKeyBox<'s>>

### 💼 Other

- 💚 ci: add cz and pre-commit
- 💚 ci: Check semver and pre-commit
- 🔖 bump(v0.1.2): tag 0.1.2

### 🎨 Styling

- 🎨 style(fmt): fmt clippy

### ⚙️ Miscellaneous Tasks

- 🎡 add release-plz and git-cliff
- 🎡 add CHANGELOG.md
## [0.1.1] - 2025-01-17

### 🚀 Features

- 🎸 add api:form one line key raw str

### 💼 Other

- Update README.md
## [0.1.0] - 2024-11-27

### 🚀 Features

- 🎸 init 0.1.0

### 💼 Other

- Create rust.yml

ci in github
- Create dependabot.yml
- Update dependabot.yml

### 📚 Documentation

- ✏️ improve docs
- ✏️ Cargo.toml
- ✏️ README

### 🎨 Styling

- 💄 remove some ref

### 🧪 Testing

- 💍 remove filesystem in test
