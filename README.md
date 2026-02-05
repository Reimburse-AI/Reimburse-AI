# Reimburse.AI 🧾💰

> **AI-powered expense reimbursement with instant stablecoin payments — non-custodial**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Beta](https://img.shields.io/badge/Status-Public%20Beta-green.svg)]()

---

## 🎯 What is Reimburse AI?

Reimburse AI is a modern expense management platform that transforms how companies handle reimbursements:

- **AI-Powered Auditing** - GPT-4o Vision verifies receipts automatically in seconds
- **Instant Payments** - Approved expenses are paid in USDC immediately  
- **Non-Custodial** - Companies retain full control via Safe{Wallet} multisig
- **Multi-Chain** - Deploy on Base, Avalanche, Polygon + Tempo/Arc (beta)
- **Gasless Transactions** - Multiple gas strategies for seamless UX
- **On-chain Transparency** - Complete audit trail across all supported chains

**Result:** Submit receipt → AI verifies → Get paid instantly. Days become seconds.

---

## 🔐 Security Architecture

Reimburse.AI uses a **non-custodial architecture** powered by [Safe{Wallet}](https://safe.global):

```
┌─────────────────────────────────────────────────────────────┐
│                  Company's Safe{Wallet}                      │
│              (Multisig - Full Company Control)               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              AllowanceModule                         │    │
│  │   ┌──────────────────────────────────────────┐      │    │
│  │   │    ReimburseAI Delegate                  │      │    │
│  │   │    - Limited spending allowance          │      │    │
│  │   │    - Can only transfer to employees      │      │    │
│  │   │    - Subject to daily/monthly limits     │      │    │
│  │   └──────────────────────────────────────────┘      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**Key Security Features:**
| Feature | Description |
|---------|-------------|
| **Non-Custodial** | We never hold your funds — your Safe, your keys |
| **Spending Limits** | AllowanceModule caps what we can transfer |
| **Multisig Required** | Company owners approve limit changes |
| **Revocable Access** | Remove our delegate access anytime |
| **Gasless UX** | Gelato Relay pays gas, employees get full amount |

---

## 🚧 Beta Access

Reimburse.AI is now in **public beta**! 

[Get Started →](https://www.reimburse.ai)

---

## ✨ Key Features

### For Employees
- 📸 **Snap & Submit** - Take a photo, upload, done
- 🚗 **Mileage Claims** - IRS-compliant mileage reimbursement (2025: $0.70/mile)
- ⚡ **Instant Payments** - No more waiting weeks for reimbursement
- 💵 **Advance Requests** - Get funds early against approved expenses
- 🏢 **Multi-Company** - Work with multiple organizations seamlessly

### For Companies
- 🤖 **AI Auditing** - GPT-4o Vision with fraud detection and policy compliance
- 📊 **GL Code Integration** - Map expenses to your accounting chart of accounts
- 💱 **Multi-Currency** - Submit in any currency, pay in USDC
- 📑 **Complete Audit Trail** - Every transaction recorded on-chain
- 🔒 **Non-Custodial** - Full control via Safe{Wallet} multisig
- ⛽ **Gasless** - Employees receive full USDC amount, no gas needed

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | Next.js 15, React 18, Reown AppKit, Wagmi, Viem |
| **Backend** | Python 3.11+, FastAPI, Supabase, OpenAI |
| **Wallet** | Safe{Wallet} + AllowanceModule |
| **Relay** | Gelato Relay, Native Sponsor, USDC Gas |
| **Chains** | Base, Avalanche, Polygon + Tempo/Arc (beta) |
| **Token** | Native Circle USDC |

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Frontend                          │
│          Next.js 15 + Reown AppKit + Wagmi          │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                   Backend API                        │
│              Python / FastAPI / Supabase             │
└─────────────────────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌──────────┐   ┌──────────┐   ┌──────────┐
    │   AI     │   │  Safe    │   │  Gelato  │
    │ Auditor  │   │ Protocol │   │  Relay   │
    │ (GPT-4o) │   │   Kit    │   │          │
    └──────────┘   └──────────┘   └──────────┘
```

---

## 📋 Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design & data flow
- [SECURITY.md](./SECURITY.md) - Security policies
- [backend/README.md](./backend/README.md) - Backend setup guide
- [frontend/README.md](./frontend/README.md) - Frontend setup guide
- [CONTRIBUTING.md](./CONTRIBUTING.md) - How to contribute

---

## 🚀 For Developers

### Prerequisites

- Node.js 20+
- Python 3.11+
- Docker (optional)
- Reown Project ID (get from https://cloud.reown.com/)
- Gelato API Key (get from https://app.gelato.network/)

### Quick Start

```bash
# Clone repository
git clone https://github.com/your-org/reimburse-ai.git
cd reimburse-ai

# Backend setup
cd backend
pip install uv && uv venv && uv pip install -e .
cp .env.example .env
# Edit .env with your keys
uv run python run.py

# Frontend setup (new terminal)
cd frontend/apps/web
npm install
cp .env.example .env.local
# Edit .env.local with your Reown Project ID
npm run dev
```

### Environment Variables

See `.env.example` files in each folder:
- `backend/.env.example` - Backend API configuration
- `frontend/apps/web/.env.example` - Frontend configuration
- `Web3/.env.example` - Smart contract configuration

---

## 🔑 Key Integrations

| Service | Purpose | Docs |
|---------|---------|------|
| **Safe{Wallet}** | Non-custodial multisig treasury | [safe.global/docs](https://docs.safe.global/) |
| **Reown AppKit** | Wallet connection (WalletConnect v2) | [docs.reown.com](https://docs.reown.com/) |
| **Gelato Relay** | Gasless transaction sponsorship | [docs.gelato.network](https://docs.gelato.network/) |
| **OpenAI** | GPT-4o Vision for receipt analysis | [platform.openai.com](https://platform.openai.com/) |
| **Supabase** | Database, auth, storage | [supabase.com/docs](https://supabase.com/docs) |

---

## 📄 License

MIT License - see [LICENSE](./LICENSE) for details.

---

**Built for the future of expense management**

🌐 [reimburse.ai](https://www.reimburse.ai)
