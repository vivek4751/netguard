# NetGuard GitHub Workflow

The NetGuard demo is connected to the private repository at `https://github.com/vivek4751/netguard-demo-dashboard`.

## Clone and run locally

```bash
git clone https://github.com/vivek4751/netguard-demo-dashboard.git
cd netguard-demo-dashboard
pnpm install
pnpm dev
```

Open the local address shown in the terminal, usually `http://localhost:3000`.

## Validate before committing

```bash
pnpm test
pnpm check
pnpm build
```

## Save and push a change

```bash
git status
git add <changed-files>
git commit -m "Describe the change"
git push origin main
```

## Pull the latest changes

```bash
git pull origin main
```

The GitHub repository is configured with the live NetGuard demo as its homepage. Keep secrets out of commits; local environment files and credentials should never be pushed to GitHub.
