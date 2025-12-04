# Reset git history - Start fresh with current code (no secrets in history)
# WARNING: This will completely remove all git history and start fresh

Write-Host "=== Reset Git History ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "This will:" -ForegroundColor Yellow
Write-Host "1. Remove the .git directory (all history)"
Write-Host "2. Initialize a new git repository"
Write-Host "3. Create a fresh initial commit with current code"
Write-Host ""
Write-Host "WARNING: All git history will be lost!" -ForegroundColor Red
Write-Host ""
$confirm = Read-Host "Continue? (yes/no)"

if ($confirm -ne "yes") {
    Write-Host "Aborted." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Backing up current remote URL..." -ForegroundColor Green
$remoteUrl = git remote get-url origin 2>$null
if ($remoteUrl) {
    Write-Host "Remote URL: $remoteUrl"
    $remoteUrl | Out-File -FilePath ".git-remote-backup.txt" -Encoding utf8
}

Write-Host ""
Write-Host "Removing .git directory..." -ForegroundColor Green
Remove-Item -Path ".git" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Initializing new git repository..." -ForegroundColor Green
git init

Write-Host "Adding all files..." -ForegroundColor Green
git add .

Write-Host "Creating initial commit..." -ForegroundColor Green
git commit -m "Initial commit - Clean history (secrets removed)"

if ($remoteUrl) {
    Write-Host ""
    Write-Host "Restoring remote URL..." -ForegroundColor Green
    git remote add origin $remoteUrl
    
    Write-Host ""
    Write-Host "To push to remote (this will overwrite remote history):" -ForegroundColor Yellow
    Write-Host "  git push origin --force --all" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "WARNING: This will overwrite the remote repository history!" -ForegroundColor Red
    Write-Host "Make sure all collaborators know to re-clone the repository." -ForegroundColor Red
} else {
    Write-Host ""
    Write-Host "No remote URL found. To add one:" -ForegroundColor Yellow
    Write-Host "  git remote add origin <your-repo-url>" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Done! Your repository now has a clean history." -ForegroundColor Green
Write-Host "The backup remote URL is saved in .git-remote-backup.txt" -ForegroundColor Green
