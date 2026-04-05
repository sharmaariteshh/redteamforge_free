import os
import subprocess
from dotenv import load_dotenv

load_dotenv()
token = os.environ.get('GITHUB_TOKEN')
if not token:
    print("NO TOKEN")
    exit(1)

cmds = [
    "git init",
    "git config user.email \"bot@example.com\"",
    "git config user.name \"RedTeamForge Bot\"",
    "git branch -M main",
    "git add .",
    "git commit -m \"Initial commit\"",
    f"git remote add origin https://oauth2:{token}@github.com/sharmaariteshh/redteamforge_free.git",
    "git push -u origin main"
]
for cmd in cmds:
    print("Running:", cmd.replace(token, "XXX"))
    subprocess.run(cmd, shell=True)
