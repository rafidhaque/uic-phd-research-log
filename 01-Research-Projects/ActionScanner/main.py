import os
import subprocess
import shutil

TEMP_DIR = "temp_repos"

def run_command(command, cwd=None):

    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout, result.stderr
    except Exception as e:
        return None, str(e)
    
def scan_action(repo_url):
    print(f"\n Started for {repo_url}!")

    repo_name = repo_url.split("/")[-1]

    repo_path = os.path.join(TEMP_DIR, repo_name)

    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

    print("...cloning...")

    run_command("git clone " + repo_url + " " + repo_path)

    package_json_path = os.path.join(repo_path, "package.json")

    if not os.path.exists(package_json_path):
        print("No JSON package here!")
        return
    else:
        print("Found it!")

    stdout, stderr = run_command("npm install --package-lock-only --ignore-scripts", cwd=repo_name)