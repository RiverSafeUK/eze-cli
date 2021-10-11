from eze.utils.cli import run_cmd
import re
import shlex


def convertToKB(size):
    match = re.search("([0-9.]*)(B|kB|MB|GB)", size)
    number = float(match.group(1))
    suffix = match.group(2)
    if suffix == "B":
        number = number / 1024
    elif suffix == "kB":
        number = number
    elif suffix == "MB":
        number = number * 1024
    elif suffix == "GB":
        number = number * 1024 * 1024
    return number


input_cmd = shlex.split('docker history --no-trunc --format "{{.Size}}_:_{{.CreatedBy}}" eze-cli')
subprocess = run_cmd(input_cmd)


summary = {"Base": {"Base Linux Image": 0}}
for line in subprocess.stdout.split("\n"):
    if line.strip() == "" or line[0:2] == "0B":
        continue

    old_line = list(filter(bool, line.split("_:_")))
    result = re.search("SIZETAG:[a-zA-Z]*:[a-zA-Z0-9 +/\-@]*", old_line[1])
    if not result:
        summary["Base"]["Base Linux Image"] += convertToKB(old_line[0])
        continue
    new_line = []
    _, category, name = result.group().split(":")

    if category not in summary:
        summary[category] = {}
    if name not in summary[category]:
        summary[category][name] = 0

    summary[category][name] += convertToKB(old_line[0])

tot_size = 0
for category in ["Base", "Language", "Tool"]:
    print(f"\n{category} Sizes")
    print("====================================")
    for name in dict(sorted(summary[category].items(), key=lambda item: -item[1])):
        size = round(summary[category][name] / 1024, 1)
        print(f"{name.ljust(25)} {str(size).rjust(6)} MB")
        tot_size += size


print("\n====================================")
print(f"{'Total Image Size '.ljust(25)} {str(round(tot_size,1)).rjust(6)} MB\n")
