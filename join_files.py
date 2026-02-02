import sys
target = sys.argv[1]
sources = sys.argv[2:]
print(f"Joining {len(sources)} files into {target}")
try:
    with open(target, 'wb') as outfile:
        for src in sources:
            with open(src, 'rb') as infile:
                outfile.write(infile.read())
    print("Done.")
except Exception as e:
    print(f"Error: {e}")
